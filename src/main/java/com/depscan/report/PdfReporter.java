package com.depscan.report;

import com.depscan.reach.Finding;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDFont;
import org.apache.pdfbox.pdmodel.font.PDType0Font;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationLink;
import org.apache.pdfbox.pdmodel.interactive.action.PDActionURI;

/**
 * PDF export (Stage 5) with PDFBox.
 *
 * <p>Embeds Inter (body/headings) and JetBrains Mono (code/paths) from
 * {@code /fonts/*.ttf} when present in the jar, falling back to Helvetica /
 * Courier when the fonts are missing (e.g. a hand-built classpath). A4,
 * header + footer with page numbers on every page, selectable text
 * (real text operators, not images), clickable advisory links, and
 * severity badges that stay readable in greyscale: badges are labelled
 * text on a grey fill (dark grey = CRITICAL, light grey = LOW), never
 * colour alone.
 *
 * <p>Contents: cover page, executive summary (counts + risk score / 10),
 * severity chart, detailed findings table, recommendations, methodology
 * and limitations, glossary.
 */
public final class PdfReporter {

    private PdfReporter() {}

    public static byte[] render(ScanReport report, String theme, boolean excludeUnreachable) throws IOException {
        return render(report, theme, excludeUnreachable, LocalDate.now().toString());
    }

    static byte[] render(ScanReport report, String theme, boolean excludeUnreachable, String date) throws IOException {
        boolean dark = "dark".equalsIgnoreCase(theme);
        var findings = excludeUnreachable
                ? report.findings().stream().filter(Finding::reachable).toList()
                : report.findings();
        double score = RiskScore.score(report);
        try (PDDocument doc = new PDDocument();
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            Fonts fonts = Fonts.load(doc);
            Writer w = new Writer(doc, fonts, dark, report.projectPath());
            // Cover page
            w.newPage();
            w.y -= 120;
            w.heading("DepScan", 36);
            w.heading("Vulnerability Report", 20);
            w.text("Project: " + report.projectPath(), 12);
            w.text("Date: " + date, 12);
            w.text("Tool: DepScan " + com.depscan.cli.Main.VERSION + " (OSV.dev + JavaParser + JGraphT)", 12);
            w.text("", 12);
            w.text(report.dependenciesScanned() + " dependencies scanned.", 12);
            w.text(report.criticalCount() + " CRITICAL (reachable)  |  " + report.lowCount() + " LOW (unreachable)  |  "
                    + report.ignoredCount() + " ignored", 12);
            w.text("Risk score: " + score + " / 10 (" + RiskScore.label(score) + ")", 14);
            w.text("", 12);
            w.text("This report lists known vulnerabilities in the project's direct Maven dependencies, "
                    + "with a reachability verdict for each one: reachable findings are CRITICAL, "
                    + "unreachable findings are LOW and still shown, never hidden.", 11);
            // Executive summary
            w.newPage();
            w.heading("Executive summary", 18);
            w.text("Total findings: " + report.findings().size() + ". Reachable (CRITICAL): "
                    + report.criticalCount() + ". Unreachable (LOW): " + report.lowCount()
                    + ". Ignored (depscan.yml): " + report.ignoredCount() + ".", 11);
            w.text("Risk score: " + score + " / 10 (" + RiskScore.label(score) + "). The score is a triage aid: "
                    + "each reachable finding adds 2.5, each unreachable finding adds 0.5, capped at 10. "
                    + "It measures how much shipped code is exposed, not a CVSS score.", 11);
            w.text("", 11);
            w.heading("Severity chart", 14);
            w.bar("CRITICAL (reachable)", (int) report.criticalCount(), Math.max(1, (int) report.findings().size()));
            w.bar("LOW (unreachable)", (int) report.lowCount(), Math.max(1, (int) report.findings().size()));
            w.bar("Ignored", (int) report.ignoredCount(), Math.max(1, (int) report.findings().size()));
            // Findings table
            w.newPage();
            w.heading("Detailed findings", 18);
            if (findings.isEmpty()) {
                w.text("No known vulnerabilities found.", 11);
            }
            for (Finding f : findings) {
                w.findingBlock(f);
            }
            // Recommendations
            w.newPage();
            w.heading("Recommendations", 18);
            w.text("Fix reachable (CRITICAL) findings first — they are the ones your code can actually reach. "
                    + "Upgrade to the fixed version shown for each finding; major-version upgrades are flagged "
                    + "as likely breaking, so read the changelog and run the test suite before shipping.", 11);
            for (Finding f : findings) {
                if (f.reachable()) {
                    w.text("- " + f.dependency().coordinates() + ": " + f.upgradeSuggestion(), 11);
                }
            }
            w.text("Then review LOW findings: the dependency is shipped, so a future caller, reflection, or "
                    + "another code path could make it reachable. Upgrade where the fix is a patch or minor bump.", 11);
            // Methodology + glossary
            w.newPage();
            w.heading("Methodology and limitations", 18);
            w.text("DepScan parses pom.xml, queries OSV.dev per direct dependency, builds a call graph of the "
                    + "project's own source with JavaParser, and checks reachability from entry points "
                    + "(main methods and public methods) with JGraphT. When an advisory carries no "
                    + "function-level data — which is the case for Maven GHSA advisories in OSV — any call "
                    + "into the dependency's Java package counts as reachable.", 11);
            w.text("Static analysis misses reflection and dynamic dispatch: code reached only via reflection, "
                    + "dynamic proxies, lambdas passed as callbacks, or classes loaded at runtime is not "
                    + "followed, so a LOW verdict is evidence, not proof, that a vulnerability cannot be "
                    + "triggered. Only direct dependencies are scanned; transitive dependencies are not "
                    + "resolved in this version.", 11);
            w.heading("Glossary", 14);
            w.text("CRITICAL: a vulnerable function is reachable from an entry point. "
                    + "LOW: the vulnerable dependency is present but no reachable call into it was found. "
                    + "OSV.dev: the free vulnerability database queried per dependency. "
                    + "SBOM: software bill of materials — a list of every component in the project. "
                    + "SARIF: Static Analysis Results Interchange Format, consumed by GitHub code scanning. "
                    + "Call graph: a directed graph of which methods call which other methods.", 11);
            w.finish();
            doc.save(out);
            return out.toByteArray();
        }
    }

    // ---- fonts ----

    record Fonts(PDFont regular, PDFont bold, PDFont mono, PDFont monoBold) {
        static Fonts load(PDDocument doc) throws IOException {
            PDFont regular = loadTtf(doc, "/fonts/Inter-Regular.ttf");
            PDFont bold = loadTtf(doc, "/fonts/Inter-Bold.ttf");
            PDFont mono = loadTtf(doc, "/fonts/JetBrainsMono-Regular.ttf");
            PDFont monoBold = loadTtf(doc, "/fonts/JetBrainsMono-Bold.ttf");
            if (regular == null) regular = new PDType1Font(Standard14Fonts.FontName.HELVETICA);
            if (bold == null) bold = new PDType1Font(Standard14Fonts.FontName.HELVETICA_BOLD);
            if (mono == null) mono = new PDType1Font(Standard14Fonts.FontName.COURIER);
            if (monoBold == null) monoBold = new PDType1Font(Standard14Fonts.FontName.COURIER_BOLD);
            return new Fonts(regular, bold, mono, monoBold);
        }

        private static PDFont loadTtf(PDDocument doc, String path) {
            try (InputStream in = PdfReporter.class.getResourceAsStream(path)) {
                if (in == null) return null;
                return PDType0Font.load(doc, in);
            } catch (Exception e) {
                return null;
            }
        }
    }

    // ---- layout writer ----

    static final class Writer {
        private final PDDocument doc;
        private final Fonts fonts;
        private final boolean dark;
        private final String project;
        private PDPage page;
        private PDPageContentStream cs;
        private float y;
        private int pageNo = 0;
        private static final float MARGIN = 56;
        private static final float WIDTH = PDRectangle.A4.getWidth() - 2 * MARGIN;

        Writer(PDDocument doc, Fonts fonts, boolean dark, String project) throws IOException {
            this.doc = doc; this.fonts = fonts; this.dark = dark; this.project = project;
        }

        void newPage() throws IOException {
            finishPage();
            page = new PDPage(PDRectangle.A4);
            doc.addPage(page);
            pageNo++;
            cs = new PDPageContentStream(doc, page);
            y = PDRectangle.A4.getHeight() - MARGIN - 20;
            // Header
            cs.beginText();
            cs.setFont(fonts.mono(), 8);
            cs.newLineAtOffset(MARGIN, PDRectangle.A4.getHeight() - 36);
            cs.showText("DepScan " + com.depscan.cli.Main.VERSION + "  |  " + project);
            cs.endText();
            cs.setLineWidth(0.5f);
            cs.moveTo(MARGIN, PDRectangle.A4.getHeight() - 44);
            cs.lineTo(PDRectangle.A4.getWidth() - MARGIN, PDRectangle.A4.getHeight() - 44);
            cs.stroke();
        }

        void finishPage() throws IOException {
            if (cs == null) return;
            // Footer with page number
            cs.beginText();
            cs.setFont(fonts.mono(), 8);
            cs.newLineAtOffset(MARGIN, 36);
            cs.showText("DepScan vulnerability report  -  Page " + pageNo);
            cs.endText();
            cs.close();
            cs = null;
        }

        void finish() throws IOException { finishPage(); }

        void ensure(float needed) throws IOException {
            if (y - needed < MARGIN + 20) newPage();
        }

        void heading(String text, float size) throws IOException {
            ensure(size + 24);
            y -= 8;
            writeLine(text, fonts.bold(), size, true);
            y -= size + 6;
        }

        void text(String text, float size) throws IOException {
            for (String line : wrap(text, fonts.regular(), size, WIDTH)) {
                ensure(size + 4);
                writeLine(line, fonts.regular(), size, false);
                y -= size + 4;
            }
            y -= 4;
        }

        void bar(String label, int value, int max) throws IOException {
            ensure(36);
            writeLine(label + ": " + value, fonts.regular(), 10, false);
            y -= 14;
            float barWidth = max <= 0 ? 0 : WIDTH * Math.min(1f, (float) value / max);
            cs.setNonStrokingColor(0.35f, 0.35f, 0.35f);
            cs.addRect(MARGIN, y - 8, Math.max(2, barWidth), 10);
            cs.fill();
            cs.setNonStrokingColor(0, 0, 0);
            y -= 22;
        }

        void findingBlock(Finding f) throws IOException {
            ensure(110);
            // Badge: grey fill + black text (readable in greyscale, not colour alone)
            String badge = f.reachable() ? "CRITICAL" : "LOW";
            float badgeW = 62;
            cs.setNonStrokingColor(f.reachable() ? 0.25f : 0.85f, f.reachable() ? 0.25f : 0.85f, f.reachable() ? 0.25f : 0.85f);
            cs.addRect(MARGIN, y - 12, badgeW, 14);
            cs.fill();
            cs.setNonStrokingColor(0, 0, 0);
            cs.beginText();
            cs.setFont(fonts.bold(), 9);
            if (f.reachable()) cs.setNonStrokingColor(1, 1, 1);
            cs.newLineAtOffset(MARGIN + 6, y - 9);
            cs.showText(badge);
            cs.endText();
            cs.setNonStrokingColor(0, 0, 0);
            // Advisory id as a clickable link, mono font
            String id = f.vulnerability().id();
            float idX = MARGIN + badgeW + 10;
            cs.beginText();
            cs.setFont(fonts.monoBold(), 10);
            cs.newLineAtOffset(idX, y - 9);
            cs.showText(id);
            cs.endText();
            float idW = fonts.monoBold().getStringWidth(id) / 1000f * 10;
            PDAnnotationLink link = new PDAnnotationLink();
            link.setRectangle(new PDRectangle(idX, y - 12, idW, 14));
            PDActionURI action = new PDActionURI();
            action.setURI("https://osv.dev/vulnerability/" + id);
            link.setAction(action);
            page.getAnnotations().add(link);
            y -= 22;
            writeLine(f.dependency().coordinates(), fonts.mono(), 10, false);
            y -= 14;
            writeLine("Location: " + (f.location().isBlank() ? "pom.xml" : f.location()), fonts.mono(), 9, false);
            y -= 13;
            for (String line : wrap("Summary: " + f.vulnerability().summary(), fonts.regular(), 10, WIDTH)) {
                writeLine(line, fonts.regular(), 10, false);
                y -= 13;
            }
            for (String line : wrap("Upgrade: " + f.upgradeSuggestion(), fonts.regular(), 10, WIDTH)) {
                writeLine(line, fonts.regular(), 10, false);
                y -= 13;
            }
            for (String line : wrap("Evidence: " + f.evidence(), fonts.regular(), 9, WIDTH)) {
                writeLine(line, fonts.regular(), 9, false);
                y -= 12;
            }
            y -= 8;
            cs.setLineWidth(0.4f);
            cs.moveTo(MARGIN, y);
            cs.lineTo(PDRectangle.A4.getWidth() - MARGIN, y);
            cs.stroke();
            y -= 10;
        }

        private void writeLine(String text, PDFont font, float size, boolean bold) throws IOException {
            cs.beginText();
            cs.setFont(font, size);
            cs.newLineAtOffset(MARGIN, y);
            cs.showText(safe(text, font));
            cs.endText();
        }

        private String safe(String text, PDFont font) {
            // Replace characters the embedded font cannot encode with '?'.
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < text.length(); i++) {
                char c = text.charAt(i);
                try {
                    font.encode(Character.toString(c));
                    sb.append(c);
                } catch (Exception e) {
                    sb.append(c < 128 ? c : '?');
                }
            }
            return sb.toString();
        }

        private List<String> wrap(String text, PDFont font, float size, float maxWidth) throws IOException {
            List<String> out = new ArrayList<>();
            if (text == null || text.isBlank()) { out.add(""); return out; }
            String[] words = text.split("\\s+");
            StringBuilder cur = new StringBuilder();
            for (String w : words) {
                String trial = cur.length() == 0 ? w : cur + " " + w;
                float wdt = font.getStringWidth(safe(trial, font)) / 1000f * size;
                if (wdt > maxWidth && cur.length() > 0) {
                    out.add(cur.toString());
                    cur = new StringBuilder(w);
                } else {
                    cur = new StringBuilder(trial);
                }
            }
            out.add(cur.toString());
            return out;
        }
    }
}
