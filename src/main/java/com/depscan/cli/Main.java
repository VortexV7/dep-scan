package com.depscan.cli;

import com.depscan.ci.CiDetector;
import com.depscan.ci.GitHubActions;
import com.depscan.config.ConfigException;
import com.depscan.config.ConfigLoader;
import com.depscan.config.DepScanConfig;
import com.depscan.osv.HttpOsvClient;
import com.depscan.osv.NetworkException;
import com.depscan.osv.OsvCache;
import com.depscan.report.BoxedReporter;
import com.depscan.report.JsonReporter;
import com.depscan.report.SarifReporter;
import com.depscan.report.ScanReport;
import com.depscan.report.TextReporter;
import com.depscan.tui.HackerTui;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicBoolean;
import org.fusesource.jansi.AnsiConsole;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

/**
 * DepScan CLI (Picocli) — v0.5.0 (Stages 2–7: + npm and Python support).
 *
 * <pre>
 *   depscan scan &lt;project-dir&gt; [--simple | --json | --format text|json|sarif]
 *          [--fail-on critical|reachable|high|none] [--offline] [--no-color]
 *          [--no-animation] [--config depscan.yml] [--tui] [--out file]
 *   depscan report &lt;project-dir&gt; --format pdf|html|json|sarif|csv|sbom --out file
 *          [--exclude-unreachable] [--theme light|dark] [--simple]
 *   depscan --help
 * </pre>
 * Default output is the boxed, colour-coded report. On a real terminal
 * (TTY, not CI) the hacker boot sequence runs first; in CI
 * (CI / GITHUB_ACTIONS / GITLAB_CI / JENKINS_URL / non-TTY) output is
 * plain, colour-free and animation-free, with GitHub annotations and a
 * step summary when running in GitHub Actions.
 *
 * <p>Exit codes: 0 clean or only unreachable findings, 1 --fail-on threshold
 * breached, 2 usage or tool error (bad flags, bad config, missing manifest),
 * 3 network error with no cached OSV response.
 */
@Command(name = "depscan", version = "0.5.0",
        description = "Reachability-aware vulnerability scanner for Maven, npm and Python projects (OSV.dev).",
        mixinStandardHelpOptions = true,
        subcommands = {Main.ScanCommand.class, Main.ReportCommand.class})
public class Main implements Callable<Integer> {

    public static final String VERSION = "0.5.0";

    @Override
    public Integer call() {
        CommandLine.usage(this, System.out);
        return 0;
    }

    public static void main(String[] args) {
        AnsiConsole.systemInstall();
        try {
            int code = new CommandLine(new Main()).execute(args);
            System.exit(code);
        } finally {
            AnsiConsole.systemUninstall();
        }
    }

    /** Shared scan setup for scan + report: config, threshold, OSV client. */
    static final class ScanSetup {
        final DepScanConfig config;
        final FailThreshold threshold;
        final OsvCache cache;
        final boolean offline;

        ScanSetup(DepScanConfig config, FailThreshold threshold, OsvCache cache, boolean offline) {
            this.config = config; this.threshold = threshold; this.cache = cache; this.offline = offline;
        }
    }

    static ScanSetup setup(Path projectDir, Path configPath, String failOn, boolean failOnCritical,
                           Path cacheDir, boolean offline) throws ConfigException {
        DepScanConfig config;
        Path dir = projectDir.toAbsolutePath().normalize();
        config = configPath != null ? ConfigLoader.load(configPath) : ConfigLoader.discover(dir);
        FailThreshold threshold;
        if (failOn != null) threshold = FailThreshold.parse(failOn);
        else if (failOnCritical) threshold = FailThreshold.CRITICAL;
        else if (config.failOn() != null) threshold = FailThreshold.parse(config.failOn());
        else threshold = FailThreshold.CRITICAL;
        OsvCache cache = new OsvCache(cacheDir != null ? cacheDir : OsvCache.defaultDir());
        return new ScanSetup(config, threshold, cache, offline);
    }

    static ScanReport runScan(ScanSetup setup, Path projectDir, ScanProgress progress) throws IOException {
        var osv = new HttpOsvClient(setup.cache, setup.offline);
        return new ScanService(osv, setup.config).scan(projectDir.toAbsolutePath().normalize(), progress);
    }

    @Command(name = "scan", description = "Scan a Maven, npm or Python project directory (pom.xml, package.json, requirements.txt and/or pyproject.toml; any combination scans all of them).",
            mixinStandardHelpOptions = true)
    static class ScanCommand implements Callable<Integer> {

        @Parameters(index = "0", description = "Project directory containing pom.xml, package.json, requirements.txt and/or pyproject.toml", defaultValue = ".")
        private Path projectDir;

        @Option(names = "--simple", description = "Plain unboxed text report (no boxes).")
        private boolean simple;

        @Option(names = "--json", description = "Machine-readable JSON report.")
        private boolean json;

        @Option(names = "--format", paramLabel = "<text|json|sarif>",
                description = "Report format: text, json or sarif (SARIF 2.1.0).")
        private String format;

        @Option(names = "--tui", description = "Full-screen hacker dashboard after the scan (TTY only; ignored in CI).")
        private boolean tui;

        @Option(names = "--out", paramLabel = "<file>", description = "Write the report to a file instead of stdout.")
        private Path out;

        @Option(names = "--fail-on", paramLabel = "<critical|reachable|high|none>",
                description = "Fail (exit 1) when this threshold is breached. Default: critical. "
                        + "critical/reachable = any reachable finding; high = any HIGH severity finding; none = never fail.")
        private String failOn;

        @Option(names = "--fail-on-critical", description = "Deprecated alias for --fail-on critical.")
        private boolean failOnCritical;

        @Option(names = "--offline", description = "Never touch the network; use the disk cache only.")
        private boolean offline;

        @Option(names = "--no-color", description = "Disable coloured output.")
        private boolean noColor;

        @Option(names = "--no-animation", description = "Disable the scanning spinner / TUI boot sequence.")
        private boolean noAnimation;

        @Option(names = "--config", paramLabel = "depscan.yml",
                description = "Config file with an ignore list (default: depscan.yml in the project dir, if present).")
        private Path configPath;

        @Option(names = "--cache-dir", description = "OSV cache directory (default ~/.cache/depscan/osv).")
        private Path cacheDir;

        @Override
        public Integer call() {
            boolean ci = CiDetector.isCi();
            if (simple && json) {
                System.err.println("depscan: --simple and --json cannot be used together");
                return ExitCodes.USAGE_OR_TOOL_ERROR;
            }
            if (format != null && !"text".equalsIgnoreCase(format) && !"json".equalsIgnoreCase(format)
                    && !"sarif".equalsIgnoreCase(format)) {
                System.err.println("depscan: unknown --format '" + format + "' (use text, json or sarif)");
                return ExitCodes.USAGE_OR_TOOL_ERROR;
            }
            if (!Files.isDirectory(projectDir)) {
                System.err.println("depscan: not a directory: " + projectDir);
                return ExitCodes.USAGE_OR_TOOL_ERROR;
            }
            ScanSetup setup;
            try {
                setup = Main.setup(projectDir, configPath, failOn, failOnCritical, cacheDir, offline);
            } catch (ConfigException e) {
                System.err.println("depscan: " + e.getMessage());
                return ExitCodes.USAGE_OR_TOOL_ERROR;
            } catch (IllegalArgumentException e) {
                System.err.println("depscan: " + e.getMessage());
                return ExitCodes.USAGE_OR_TOOL_ERROR;
            }

            boolean colour = CiDetector.shouldUseColor(noColor);
            boolean useJson = json || "json".equalsIgnoreCase(format);
            boolean useSarif = "sarif".equalsIgnoreCase(format);
            boolean machineOutput = useJson || useSarif;
            boolean useSimple = simple || "text".equalsIgnoreCase(format) || ci;
            boolean hacker = !machineOutput && HackerTui.shouldUseHackerUi(noAnimation, noColor);
            boolean animate = !machineOutput && CiDetector.shouldAnimate(noAnimation);

            if (hacker) HackerTui.boot(System.out, true, colour);
            ScanProgress progress = hacker
                    ? HackerTui.progressListener(System.err, colour)
                    : ScanProgress.NONE;
            AtomicBoolean stopSpinner = new AtomicBoolean(false);
            Thread spinner = null;
            if (animate && !hacker) spinner = startSpinner(stopSpinner);

            ScanReport report;
            try {
                report = Main.runScan(setup, projectDir, progress);
            } catch (NetworkException e) {
                stopSpinner(stopSpinner, spinner);
                System.err.println("depscan: " + e.getMessage());
                return ExitCodes.NETWORK_NO_CACHE;
            } catch (IOException e) {
                stopSpinner(stopSpinner, spinner);
                System.err.println("depscan: " + e.getMessage());
                return ExitCodes.USAGE_OR_TOOL_ERROR;
            } catch (Exception e) {
                stopSpinner(stopSpinner, spinner);
                System.err.println("depscan: scan failed: " + e.getMessage());
                return ExitCodes.USAGE_OR_TOOL_ERROR;
            } finally {
                stopSpinner(stopSpinner, spinner);
            }

            // GitHub Actions: annotations + step summary (stderr / $GITHUB_STEP_SUMMARY only).
            if (CiDetector.isGitHubActions()) {
                GitHubActions.emitAnnotations(report);
                GitHubActions.writeStepSummary(report);
            }
            if (hacker && report.criticalCount() > 0) {
                HackerTui.pulsingAlert(System.out, report.criticalCount(), true, colour);
            }

            String rendered;
            try {
                if (useSarif) rendered = SarifReporter.render(report);
                else if (useJson) rendered = new JsonReporter().render(report);
                else if (useSimple) rendered = new TextReporter(colour).render(report);
                else rendered = new BoxedReporter(colour).render(report);
            } catch (Exception e) {
                System.err.println("depscan: could not render report: " + e.getMessage());
                return ExitCodes.USAGE_OR_TOOL_ERROR;
            }
            try {
                if (out != null) {
                    Files.writeString(out, rendered);
                    System.out.println("Report written to " + out);
                } else if (tui && !ci && System.console() != null && !machineOutput) {
                    System.out.print(rendered);
                    com.depscan.tui.Tui.runDashboard(report, colour);
                } else {
                    System.out.print(rendered);
                    if (!rendered.endsWith("\n")) System.out.println();
                }
            } catch (Exception e) {
                System.err.println("depscan: could not write report: " + e.getMessage());
                return ExitCodes.USAGE_OR_TOOL_ERROR;
            }
            return ExitCodes.forReport(report, setup.threshold);
        }

        /** Spinner on stderr, so stdout stays clean for piping / --json. */
        private static Thread startSpinner(AtomicBoolean stop) {
            Thread t = new Thread(() -> {
                String[] frames = {"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"};
                int i = 0;
                while (!stop.get()) {
                    System.err.print("\r" + frames[i++ % frames.length] + " Scanning dependencies and OSV.dev...");
                    try {
                        Thread.sleep(100);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
                System.err.print("\r" + " ".repeat(45) + "\r");
            });
            t.setDaemon(true);
            t.start();
            return t;
        }

        private static void stopSpinner(AtomicBoolean stop, Thread spinner) {
            if (spinner == null) return;
            stop.set(true);
            try {
                spinner.join(500);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    @Command(name = "report", description = "Scan a Maven, npm or Python project and export a report file (pdf, html, json, sarif, csv, sbom).",
            mixinStandardHelpOptions = true)
    static class ReportCommand implements Callable<Integer> {

        @Parameters(index = "0", description = "Project directory containing pom.xml, package.json, requirements.txt and/or pyproject.toml", defaultValue = ".")
        private Path projectDir;

        @Option(names = "--format", paramLabel = "<pdf|html|json|sarif|csv|sbom>", required = true,
                description = "Export format.")
        private String format;

        @Option(names = "--out", paramLabel = "<file>", description = "Output file (default: depscan-report.<ext>).")
        private Path out;

        @Option(names = "--exclude-unreachable", description = "Omit LOW (unreachable) findings from the report.")
        private boolean excludeUnreachable;

        @Option(names = "--simple", description = "Plain report without the boxed / styled extras (html/pdf only).")
        private boolean simple;

        @Option(names = "--theme", paramLabel = "<light|dark>", defaultValue = "light",
                description = "Theme for html/pdf reports: light or dark.")
        private String theme;

        @Option(names = "--fail-on", paramLabel = "<critical|reachable|high|none>")
        private String failOn;

        @Option(names = "--offline", description = "Never touch the network; use the disk cache only.")
        private boolean offline;

        @Option(names = "--no-color", description = "Disable coloured output.")
        private boolean noColor;

        @Option(names = "--no-animation", description = "Disable animation.")
        private boolean noAnimation;

        @Option(names = "--config", paramLabel = "depscan.yml")
        private Path configPath;

        @Option(names = "--cache-dir", description = "OSV cache directory (default ~/.cache/depscan/osv).")
        private Path cacheDir;

        @Override
        public Integer call() {
            String fmt = format.toLowerCase();
            if (!java.util.List.of("pdf", "html", "json", "sarif", "csv", "sbom").contains(fmt)) {
                System.err.println("depscan: unknown --format '" + format + "' (use pdf, html, json, sarif, csv or sbom)");
                return ExitCodes.USAGE_OR_TOOL_ERROR;
            }
            if (!"light".equalsIgnoreCase(theme) && !"dark".equalsIgnoreCase(theme)) {
                System.err.println("depscan: unknown --theme '" + theme + "' (use light or dark)");
                return ExitCodes.USAGE_OR_TOOL_ERROR;
            }
            if (!Files.isDirectory(projectDir)) {
                System.err.println("depscan: not a directory: " + projectDir);
                return ExitCodes.USAGE_OR_TOOL_ERROR;
            }
            ScanSetup setup;
            try {
                setup = Main.setup(projectDir, configPath, failOn, false, cacheDir, offline);
            } catch (ConfigException e) {
                System.err.println("depscan: " + e.getMessage());
                return ExitCodes.USAGE_OR_TOOL_ERROR;
            } catch (IllegalArgumentException e) {
                System.err.println("depscan: " + e.getMessage());
                return ExitCodes.USAGE_OR_TOOL_ERROR;
            }
            ScanReport report;
            try {
                report = Main.runScan(setup, projectDir, ScanProgress.NONE);
            } catch (NetworkException e) {
                System.err.println("depscan: " + e.getMessage());
                return ExitCodes.NETWORK_NO_CACHE;
            } catch (IOException e) {
                System.err.println("depscan: " + e.getMessage());
                return ExitCodes.USAGE_OR_TOOL_ERROR;
            }
            if (CiDetector.isGitHubActions()) {
                GitHubActions.emitAnnotations(report);
                GitHubActions.writeStepSummary(report);
            }
            // --exclude-unreachable applies to every export format, not just pdf/html.
            if (excludeUnreachable) {
                report = new ScanReport(report.projectPath(), report.dependenciesScanned(),
                        report.findings().stream().filter(com.depscan.reach.Finding::reachable).toList(),
                        report.skippedDependencies(), report.usedStaleCache(),
                        report.ignoredFindings(), report.configNotes(), report.dependencies());
            }
            Path target = out != null ? out : Path.of("depscan-report." + fmt);
            try {
                switch (fmt) {
                    case "pdf" -> {
                        byte[] pdf = com.depscan.report.PdfReporter.render(report, theme, excludeUnreachable);
                        Files.write(target, pdf);
                    }
                    case "html" -> Files.writeString(target,
                            com.depscan.report.HtmlReporter.render(report, theme, excludeUnreachable));
                    case "json" -> Files.writeString(target, new JsonReporter().render(report));
                    case "sarif" -> Files.writeString(target, SarifReporter.render(report));
                    case "csv" -> Files.writeString(target, com.depscan.report.CsvReporter.render(report));
                    case "sbom" -> Files.writeString(target, com.depscan.report.SbomReporter.render(report));
                    default -> throw new IllegalStateException("unreachable");
                }
            } catch (Exception e) {
                System.err.println("depscan: could not write report: " + e.getMessage());
                return ExitCodes.USAGE_OR_TOOL_ERROR;
            }
            System.out.println("Report written to " + target + " (" + fmt + ", "
                    + report.criticalCount() + " CRITICAL, " + report.lowCount() + " LOW)");
            return ExitCodes.forReport(report, setup.threshold);
        }
    }
}
