package com.depscan.graph;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.CallableDeclaration;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.ConstructorDeclaration;
import com.github.javaparser.ast.body.EnumDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.MethodReferenceExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.expr.VariableDeclarationExpr;
import com.github.javaparser.ast.stmt.BlockStmt;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

/**
 * Builds a directed call graph from Java source with JavaParser — no symbol
 * solver, no classpath, no compilation required. Resolution is heuristic but
 * explicit about its rules (see below); it is designed for reachability
 * analysis, where a missed edge is a false "unreachable", so ambiguous calls
 * resolve to <em>all</em> plausible targets rather than none.
 *
 * <p>Resolution rules:
 * <ol>
 *   <li>Method id = {@code FQN#name(arity)} — arity disambiguates overloads;
 *       parameter types are not used (source-only parsing cannot reliably
 *       resolve them without a classpath).</li>
 *   <li>Unqualified call in a class &rarr; a method of that class, else a
 *       method inherited from a superclass / interface in the codebase.</li>
 *   <li>Qualified call {@code x.m(...)}: {@code x} is resolved from local
 *       variable / parameter / field declarations in the enclosing method and
 *       class; if {@code x} is a known class name, the call targets that
 *       class; if {@code x} is {@code this}/{@code super}, the enclosing /
 *       superclass; otherwise the scope's type is unknown and the call is
 *       recorded as an external call to {@code <scope>.m} only when the scope
 *       looks like a class name (capitalised), else it is matched by
 *       method-name against every known method (virtual-dispatch fallback).</li>
 *   <li>Interface / inheritance: a call to a method declared on an interface
 *       or superclass also creates edges to every overriding implementation
 *       in the codebase with the same name+arity (virtual dispatch), and a
 *       call on a concrete class whose method is overridden in a subclass
 *       also edges to the overrides. {@code new X(...)} is an edge to
 *       {@code X#X(arity)} when X is in the codebase, else an external call.</li>
 *   <li>Calls inside lambdas / anonymous classes belong to the enclosing
 *       method. Static imports are treated as unqualified calls.</li>
 * </ol>
 * Anything that cannot be resolved to a user method is recorded as an
 * external call ({@code ClassName#method(arity)} with the best-known class
 * name, or {@code ?#method(arity)} when even that is unknown) — the reach
 * stage matches those against vulnerable functions / packages.
 */
public final class CallGraphBuilder {

    private CallGraphBuilder() {}

    public static CallGraph build(Path sourceRoot) throws IOException {
        List<Path> files;
        try (Stream<Path> s = Files.walk(sourceRoot)) {
            files = s.filter(p -> p.toString().endsWith(".java")).sorted().toList();
        }
        var ctx = new Context();
        for (Path f : files) {
            CompilationUnit cu;
            try {
                cu = StaticJavaParser.parse(f);
            } catch (Exception e) {
                System.err.println("depscan: warning: could not parse " + f + " (" + e.getMessage() + "), skipping");
                continue;
            }
            ctx.addFile(cu, f);
        }
        ctx.resolveEdges();
        return ctx.toGraph();
    }

    // ------------------------------------------------------------------
    // Internal state
    // ------------------------------------------------------------------

    private static final class ClassInfo {
        String fqn;
        String simpleName;
        String superFqn;                 // may be null
        List<String> interfaces = new ArrayList<>();
        boolean isInterface;
        Map<String, String> methods = new LinkedHashMap<>(); // name(arity) -> methodId
    }

    private static final class Context {
        Map<String, ClassInfo> byFqn = new LinkedHashMap<>();
        Map<String, String> bySimpleName = new HashMap<>(); // simple -> FQN (first wins)
        Map<String, String> methodToFile = new LinkedHashMap<>();
        Map<String, String> methodLocations = new LinkedHashMap<>();
        Map<String, Map<String, String>> callSites = new LinkedHashMap<>();
        Map<String, Set<String>> edges = new LinkedHashMap<>();
        Map<String, Set<String>> external = new LinkedHashMap<>();
        Set<String> entryPoints = new LinkedHashSet<>();
        // simple class name -> fully-qualified name, from import declarations
        // across all scanned files (first wins). This is what lets an external
        // call like StringSubstitutor.createInterpolator() resolve to
        // org.apache.commons.text.StringSubstitutor#createInterpolator(0)
        // instead of the bare simple name.
        Map<String, String> imports = new HashMap<>();
        // methodId -> enclosing class FQN, for inheritance lookups
        Map<String, String> methodClass = new HashMap<>();
        // raw calls collected per method, resolved in a second pass
        record RawCall(String caller, String scopeText, String name, int arity, boolean isConstructor, String scopeTypeHint,
                       String file, int line) {}
        List<RawCall> rawCalls = new ArrayList<>();
        // methodId -> variable name -> declared type (simple name)
        Map<String, Map<String, String>> methodVars = new HashMap<>();
        // class FQN -> field name -> type (simple name)
        Map<String, Map<String, String>> classFields = new HashMap<>();

        void addFile(CompilationUnit cu, Path file) {
            String pkg = cu.getPackageDeclaration().map(p -> p.getNameAsString()).orElse("");
            cu.getImports().forEach(imp -> {
                if (!imp.isAsterisk()) {
                    String fqn = imp.getNameAsString();
                    int dot = fqn.lastIndexOf('.');
                    if (dot > 0) imports.putIfAbsent(fqn.substring(dot + 1), fqn);
                }
            });
            // First pass: register classes + methods.
            cu.findAll(ClassOrInterfaceDeclaration.class).forEach(c -> registerClass(c, pkg, file));
            cu.findAll(EnumDeclaration.class).forEach(e -> {
                ClassInfo info = new ClassInfo();
                info.fqn = pkg.isEmpty() ? e.getNameAsString() : pkg + "." + e.getNameAsString();
                info.simpleName = e.getNameAsString();
                byFqn.put(info.fqn, info);
                bySimpleName.putIfAbsent(info.simpleName, info.fqn);
            });
            // Second pass: collect calls per method.
            cu.findAll(MethodDeclaration.class).forEach(m -> collectMethod(m, pkg, file));
            cu.findAll(ConstructorDeclaration.class).forEach(c -> collectMethod(c, pkg, file));
        }

        private void registerClass(ClassOrInterfaceDeclaration c, String pkg, Path file) {
            // Nested classes: FQN uses the enclosing class name with '.'.
            String enclosing = c.getParentNode()
                    .flatMap(p -> p instanceof ClassOrInterfaceDeclaration parent
                            ? java.util.Optional.of(parent.getNameAsString()) : java.util.Optional.empty())
                    .orElse("");
            String simple = enclosing.isEmpty() ? c.getNameAsString() : enclosing + "." + c.getNameAsString();
            String fqn = pkg.isEmpty() ? simple : pkg + "." + simple;
            ClassInfo info = byFqn.computeIfAbsent(fqn, k -> new ClassInfo());
            info.fqn = fqn;
            info.simpleName = c.getNameAsString();
            info.isInterface = c.isInterface();
            bySimpleName.putIfAbsent(c.getNameAsString(), fqn);
            c.getExtendedTypes().stream().findFirst().ifPresent(t -> info.superFqn = resolveTypeName(t.getNameAsString(), pkg));
            c.getImplementedTypes().forEach(t -> info.interfaces.add(resolveTypeName(t.getNameAsString(), pkg)));
            Map<String, String> fields = classFields.computeIfAbsent(fqn, k -> new HashMap<>());
            c.getFields().forEach(f -> f.getVariables().forEach(v ->
                    fields.put(v.getNameAsString(), v.getType().asString())));
            for (CallableDeclaration<?> m : c.getMembers().stream()
                    .filter(mm -> mm instanceof CallableDeclaration).map(mm -> (CallableDeclaration<?>) mm).toList()) {
                String name = m instanceof MethodDeclaration md ? md.getNameAsString() : c.getNameAsString();
                int arity = m.getParameters().size();
                String methodId = fqn + "#" + name + "(" + arity + ")";
                info.methods.put(name + "(" + arity + ")", methodId);
                methodToFile.put(methodId, file.toString());
                int declLine = m.getRange().map(r -> r.begin.line).orElse(-1);
                if (declLine > 0) methodLocations.put(methodId, file + ":" + declLine);
                methodClass.put(methodId, fqn);
                boolean isMain = m instanceof MethodDeclaration md
                        && md.getNameAsString().equals("main") && arity == 1
                        && md.isPublic() && md.isStatic();
                boolean isPublic = m instanceof MethodDeclaration md ? md.isPublic()
                        : m instanceof ConstructorDeclaration cd && cd.isPublic();
                if (isMain || isPublic) entryPoints.add(methodId);
            }
        }

        private void collectMethod(CallableDeclaration<?> m, String pkg, Path file) {
            String classFqn = enclosingClassFqn(m, pkg);
            if (classFqn == null) return;
            String name = m instanceof MethodDeclaration md ? md.getNameAsString()
                    : ((ConstructorDeclaration) m).getNameAsString();
            String methodId = classFqn + "#" + name + "(" + m.getParameters().size() + ")";
            Map<String, String> vars = new HashMap<>();
            for (Parameter p : m.getParameters()) vars.put(p.getNameAsString(), p.getType().asString());
            methodVars.put(methodId, vars);
            m.findAll(VariableDeclarator.class).forEach(v ->
                    vars.put(v.getNameAsString(), v.getType().asString()));
            // Field types visible as unqualified scope.
            classFields.getOrDefault(classFqn, Map.of()).forEach(vars::putIfAbsent);

            m.accept(new VoidVisitorAdapter<Void>() {
                @Override
                public void visit(MethodCallExpr call, Void arg) {
                    super.visit(call, arg);
                    String scope = call.getScope().map(Expression::toString).orElse(null);
                    rawCalls.add(new RawCall(methodId, scope, call.getNameAsString(),
                            call.getArguments().size(), false, null,
                            file.toString(), call.getRange().map(r -> r.begin.line).orElse(-1)));
                }

                @Override
                public void visit(ObjectCreationExpr expr, Void arg) {
                    super.visit(expr, arg);
                    String type = expr.getType().getNameAsString();
                    rawCalls.add(new RawCall(methodId, null, type, expr.getArguments().size(), true, type,
                            file.toString(), expr.getRange().map(r -> r.begin.line).orElse(-1)));
                }

                @Override
                public void visit(MethodReferenceExpr ref, Void arg) {
                    super.visit(ref, arg);
                    rawCalls.add(new RawCall(methodId, ref.getScope().toString(),
                            ref.getIdentifier(), 0, false, null,
                            file.toString(), ref.getRange().map(r -> r.begin.line).orElse(-1)));
                }
            }, null);
            // Entry points were registered in registerClass; main/public already covered.
            // (Re-assert here in case the method was declared in an enum etc.)
            if (m instanceof MethodDeclaration md && md.getNameAsString().equals("main")) {
                entryPoints.add(methodId);
            }
        }

        private String enclosingClassFqn(CallableDeclaration<?> m, String pkg) {
            var node = m.getParentNode();
            while (node.isPresent()) {
                if (node.get() instanceof ClassOrInterfaceDeclaration c) {
                    String simple = c.getNameAsString();
                    // Walk up for nesting.
                    var parent = c.getParentNode();
                    while (parent.isPresent() && parent.get() instanceof ClassOrInterfaceDeclaration pc) {
                        simple = pc.getNameAsString() + "." + simple;
                        parent = pc.getParentNode();
                    }
                    return pkg.isEmpty() ? simple : pkg + "." + simple;
                }
                if (node.get() instanceof EnumDeclaration e) {
                    return pkg.isEmpty() ? e.getNameAsString() : pkg + "." + e.getNameAsString();
                }
                node = node.get().getParentNode();
            }
            return null;
        }

        private String resolveTypeName(String simple, String pkg) {
            if (simple.contains(".")) return simple;
            String imported = imports.get(simple);
            if (imported != null) return imported;
            String known = bySimpleName.get(simple);
            if (known != null) return known;
            return pkg.isEmpty() ? simple : pkg + "." + simple;
        }

        void resolveEdges() {
            for (RawCall rc : rawCalls) {
                Set<String> targets = resolveCall(rc);
                for (String t : targets) {
                    if (methodToFile.containsKey(t)) {
                        edges.computeIfAbsent(rc.caller(), k -> new LinkedHashSet<>()).add(t);
                        // Virtual dispatch: also edge to overrides of t.
                        for (String override : overridesOf(t)) {
                            if (!override.equals(t)) {
                                edges.computeIfAbsent(rc.caller(), k -> new LinkedHashSet<>()).add(override);
                            }
                        }
                    } else {
                        external.computeIfAbsent(rc.caller(), k -> new LinkedHashSet<>()).add(t);
                        if (rc.line() > 0) {
                            callSites.computeIfAbsent(rc.caller(), k -> new LinkedHashMap<>())
                                    .putIfAbsent(t, rc.file() + ":" + rc.line());
                        }
                    }
                }
            }
            // Ensure every user method appears as a key (even with no callees).
            for (String m : methodToFile.keySet()) {
                edges.putIfAbsent(m, new LinkedHashSet<>());
                external.putIfAbsent(m, new LinkedHashSet<>());
            }
        }

        /** All methods in the codebase overriding the given method (same name+arity, subclass). */
        private Set<String> overridesOf(String methodId) {
            Set<String> out = new LinkedHashSet<>();
            String cls = methodClass.get(methodId);
            if (cls == null) return out;
            String key = methodId.substring(methodId.indexOf('#') + 1); // name(arity)
            for (ClassInfo sub : byFqn.values()) {
                if (isSubclassOf(sub.fqn, cls) && !sub.fqn.equals(cls)) {
                    String override = sub.methods.get(key);
                    if (override != null) out.add(override);
                }
            }
            return out;
        }

        private boolean isSubclassOf(String candidate, String ancestor) {
            String cur = candidate;
            Set<String> seen = new HashSet<>();
            while (cur != null && seen.add(cur)) {
                ClassInfo info = byFqn.get(cur);
                if (info == null) return false;
                if (ancestor.equals(info.superFqn) || info.interfaces.contains(ancestor)) return true;
                cur = info.superFqn;
            }
            return false;
        }

        private Set<String> resolveCall(RawCall rc) {
            String callerClass = methodClass.get(rc.caller());
            String key = rc.name() + "(" + rc.arity() + ")";
            if (rc.isConstructor()) {
                String fqn = resolveTypeName(rc.name(), classPackage(callerClass));
                String id = fqn + "#" + rc.name() + "(" + rc.arity() + ")";
                return Set.of(id);
            }
            // Unqualified: own class, then inherited.
            if (rc.scopeText() == null) {
                if (callerClass != null) {
                    String own = byFqn.getOrDefault(callerClass, new ClassInfo()).methods.get(key);
                    if (own != null) return Set.of(own);
                    String inherited = findInherited(callerClass, key);
                    if (inherited != null) return Set.of(inherited);
                }
                // Static import / same-package fallback: every known method with this name+arity.
                Set<String> all = new LinkedHashSet<>();
                for (ClassInfo ci : byFqn.values()) {
                    String m = ci.methods.get(key);
                    if (m != null) all.add(m);
                }
                if (!all.isEmpty()) return all;
                return Set.of("?#" + rc.name() + "(" + rc.arity() + ")");
            }
            String scope = rc.scopeText();
            if ("this".equals(scope)) {
                if (callerClass != null) {
                    String own = byFqn.getOrDefault(callerClass, new ClassInfo()).methods.get(key);
                    if (own != null) return Set.of(own);
                }
                return Set.of("?#" + rc.name() + "(" + rc.arity() + ")");
            }
            if ("super".equals(scope)) {
                if (callerClass != null) {
                    String sup = byFqn.getOrDefault(callerClass, new ClassInfo()).superFqn;
                    if (sup != null) {
                        String m = byFqn.getOrDefault(sup, new ClassInfo()).methods.get(key);
                        if (m != null) return Set.of(m);
                    }
                }
                return Set.of("?#" + rc.name() + "(" + rc.arity() + ")");
            }
            // Variable / parameter / field: use its declared type.
            Map<String, String> vars = methodVars.getOrDefault(rc.caller(), Map.of());
            String varType = vars.get(scope);
            if (varType != null) {
                String typeFqn = resolveTypeName(stripGenerics(varType), classPackage(callerClass));
                ClassInfo target = byFqn.get(typeFqn);
                if (target != null) {
                    String m = target.methods.get(key);
                    if (m != null) return implementationsOf(target, key, m);
                    String inherited = findInherited(typeFqn, key);
                    if (inherited != null) return implementationsOf(byFqn.get(methodClass.get(inherited)), key, inherited);
                    // Method not found on a known user type: external call on that type.
                    return Set.of(typeFqn + "#" + rc.name() + "(" + rc.arity() + ")");
                }
                // Known type name but not in codebase (library/JDK): external.
                return Set.of(typeFqn + "#" + rc.name() + "(" + rc.arity() + ")");
            }
            // Scope is a `new X(...)` expression: the call is on a fresh X.
            if (scope.startsWith("new ")) {
                String typeName = scope.substring(4);
                int paren = typeName.indexOf('(');
                if (paren >= 0) typeName = typeName.substring(0, paren).trim();
                String fqn = resolveTypeName(typeName, classPackage(callerClass));
                return Set.of(fqn + "#" + rc.name() + "(" + rc.arity() + ")");
            }
            // Chained call, e.g. StringSubstitutor.createInterpolator().replace(x)
            // or foo.bar().baz(): the receiver's class is the first segment of
            // the chain (a class name or a variable); use it as the declaring
            // class. Return-type tracking is out of scope for a source-only
            // parser, and the first segment is the best available evidence.
            if (scope.contains(".")) {
                String first = scope.substring(0, scope.indexOf('.'));
                String fqn = null;
                Map<String, String> vars2 = methodVars.getOrDefault(rc.caller(), Map.of());
                if (vars2.containsKey(first)) {
                    fqn = resolveTypeName(stripGenerics(vars2.get(first)), classPackage(callerClass));
                } else if (!first.isEmpty() && Character.isUpperCase(first.charAt(0))) {
                    fqn = resolveTypeName(first, classPackage(callerClass));
                }
                if (fqn != null) {
                    ClassInfo target = byFqn.get(fqn);
                    if (target != null) {
                        String m = target.methods.get(key);
                        if (m != null) return implementationsOf(target, key, m);
                    }
                    return Set.of(fqn + "#" + rc.name() + "(" + rc.arity() + ")");
                }
            }
            // Scope is a class name (static call / new-style): ClassName.method(...)
            if (!scope.isEmpty() && Character.isUpperCase(scope.charAt(0)) && !scope.contains(" ")) {
                String fqn = resolveTypeName(scope, classPackage(callerClass));
                // If the class is in the codebase, resolve; else external with that class.
                ClassInfo target = byFqn.get(fqn);
                if (target != null) {
                    String m = target.methods.get(key);
                    if (m != null) return implementationsOf(target, key, m);
                }
                return Set.of(fqn + "#" + rc.name() + "(" + rc.arity() + ")");
            }
            // Unknown scope (method result, chained call, etc.): match by name across codebase,
            // else record an external call with unknown class so package matching can still try.
            Set<String> all = new LinkedHashSet<>();
            for (ClassInfo ci : byFqn.values()) {
                String m = ci.methods.get(key);
                if (m != null) all.add(m);
            }
            if (!all.isEmpty()) return all;
            return Set.of("?#" + rc.name() + "(" + rc.arity() + ")");
        }

        /** If target is an interface/abstract type, include every implementation; else just the method. */
        private Set<String> implementationsOf(ClassInfo target, String key, String declared) {
            Set<String> out = new LinkedHashSet<>();
            out.add(declared);
            for (ClassInfo ci : byFqn.values()) {
                if (!ci.fqn.equals(target.fqn) && isSubclassOf(ci.fqn, target.fqn)) {
                    String impl = ci.methods.get(key);
                    if (impl != null) out.add(impl);
                }
            }
            return out;
        }

        private String findInherited(String classFqn, String key) {
            String cur = byFqn.getOrDefault(classFqn, new ClassInfo()).superFqn;
            Set<String> seen = new HashSet<>();
            while (cur != null && seen.add(cur)) {
                ClassInfo info = byFqn.get(cur);
                if (info == null) return null;
                String m = info.methods.get(key);
                if (m != null) return m;
                cur = info.superFqn;
            }
            // Interfaces of the class and its ancestors.
            ClassInfo start = byFqn.get(classFqn);
            if (start != null) {
                for (String iface : start.interfaces) {
                    ClassInfo ii = byFqn.get(iface);
                    if (ii != null && ii.methods.containsKey(key)) return ii.methods.get(key);
                }
            }
            return null;
        }

        private static String stripGenerics(String t) {
            int i = t.indexOf('<');
            return i >= 0 ? t.substring(0, i) : t;
        }

        private static String classPackage(String classFqn) {
            if (classFqn == null) return "";
            int i = classFqn.lastIndexOf('.');
            // Heuristic: package is everything before the (capitalised) class name.
            return i > 0 ? classFqn.substring(0, i) : "";
        }

        CallGraph toGraph() {
            return new CallGraph(
                    new LinkedHashSet<>(methodToFile.keySet()),
                    new LinkedHashSet<>(entryPoints),
                    edges, external, new LinkedHashMap<>(methodToFile),
                    new LinkedHashMap<>(methodLocations),
                    new LinkedHashMap<>(callSites));
        }
    }
}
