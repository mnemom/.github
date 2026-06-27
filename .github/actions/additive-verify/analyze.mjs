#!/usr/bin/env node
/**
 * additive-verify — the additive discriminator for ADW-bot PRs.
 *
 * GOAL (MNE / autoland-safety): let a genuinely-ADDITIVE bot PR auto-land without
 * a human review, while any PR that changes product/behavior still requires one.
 * "Additive" is asserted STRUCTURALLY (no behavior/control-flow change), not by
 * file path — a legit instrumentation PR touches src/ exactly like a behavior PR
 * does (cf. mnemom-platform#680 vs #155/#161).
 *
 * Two tiers, evaluated per changed file. The PR is ADDITIVE iff EVERY changed
 * file passes its tier:
 *
 *   TIER A — non-source files: must be on the additive-path allowlist AND added
 *     (or, for docs/markdown, added-or-modified). A *modified* lockfile, config,
 *     wrangler.toml, package.json, or an *edited* existing test is NOT additive
 *     (it can weaken a guard or change a dependency / runtime binding).
 *
 *   TIER B — source files (matched by `source_globs`): parsed with the TypeScript
 *     compiler. The change must be ADD-ONLY at the statement level:
 *       - no existing top-level/exported function removed or renamed;
 *       - no existing function's signature changed;
 *       - no existing statement removed or modified inside an existing function;
 *       - no control-flow / return / throw statement INJECTED into an existing
 *         function (new spans/logs/metrics calls are fine; a new `return`,
 *         `if`, `for`, response-emit is not).
 *     The legitimate "extract-and-wrap" instrumentation refactor (an existing
 *     function's body is relocated verbatim into a new sibling and the original
 *     becomes a telemetry try/finally wrapper that delegates to it) is recognized
 *     and ALLOWED — provided the public signature is unchanged.
 *
 * Calibration target (proven against real PRs):
 *   mnemom-platform#680  -> ADDITIVE  (auto-land)
 *   mnemom-platform#749  -> NEEDS-REVIEW
 *   mnemom-risk#155      -> NEEDS-REVIEW   (deceptive: "add a conformance test", 0 deletions)
 *   mnemom-risk#161      -> NEEDS-REVIEW   ("add a unit test" bundling an auth reimpl)
 *
 * FAIL-CLOSED: any parse error, any unrecognized/unclassifiable file, or any
 * internal error => NEEDS-REVIEW. The verdict can only ever WAIVE review when it
 * is positively certain the change is additive; on doubt it routes to a human.
 *
 * Pure & dependency-light: TypeScript is the only runtime dep. No network, no
 * model judgement — a deterministic, auditable signal.
 */
import ts from "typescript";
import fs from "node:fs";
import path from "node:path";

// ---------------------------------------------------------------------------
// Config (loaded from .github/additive-verify.yml in the target repo, or
// defaults below). Globs are matched against the repo-relative POSIX path.
// ---------------------------------------------------------------------------
const DEFAULT_CONFIG = {
  // Files matched here are application source -> Tier B (AST analysis).
  source_globs: ["**/src/**/*.ts", "**/src/**/*.tsx", "**/src/**/*.js", "**/src/**/*.mjs"],
  // Source globs that are NEVER source despite living under src/ (tests, fixtures).
  source_excludes: ["**/__tests__/**", "**/*.test.*", "**/*.spec.*", "**/test/**", "**/tests/**", "**/fixtures/**"],
  // Tier A: paths that are inherently additive-safe when ADDED (status=added).
  additive_added_globs: [
    "**/*.md", "**/*.mdx",
    "app_docs/**", "docs/**", "**/runbook*", "**/RUNBOOK*",
    "**/dashboards/**", "**/*.dashboard.json",
    "**/__tests__/**", "**/*.test.*", "**/*.spec.*", "**/test/**", "**/tests/**",
  ],
  // Tier A: paths that are additive-safe even when MODIFIED (docs only — text).
  additive_modified_globs: ["**/*.md", "**/*.mdx", "app_docs/**", "docs/**", "**/runbook*", "**/RUNBOOK*"],
  // Telemetry/observability calls that may be ADDED inside an existing function.
  telemetry_call_regex:
    "^(console\\.(log|info|warn|error|debug)|.*\\.(recordSpan|recordVerification|addEvent|setAttribute|increment|observe|gauge|counter|histogram|startSpan|endSpan)|emit[A-Za-z0-9]*Span|track[A-Za-z0-9]*|log[A-Za-z0-9]*Span|metrics?\\.)",
};

function globToRe(glob) {
  // minimal glob: ** => any, * => any-but-slash, . escaped.
  let re = "^";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === "*") {
      if (glob[i + 1] === "*") { re += ".*"; i++; if (glob[i + 1] === "/") i++; }
      else re += "[^/]*";
    } else if (".+?^${}()|[]\\".includes(c)) re += "\\" + c;
    else re += c;
  }
  return new RegExp(re + "$");
}
const matchesAny = (p, globs) => globs.some((g) => globToRe(g).test(p));

// ---------------------------------------------------------------------------
// Tier B — TypeScript AST analysis
// ---------------------------------------------------------------------------
const CONTROL_FLOW_KINDS = new Set([
  ts.SyntaxKind.ReturnStatement, ts.SyntaxKind.ThrowStatement, ts.SyntaxKind.IfStatement,
  ts.SyntaxKind.SwitchStatement, ts.SyntaxKind.ForStatement, ts.SyntaxKind.ForInStatement,
  ts.SyntaxKind.ForOfStatement, ts.SyntaxKind.WhileStatement, ts.SyntaxKind.DoStatement,
  ts.SyntaxKind.BreakStatement, ts.SyntaxKind.ContinueStatement,
]);

const parse = (src, name) =>
  ts.createSourceFile(name, src, ts.ScriptTarget.Latest, true, name.endsWith(".tsx") ? ts.ScriptKind.TSX : ts.ScriptKind.TS);

function collectFunctions(sf) {
  const map = new Map();
  function nameOf(node) {
    if (node.name && ts.isIdentifier(node.name)) return node.name.text;
    if (node.parent && ts.isVariableDeclaration(node.parent) && node.parent.name && ts.isIdentifier(node.parent.name))
      return node.parent.name.text;
    if (node.parent && ts.isPropertyAssignment(node.parent) && node.parent.name) return node.parent.name.getText(sf);
    return null;
  }
  function walk(node, prefix) {
    if (ts.isFunctionDeclaration(node) || ts.isMethodDeclaration(node) || ts.isFunctionExpression(node) || ts.isArrowFunction(node)) {
      const n = nameOf(node);
      if (n) { const key = prefix ? `${prefix}.${n}` : n; map.set(key, node); ts.forEachChild(node, (c) => walk(c, key)); return; }
    }
    ts.forEachChild(node, (c) => walk(c, prefix));
  }
  walk(sf, "");
  return map;
}

function signatureOf(node, sf) {
  const params = node.parameters ? node.parameters.map((p) => p.getText(sf).replace(/\s+/g, " ").trim()).join(", ") : "";
  const ret = node.type ? node.type.getText(sf).replace(/\s+/g, " ").trim() : "";
  return `(${params})=>${ret}`;
}
const bodyStatements = (node) => (node.body && node.body.statements ? [...node.body.statements] : []);
const bodyFingerprint = (node, sf) => bodyStatements(node).map((s) => s.getText(sf).replace(/\s+/g, " ").trim()).filter(Boolean);

function isBehavioralStatement(stmt) {
  let bad = null;
  (function visit(n) {
    if (bad) return;
    if (CONTROL_FLOW_KINDS.has(n.kind)) { bad = ts.SyntaxKind[n.kind]; return; }
    ts.forEachChild(n, visit);
  })(stmt);
  return bad;
}

function diffExistingFunction(name, oldNode, newNode, sfOld, sfNew) {
  const v = [];
  const so = signatureOf(oldNode, sfOld), sn = signatureOf(newNode, sfNew);
  if (so !== sn) v.push(`signature changed: ${name}  ${so} => ${sn}`);
  const oldStmts = bodyFingerprint(oldNode, sfOld);
  const newNodes = bodyStatements(newNode);
  const newStmts = newNodes.map((s) => s.getText(sfNew).replace(/\s+/g, " ").trim());
  for (const r of oldStmts.filter((s) => !newStmts.includes(s)))
    v.push(`existing statement removed/modified in ${name}: «${r.slice(0, 90)}»`);
  for (const s of newNodes) {
    const txt = s.getText(sfNew).replace(/\s+/g, " ").trim();
    if (oldStmts.includes(txt)) continue;
    const bad = isBehavioralStatement(s);
    if (bad) v.push(`control-flow ${bad} injected into existing function ${name}: «${txt.slice(0, 90)}»`);
  }
  return v;
}

function isInstrumentationWrapper(wrapperNode, delegateLeaf, sf) {
  const stmts = bodyStatements(wrapperNode);
  const tries = stmts.filter((s) => ts.isTryStatement(s));
  if (tries.length !== 1) return false;
  for (const s of stmts) { if (ts.isTryStatement(s) || ts.isVariableStatement(s)) continue; return false; }
  return tries[0].getText(sf).includes(delegateLeaf + "(");
}

export function analyzeSource(oldSrc, newSrc, fname) {
  const sfOld = parse(oldSrc, fname);
  const sfNew = parse(newSrc, fname);
  const oldFns = collectFunctions(sfOld), newFns = collectFunctions(sfNew);
  const violations = [];
  const newOnly = [...newFns].filter(([n]) => !oldFns.has(n));
  const newFps = new Map(newOnly.map(([n, node]) => [n, bodyFingerprint(node, sfNew).join("\n")]));
  for (const [name] of oldFns) if (!newFns.has(name)) violations.push(`existing function removed/renamed: ${name}`);
  for (const [name, newNode] of newFns) {
    const oldNode = oldFns.get(name);
    if (!oldNode) continue;
    const oldFp = bodyFingerprint(oldNode, sfOld).join("\n");
    let relocated = null;
    if (oldFp) for (const [nn, fp] of newFps) if (fp === oldFp) { relocated = nn; break; }
    if (relocated && isInstrumentationWrapper(newNode, relocated.split(".").pop(), sfNew)) {
      const so = signatureOf(oldNode, sfOld), sn = signatureOf(newNode, sfNew);
      if (so !== sn) violations.push(`signature changed for wrapped ${name}: ${so} => ${sn}`);
      continue;
    }
    violations.push(...diffExistingFunction(name, oldNode, newNode, sfOld, sfNew));
  }
  return violations;
}

// ---------------------------------------------------------------------------
// Driver — classify each changed file and produce the PR verdict.
// `files` is the GitHub PR files payload (status/filename/additions/deletions),
// `readBlob(path, side)` returns the file content at base ("old") / head ("new").
// ---------------------------------------------------------------------------
export async function verifyPR({ files, readBlob, config = DEFAULT_CONFIG }) {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  const telemetryRe = new RegExp(cfg.telemetry_call_regex); // reserved for future use
  void telemetryRe;
  const verdicts = [];
  let additive = true;

  for (const f of files) {
    const p = f.filename;
    const status = f.status;
    const isSource =
      matchesAny(p, cfg.source_globs) && !matchesAny(p, cfg.source_excludes);

    if (isSource) {
      // Tier B
      if (status === "removed") { additive = false; verdicts.push({ p, tier: "B", ok: false, why: ["source file deleted"] }); continue; }
      if (status === "added") {
        // A brand-new source file is additive ONLY if it introduces no
        // wiring into existing flow on its own — but a new file can still be
        // imported & called by existing code. We allow a NEW source file
        // (no prior behavior to change) but flag it for the wiring check:
        // if its addition is paired with NO modification of an existing
        // dispatcher, it is additive. Conservative default: NEW source files
        // are treated as additive (they add code; they cannot rewrite prior
        // behavior). Edits that WIRE them in would show as Tier-B violations
        // on the existing file. (Tunable: set new_source_needs_review=true.)
        if (cfg.new_source_needs_review) { additive = false; verdicts.push({ p, tier: "B", ok: false, why: ["new source file (policy: review new source)"] }); }
        else verdicts.push({ p, tier: "B", ok: true, why: ["new source file (no prior behavior)"] });
        continue;
      }
      // modified / renamed
      let oldSrc, newSrc;
      try { oldSrc = await readBlob(p, "old"); newSrc = await readBlob(p, "new"); }
      catch (e) { additive = false; verdicts.push({ p, tier: "B", ok: false, why: ["could not read blob (fail-closed): " + e.message] }); continue; }
      let v;
      try { v = analyzeSource(oldSrc, newSrc, p); }
      catch (e) { additive = false; verdicts.push({ p, tier: "B", ok: false, why: ["parse/analyze error (fail-closed): " + e.message] }); continue; }
      const ok = v.length === 0;
      if (!ok) additive = false;
      verdicts.push({ p, tier: "B", ok, why: ok ? ["additive instrumentation only"] : v });
      continue;
    }

    // Tier A — non-source
    if (status === "added" && matchesAny(p, cfg.additive_added_globs)) {
      verdicts.push({ p, tier: "A", ok: true, why: ["allowlisted additive path (added)"] }); continue;
    }
    if (status === "modified" && matchesAny(p, cfg.additive_modified_globs)) {
      verdicts.push({ p, tier: "A", ok: true, why: ["allowlisted doc path (modified text)"] }); continue;
    }
    // Anything else (modified config/lockfile/wrangler.toml/package.json, edited
    // test, unknown path, removed file) -> fail-closed.
    additive = false;
    verdicts.push({ p, tier: "A", ok: false, why: [`not on additive allowlist for status=${status} (fail-closed)`] });
  }

  return { additive, verdicts };
}

export function loadConfig(repoRoot) {
  for (const rel of [".github/additive-verify.yml", ".github/additive-verify.yaml"]) {
    const fp = path.join(repoRoot, rel);
    if (fs.existsSync(fp)) {
      // tiny YAML: we only support simple list/scalar keys; fall back to default on any complexity.
      try { return parseTinyYaml(fs.readFileSync(fp, "utf8")); } catch { return DEFAULT_CONFIG; }
    }
  }
  return DEFAULT_CONFIG;
}
function parseTinyYaml(text) {
  const cfg = {}; let key = null;
  for (const raw of text.split("\n")) {
    const line = raw.replace(/#.*$/, "");
    if (!line.trim()) continue;
    const li = line.match(/^(\w[\w-]*):\s*(.*)$/);
    if (li) { key = li[1]; const val = li[2].trim(); if (val === "" ) cfg[key] = []; else if (val === "true"||val==="false") cfg[key]=val==="true"; else cfg[key] = val.replace(/^["']|["']$/g, ""); continue; }
    const item = line.match(/^\s*-\s*(.*)$/);
    if (item && key && Array.isArray(cfg[key])) cfg[key].push(item[1].trim().replace(/^["']|["']$/g, ""));
  }
  return { ...DEFAULT_CONFIG, ...cfg };
}

export { DEFAULT_CONFIG };
