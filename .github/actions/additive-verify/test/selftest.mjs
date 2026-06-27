#!/usr/bin/env node
/**
 * Calibration self-test for the additive discriminator.
 *
 * The fixtures are the EXACT base/head blobs of four real ADW-bot PRs. They lock
 * the calibration into CI so the discriminator can never silently regress:
 *
 *   mnemom-platform#680  per-log observer.process_log span  -> ADDITIVE (auto-land)
 *       includes the extract-and-wrap instrumentation refactor (0 line deletions).
 *   mnemom-platform#749  Grafana dashboard + runbook + src rewrite -> NEEDS-REVIEW
 *   mnemom-risk#155      "add a conformance test" (titled additive) but adds a
 *                        `return jsonResponse({..._persistence_failed})` inside an
 *                        existing handler -> NEEDS-REVIEW  (deceptive; 0 deletions)
 *   mnemom-risk#161      "add a unit test" bundling an auth+tenant reimplementation
 *                        (signature changes, fail-closed branches) -> NEEDS-REVIEW
 *
 * Each PR passes iff EVERY changed source file is additive. We exercise the
 * source-file analyzer (analyzeSource) directly against the fixtures.
 */
import { analyzeSource } from "../analyze.mjs";
import fs from "node:fs";
import url from "node:url";
import path from "node:path";

const here = path.dirname(url.fileURLToPath(import.meta.url));
const fx = (n) => fs.readFileSync(path.join(here, "fixtures", n), "utf8");
const analyze = (base, head, name) => analyzeSource(fx(base), fx(head), name);

// A PR-level case = the union of its changed source files. additive iff all clean.
const cases = [
  {
    pr: "mnemom-platform#680",
    expect: "additive",
    files: [
      analyze("p680.index.old.ts", "p680.index.new.ts", "observer/src/index.ts"),
      analyze("p680.metrics.old.ts", "p680.metrics.new.ts", "observer/src/metrics.ts"),
    ],
  },
  {
    pr: "mnemom-platform#749",
    expect: "needs-review",
    files: [analyze("p749.index.old.ts", "p749.index.new.ts", "log-relay/src/index.ts")],
  },
  {
    pr: "mnemom-risk#155",
    expect: "needs-review",
    files: [analyze("r155.handlers.old.ts", "r155.handlers.new.ts", "server/src/handlers.ts")],
  },
  {
    pr: "mnemom-risk#161",
    expect: "needs-review",
    files: [
      analyze("r161.handlers.old.ts", "r161.handlers.new.ts", "server/src/handlers.ts"),
      analyze("r161.index.old.ts", "r161.index.new.ts", "server/src/index.ts"),
    ],
  },
];

let failed = 0;
for (const c of cases) {
  const violations = c.files.flat();
  const verdict = violations.length === 0 ? "additive" : "needs-review";
  const pass = verdict === c.expect;
  if (!pass) failed++;
  console.log(`${pass ? "PASS" : "FAIL"}  ${c.pr.padEnd(22)} expected=${c.expect.padEnd(12)} got=${verdict}`);
  if (!pass || process.env.VERBOSE) for (const v of violations.slice(0, 6)) console.log("        · " + v);
}

console.log(failed === 0 ? "\nAll calibration cases pass." : `\n${failed} calibration case(s) FAILED.`);
process.exit(failed === 0 ? 0 : 1);
