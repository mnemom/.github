#!/usr/bin/env node
/**
 * additive-verify CI runner.
 *
 * Resolves the PR's changed files + base/head blobs from the local checkout and
 * the GitHub API, runs the additive discriminator (analyze.mjs), writes a job
 * summary, and exits 0 (ADDITIVE) or 1 (NEEDS-REVIEW). The reusable workflow
 * surfaces this as the `additive-verify` commit status.
 *
 * Inputs (env): GITHUB_TOKEN, GITHUB_REPOSITORY, PR_NUMBER, BASE_SHA, HEAD_SHA,
 * GITHUB_STEP_SUMMARY, GITHUB_OUTPUT, GITHUB_WORKSPACE.
 *
 * This runner NEVER merges and NEVER changes protection — it only computes and
 * publishes a status. Wiring the status into branch protection is the human step
 * (see docs/additive-verify.md).
 */
import { verifyPR, loadConfig } from "./analyze.mjs";
import fs from "node:fs";

const {
  GITHUB_TOKEN, GITHUB_REPOSITORY, PR_NUMBER, BASE_SHA, HEAD_SHA,
  GITHUB_STEP_SUMMARY, GITHUB_OUTPUT, GITHUB_WORKSPACE = ".",
} = process.env;

const [owner, repo] = (GITHUB_REPOSITORY || "/").split("/");
const api = async (p) => {
  const r = await fetch(`https://api.github.com${p}`, {
    headers: { Authorization: `Bearer ${GITHUB_TOKEN}`, Accept: "application/vnd.github+json", "User-Agent": "additive-verify" },
  });
  if (!r.ok) throw new Error(`GitHub API ${p} -> ${r.status}`);
  return r.json();
};
const rawBlob = async (path, ref) => {
  const r = await fetch(`https://api.github.com/repos/${owner}/${repo}/contents/${encodeURI(path)}?ref=${ref}`, {
    headers: { Authorization: `Bearer ${GITHUB_TOKEN}`, Accept: "application/vnd.github.raw", "User-Agent": "additive-verify" },
  });
  if (!r.ok) throw new Error(`blob ${path}@${ref} -> ${r.status}`);
  return r.text();
};

async function main() {
  const files = [];
  for (let page = 1; ; page++) {
    const batch = await api(`/repos/${owner}/${repo}/pulls/${PR_NUMBER}/files?per_page=100&page=${page}`);
    files.push(...batch);
    if (batch.length < 100) break;
  }
  const config = loadConfig(GITHUB_WORKSPACE);
  const readBlob = (path, side) => rawBlob(path, side === "old" ? BASE_SHA : HEAD_SHA);

  const { additive, verdicts } = await verifyPR({ files, readBlob, config });

  // Job summary
  const lines = [`## additive-verify — ${additive ? "✅ ADDITIVE (review may be waived)" : "🟥 NEEDS-REVIEW"}`, ""];
  lines.push("| file | tier | verdict | reason |", "| --- | --- | --- | --- |");
  for (const v of verdicts) {
    const reason = v.why.join("; ").replace(/\|/g, "\\|");
    lines.push(`| \`${v.p}\` | ${v.tier} | ${v.ok ? "✅" : "🟥"} | ${reason} |`);
  }
  if (!additive) {
    lines.push("", "> A 🟥 means this PR changes behavior/control-flow (or touches a non-allowlisted",
      "> path). It must keep the normal human review. This check does NOT block the PR by",
      "> itself — it only reports whether review may be safely waived.");
  }
  const summary = lines.join("\n") + "\n";
  if (GITHUB_STEP_SUMMARY) fs.appendFileSync(GITHUB_STEP_SUMMARY, summary);
  else process.stdout.write(summary);

  if (GITHUB_OUTPUT) fs.appendFileSync(GITHUB_OUTPUT, `additive=${additive}\n`);

  // Exit code drives the check conclusion. NEEDS-REVIEW => failure (red status),
  // which the branch-protection bypass (human step) keys off: bypass applies only
  // when this status is success.
  process.exit(additive ? 0 : 1);
}

main().catch((e) => {
  // Fail-closed: any runner error => NEEDS-REVIEW.
  const msg = `## additive-verify — 🟥 NEEDS-REVIEW (runner error, fail-closed)\n\n\`\`\`\n${e.stack || e.message}\n\`\`\`\n`;
  if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, msg);
  else process.stderr.write(msg);
  if (process.env.GITHUB_OUTPUT) fs.appendFileSync(process.env.GITHUB_OUTPUT, "additive=false\n");
  process.exit(1);
});
