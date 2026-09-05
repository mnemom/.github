# additive-verify — autoland-safe review waiver for ADW-bot PRs

This document specifies **how a human (org admin) wires the `additive-verify`
check into branch protection** so that a genuinely-additive ADW-bot PR can land
without a human review, while behavior/product changes still require one.

**The CI check itself ships parked** (the reusable workflow + composite action in
this repo). Nothing here is applied automatically. The workflow only computes and
publishes the `additive-verify` commit status. **Wiring it into protection is the
deliberate human step below.**

---

## 1. Protection survey of the Q&R repos (as found)

All eight repos protect `main` with **`required_linear_history`**, no force-push,
no deletion. Crucially, **none currently require a human PR review via GitHub
config** — `required_pull_request_reviews` is unset on classic protection, and no
repo has a `pull_request` *ruleset* rule. The "review" today is a **process
convention** (the ADW shepherd's `adw:needs-human` label + the `review-gate`
status aggregating Claude Code Review / CodeQL), not a GitHub-enforced gate.

| repo | required status checks on `main` | review enforced by GitHub? | rulesets | CODEOWNERS |
| --- | --- | --- | --- | --- |
| `mnemom-api` | Unit Tests, Type Check, Security-axis / Schemathesis / No-internal-leak / Cross-service contract conformance, gitleaks, trufflehog | no | none | `* @alexgarden`, `src/billing/`, `.github/workflows/` |
| `mnemom-platform` | Typecheck, Test, gitleaks, npm-audit (prod deps), lint (strict) | no | none | `* @alexgarden`, `deploy/`, `cli/src/lib/config.ts`, `.github/workflows/` |
| `mnemom-website` | Type Check, Build, Lint, Test, lighthouse, journeys-e2e-gate | no | **"Bypass for Mnemom Watchdog"** (active): required status checks + deletion/non-FF; bypass actor = `mnemom-watchdog` App (id 3513404) | `* @alexgarden`, `.github/workflows/` |
| `docs` | Block internal-reference leakage | no | none | (none) |
| `polis` | CI Gate | no (Copilot review only) | **"Copilot review for default branch"** (active): `copilot_code_review` (automated, not human) + deletion/non-FF | (none) |
| `coherence` | (none) | no | none | `* @alexgarden`, … |
| `mnemom-risk` | server-typecheck, server-tests (strict) | no | none | `* @alexgarden`, `server/`, `.github/workflows/` |
| `mnemom-reputation` | server-check, client-typescript (strict) | no | none | `* @alexgarden`, `server/`, `.github/workflows/` |

CODEOWNERS lists `@alexgarden` as owner everywhere it exists, but because
`require_code_owner_reviews` is **off**, CODEOWNERS is advisory — it does not
block a merge today.

### Why does platform#749 "need a review" while platform#680 didn't?

Not via GitHub config (neither repo requires review). The distinction is the
**ADW shepherd's risk routing**: `#680` was clean additive instrumentation and
merged; `#749` and the `mnemom-risk` PRs `#155`/`#161` were labelled
**`adw:needs-human`** and parked. `additive-verify` makes that human-judgement
distinction **machine-checked and GitHub-enforceable** so a review waiver can be
granted safely (the shepherd's label is a process signal; a required status check
is an enforceable gate).

> **Implication for the change below:** because GitHub does not currently enforce
> a human review on these repos, "waive the review when additive-verify is green"
> is implemented as: **introduce a review requirement that the bot can satisfy
> *either* by a human approval *or* by a green `additive-verify`** — not by
> loosening an existing hard gate. If a repo is intended to truly require human
> review going forward, that review rule is added at the same time (Option B).

---

## 2. Why a blanket App bypass is unsafe (and is NOT what we do)

A GitHub **ruleset bypass actor** of type *Integration* (the mechanism the
`mnemom-website` ruleset uses for the Watchdog App) grants the bypass to
**everything the App does, unconditionally** — it **cannot** be conditioned on a
status check being green. Adding the `mnemom-adw` App (id **3942970**) as a
bypass actor on a review rule would therefore be exactly the blanket bypass that
auto-lands `#161`'s auth change. **Do not do this.**

The conditional waiver is instead enforced by **`additive-verify` itself being a
required, fail-closed status check** that goes red on any behavior change. The bot
clears review by clearing the check; a human is only pulled in when the check is
red.

---

## 3. Branch-protection change spec (human step)

Pick **one** mechanism per repo. Option A is the simplest and is recommended for
repos that (per the survey) do not enforce human review today. Option B adds an
actual human-review requirement and is for repos where you want review-by-default
with an additive escape hatch.

Replace `<REPO>` with one of the Q&R repos. The `mnemom-adw` App id is **3942970**.

### Prerequisite (both options): publish the check on the repo

Add the thin caller workflow to `<REPO>` (this is itself an ordinary PR; it must
be merged by a human because `.github/workflows/**` is NEVER-AUTO for the bot):

```yaml
# .github/workflows/additive-verify.yml in <REPO>
name: additive-verify
on:
  pull_request:
    types: [opened, synchronize, reopened]
jobs:
  additive-verify:
    uses: mnemom/.github/.github/workflows/additive-verify.yml@main
```

Open one PR per repo, let `additive-verify` run once so the `additive-verify`
status context exists, **then** apply A or B.

### Option A — make `additive-verify` a required check, gating the merge directly

The bot's PR cannot merge until `additive-verify` is **green**, which it only is
when the change is additive. A behavior change → red `additive-verify` → blocked →
the shepherd's `adw:needs-human` routing takes over (human reviews + merges). No
review rule is loosened; the check *is* the gate.

```sh
# Add additive-verify to the existing required-status-check contexts (classic protection).
# Read the current contexts first so you append rather than replace:
gh api repos/mnemom/<REPO>/branches/main/protection/required_status_checks/contexts

gh api -X POST repos/mnemom/<REPO>/branches/main/protection/required_status_checks/contexts \
  -f 'contexts[]=additive-verify'
```

Use this when the desired behavior is "bot PRs auto-land **iff** additive; a
behavior PR is held for a human." This matches today's posture (no GitHub-enforced
human review) while making the additive/behavior split enforceable.

### Option B — require human review, waived only when additive-verify is green

Use a **repo ruleset** (not classic protection) so you can attach a *conditional*
bypass. The review rule requires 1 approval; the `mnemom-adw` App is a bypass
actor for the **pull-request review rule only**, and the **`additive-verify`
required status check stays in force for everyone, App included.** Result: the bot
skips the human approval, but a red `additive-verify` still blocks it.

```sh
cat > ruleset.json <<'JSON'
{
  "name": "Review required (additive-verify waiver for adw-bot)",
  "target": "branch",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    { "type": "pull_request",
      "parameters": {
        "required_approving_review_count": 1,
        "dismiss_stale_reviews_on_push": true,
        "require_code_owner_review": false,
        "require_last_push_approval": false,
        "required_review_thread_resolution": false
      } },
    { "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": false,
        "do_not_enforce_on_create": false,
        "required_status_checks": [
          { "context": "additive-verify" }
        ]
      } }
  ],
  "bypass_actors": [
    { "actor_id": 3942970, "actor_type": "Integration", "bypass_mode": "always" }
  ]
}
JSON

gh api -X POST repos/mnemom/<REPO>/rulesets --input ruleset.json
```

> **Critical:** the App bypass attaches to the **`pull_request` (review) rule**.
> The `required_status_checks` rule has **no** bypass actor, so `additive-verify`
> is unbypassable — the conditionality lives entirely in the check. This is the
> safe shape; an App bypass on the *status-checks* rule (or a ruleset-wide bypass)
> would re-create the blanket bypass and is forbidden.
>
> Caveat to verify in staging: GitHub applies the App bypass to **all** of the
> bot's PRs on that branch, additive or not — so under Option B the *human-review*
> requirement is what the bot skips wholesale, and **`additive-verify` is the only
> thing standing between a behavior PR and the merge.** That is why
> `additive-verify` must be required and fail-closed. Confirm on a scratch repo
> that a red `additive-verify` blocks an App-authored PR before rolling out.

### Recommended rollout

1. `mnemom-risk` first (it owns the evidence PRs `#155`/`#161`) under **Option A**.
2. Replay `#155`, `#161`, and a fresh additive PR; confirm the first two stay
   red on `additive-verify` and the additive one goes green.
3. Then `mnemom-platform`; replay `#680` (green) and `#749` (red).
4. Expand to the rest. Keep `coherence`/`docs` last (thin or no existing checks).

## 4. Rollback

**Option A** — remove the required context (the check still runs, just stops
gating):

```sh
gh api -X DELETE repos/mnemom/<REPO>/branches/main/protection/required_status_checks/contexts \
  -f 'contexts[]=additive-verify'
```

**Option B** — delete the ruleset (find its id, then delete):

```sh
gh api repos/mnemom/<REPO>/rulesets --jq '.[] | select(.name|startswith("Review required (additive-verify")) | .id'
gh api -X DELETE repos/mnemom/<REPO>/rulesets/<RULESET_ID>
```

To **fully revoke the bot's waiver immediately** (kill switch), set the ruleset
`enforcement` to `disabled` or remove the `bypass_actors` entry — the bot then
falls back to needing a human approval like anyone else:

```sh
gh api -X PUT repos/mnemom/<REPO>/rulesets/<RULESET_ID> --input ruleset.json   # with bypass_actors: []
```

Removing the caller workflow from `<REPO>` stops the check entirely (another
human PR, since `.github/workflows/**` is NEVER-AUTO).
