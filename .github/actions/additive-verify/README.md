# additive-verify

A **structural additive discriminator** for ADW-bot PRs. It lets a genuinely
**additive** bot PR auto-land without a human review, while any PR that changes
product/behavior keeps its review. The signal is **structural** (no
behavior/control-flow change), not path-based — a legit instrumentation PR
touches `src/` exactly like a behavior PR does.

> **This check computes and reports a status only.** It does **not** merge, and
> it does **not** modify any branch-protection rule or ruleset. Granting the
> ADW-bot a review waiver *conditioned on this status being green* is a
> deliberate human (org-admin) step — see
> [Branch-protection change spec](#branch-protection-change-spec-human-step).

---

## Why path-based gating is not enough

The two-dial autonomy policy already in the worker (`mnemom_adw.policy.evaluate`,
MNE-486, shadow) classifies blast-radius by **path** against a red-line catalog
(`*auth.ts`, `*/auth/*`, `*billing/*`, `*rls*`, …). But the real behavior changes
this check exists to stop **don't live in red-line filenames**:

| PR | Title (claims additive) | What it actually did | Red-line path? |
| --- | --- | --- | --- |
| `mnemom-risk#155` | "add a conformance test" | added `return jsonResponse({…_persistence_failed})` inside an existing handler — a live response-shape change | **no** (`server/src/handlers.ts`) |
| `mnemom-risk#161` | "add a unit test" | full auth + tenant-scoping reimplementation: changed 5 handler signatures, added fail-closed branches, rewrote the GET dispatch | **no** (`handlers.ts` / `index.ts`) |

A blanket "bot skips review" rule (or a path-only allowlist) would have
auto-landed #161's auth change to prod. The discriminator therefore asserts **no
behavior/control-flow change**, structurally.

## The discriminator (two tiers, per changed file)

A PR is **ADDITIVE** iff **every** changed file passes its tier. Otherwise
**NEEDS-REVIEW**. Fail-closed throughout.

### Tier A — non-source files
Must be on the additive-path **allowlist** *and* newly **added** (docs/markdown
may also be modified). A *modified* lockfile, `wrangler.toml`, `package.json`, or
config, or an *edited* existing test, is **not** additive (it can change a
dependency, a runtime binding, or weaken a guard) → review.

### Tier B — source files (`**/src/**`, excluding tests)
Parsed with the TypeScript compiler. Add-only at the statement level:
- no existing exported/top-level function removed or renamed;
- no existing function **signature** changed;
- no existing statement removed/modified inside an existing function;
- no control-flow / `return` / `throw` / response-emit **injected** into an
  existing function (new span/log/metric calls are fine; a new `return`/`if`/
  `for` is not).

The legitimate **extract-and-wrap** instrumentation refactor — an existing
function's body relocated *verbatim* into a new sibling, the original becoming a
telemetry `try/finally` wrapper that delegates to it — is recognized and allowed,
**provided the public signature is unchanged**.

## Calibration (locked by the self-test)

| PR | Expected | Result |
| --- | --- | --- |
| `mnemom-platform#680` per-log `observer.process_log` span | **ADDITIVE** (auto-land) | ✅ ADDITIVE |
| `mnemom-platform#749` Grafana dashboard + runbook + `src` rewrite | NEEDS-REVIEW | ✅ NEEDS-REVIEW |
| `mnemom-risk#155` "add a conformance test" (+ response change) | NEEDS-REVIEW | ✅ NEEDS-REVIEW |
| `mnemom-risk#161` "add a unit test" (+ auth reimpl) | NEEDS-REVIEW | ✅ NEEDS-REVIEW |

`#680` is the hard case: its `index.ts` change has **zero line deletions** (the
body moved verbatim under the wrapper). A naive "deletions == 0 ⇒ additive" rule
would also wrongly PASS `#155` (which *also* has zero deletions). Only the AST
analysis separates them. Run `npm test` (or `VERBOSE=1 npm test`) to see it.

## Honest failure modes

**False negatives (additive PR wrongly sent to review — safe, just slower):**
- A different additive *refactor* shape we don't yet recognize (e.g. wrap-without-
  `try`, or splitting one function into two pure helpers). The wrapper detector
  only matches the `try/finally`-delegate shape.
- A formatter/import-sorter reflow of an existing function reads as
  "statements modified." Keep auto-format out of additive PRs, or widen the
  fingerprint normalization.

**False positives (behavior PR wrongly waived — the dangerous direction; we bias
hard against these):**
- A NEW source file that *is itself* the behavior change and is wired in by a
  build/registry the analyzer doesn't see (no edit to an existing dispatcher).
  Mitigation: `new_source_needs_review: true` for repos with implicit wiring.
- A telemetry call with a real side-effect masquerading as observability (e.g. a
  "metric" that also mutates state). The telemetry allowlist is name-based.
- Non-TS behavior we don't parse (SQL migrations, YAML that drives runtime,
  Python). Those are handled by *staying off the Tier-A allowlist* → fail-closed
  to review, not by Tier-B. Do **not** add migration/Wrangler/Helm globs to the
  allowlist.
- A `.js`/`.mjs` source change to a file the tsconfig wouldn't actually type-check
  is still AST-parsed structurally; logic holds, but type-level contract changes
  (e.g. a widened return type with no statement change) are not caught.

Because every uncertainty path resolves to **NEEDS-REVIEW**, the worst realistic
outcome is "a safe PR waits for a human," not "a behavior change auto-lands."

## Configuration

Copy [`config.example.yml`](./config.example.yml) to
`.github/additive-verify.yml` in a target repo to override globs. Omitted keys
use the baked-in defaults.

## Local use

```sh
cd .github/actions/additive-verify
npm ci
npm test            # calibration self-test
VERBOSE=1 npm test  # show the per-file violation signals
```
