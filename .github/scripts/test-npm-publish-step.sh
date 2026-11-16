#!/usr/bin/env bash
# Runs the `Publish` step of .github/workflows/npm-publish.yml against a stub `npm`.
#
# The step's shell is extracted from the workflow with yq and run under the shell GitHub
# uses for `run:` on ubuntu (bash --noprofile --norc -eo pipefail), with the env the
# step's `env:` block maps. The stub records every npm argv and plays one registry
# outcome per case. `sleep` is stubbed so the poll loop runs without waiting.
#
# Usage: .github/scripts/test-npm-publish-step.sh [path/to/npm-publish.yml]
set -euo pipefail

WORKFLOW="${1:-.github/workflows/npm-publish.yml}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

failures=0
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }
pass() { echo "ok:   $*"; }

step_field() {
  yq -r ".jobs.publish.steps[] | select(.name == \"Publish\") | $1" "$WORKFLOW"
}

step_field '.run' > "$WORK/step.sh"
if [ ! -s "$WORK/step.sh" ] || [ "$(cat "$WORK/step.sh")" = "null" ]; then
  echo "FAIL: no step named Publish under jobs.publish in $WORKFLOW"
  exit 1
fi

# The step reads its inputs only through `env:`; pin the mapping so a case below that sets
# TAG/PROVENANCE/PKG_* exercises the same values the workflow passes.
check_env() {
  local key="$1" want="$2" got
  got="$(step_field ".env.$key")"
  if [ "$got" = "$want" ]; then pass "env $key = $want"; else fail "env $key is '$got', want '$want'"; fi
}
# shellcheck disable=SC2016 # the ${{ }} are literal workflow text, compared, not expanded
{
  check_env PKG_NAME '${{ steps.check.outputs.pkg-name }}'
  check_env PKG_VERSION '${{ steps.check.outputs.pkg-version }}'
  check_env TAG '${{ inputs.tag }}'
  check_env PROVENANCE '${{ inputs.provenance }}'
}
WAIT_DEFAULT="$(step_field '.env.PUBLISHED_WAIT_SECONDS')"

mkdir -p "$WORK/bin"
cat > "$WORK/bin/npm" <<'STUB'
#!/usr/bin/env bash
# STUB_PUBLISH: ok | e409-staged | e403-published | e409-conflict | e401
# STUB_SERVED_ON: Nth `npm view <pkg> version` call that returns the version; 0 = never
echo "$*" >> "$STUB_DIR/argv"
case "$1" in
  publish)
    case "$STUB_PUBLISH" in
      ok) echo "+ ${PKG_NAME}@${PKG_VERSION}"; exit 0 ;;
      e409-staged)
        echo "npm error code E409" >&2
        echo "npm error 409 Conflict - PUT https://registry.npmjs.org/${PKG_NAME} - Cannot publish over previously staged version \"${PKG_VERSION}\"" >&2
        exit 1 ;;
      e403-published)
        echo "npm error code E403" >&2
        echo "npm error 403 403 Forbidden - PUT https://registry.npmjs.org/${PKG_NAME} - You cannot publish over the previously published versions: ${PKG_VERSION}." >&2
        exit 1 ;;
      e409-conflict)
        echo "npm error code E409" >&2
        echo "npm error 409 Conflict - PUT https://registry.npmjs.org/${PKG_NAME} - Document update conflict" >&2
        exit 1 ;;
      e401)
        echo "npm error code E401" >&2
        echo "npm error 401 Unauthorized - PUT https://registry.npmjs.org/${PKG_NAME}" >&2
        exit 1 ;;
    esac ;;
  view)
    case "$3" in
      version)
        n=$(( $(cat "$STUB_DIR/views" 2>/dev/null || echo 0) + 1 ))
        echo "$n" > "$STUB_DIR/views"
        if [ "$STUB_SERVED_ON" -gt 0 ] && [ "$n" -ge "$STUB_SERVED_ON" ]; then
          echo "$PKG_VERSION"; exit 0
        fi
        echo "npm error code E404" >&2; exit 1 ;;
      gitHead) echo "1111111111111111111111111111111111111111"; exit 0 ;;
    esac ;;
esac
echo "stub npm: unexpected call: $*" >&2
exit 2
STUB
printf '#!/usr/bin/env bash\nexit 0\n' > "$WORK/bin/sleep"
chmod +x "$WORK/bin/npm" "$WORK/bin/sleep"

# run_case NAME PUBLISH SERVED_ON PROVENANCE WAIT_SECONDS
run_case() {
  local dir="$WORK/case-$1"
  mkdir -p "$dir/tmp"
  set +e
  env -i PATH="$WORK/bin:$PATH" HOME="$dir" \
    STUB_DIR="$dir" STUB_PUBLISH="$2" STUB_SERVED_ON="$3" \
    PKG_NAME="@mnemom/example" PKG_VERSION="1.2.3-next.4" TAG="next" PROVENANCE="$4" \
    PUBLISHED_WAIT_SECONDS="$5" RUNNER_TEMP="$dir/tmp" \
    GITHUB_SHA="2222222222222222222222222222222222222222" \
    bash --noprofile --norc -eo pipefail "$WORK/step.sh" > "$dir/out" 2>&1
  echo $? > "$dir/rc"
  set -e
}
rc() { cat "$WORK/case-$1/rc"; }
out_has() { grep -Fq -- "$2" "$WORK/case-$1/out"; }
publish_argv() { grep "^publish" "$WORK/case-$1/argv" 2>/dev/null || true; }
views() { cat "$WORK/case-$1/views" 2>/dev/null || echo 0; }
expect() {
  local name="$1" desc="$2"; shift 2
  if "$@"; then pass "$name: $desc"; else fail "$name: $desc"; sed 's/^/      | /' "$WORK/case-$name/out"; fi
}

# Normal path: one publish with the documented flags, provenance only when asked.
run_case publish-provenance ok 0 true "$WAIT_DEFAULT"
expect publish-provenance "exits 0" test "$(rc publish-provenance)" = 0
expect publish-provenance "argv is publish --access public --tag next --provenance" \
  test "$(publish_argv publish-provenance)" = "publish --access public --tag next --provenance"

run_case publish-no-provenance ok 0 false "$WAIT_DEFAULT"
expect publish-no-provenance "exits 0" test "$(rc publish-no-provenance)" = 0
expect publish-no-provenance "argv is publish --access public --tag next" \
  test "$(publish_argv publish-no-provenance)" = "publish --access public --tag next"

# A concurrent publish of the same version: a no-op only once npm serves that version.
run_case e409-staged-served e409-staged 3 true "$WAIT_DEFAULT"
expect e409-staged-served "exits 0" test "$(rc e409-staged-served)" = 0
expect e409-staged-served "polls npm view until the 3rd call serves the version" test "$(views e409-staged-served)" = 3
expect e409-staged-served "notice names both gitHeads" out_has e409-staged-served \
  "::notice::@mnemom/example@1.2.3-next.4 is on npm, published by another run from 1111111111111111111111111111111111111111 (this run: 2222222222222222222222222222222222222222)"

run_case e403-published-served e403-published 1 true "$WAIT_DEFAULT"
expect e403-published-served "exits 0" test "$(rc e403-published-served)" = 0
expect e403-published-served "prints the notice" out_has e403-published-served "::notice::"

# A real failure never passes as a no-op.
run_case e409-staged-never-served e409-staged 0 true 0
expect e409-staged-never-served "exits 1" test "$(rc e409-staged-never-served)" = 1
expect e409-staged-never-served "prints ::error::" out_has e409-staged-never-served "::error::"
expect e409-staged-never-served "prints no ::notice::" bash -c "! grep -Fq '::notice::' '$WORK/case-e409-staged-never-served/out'"

run_case e409-conflict e409-conflict 1 true "$WAIT_DEFAULT"
expect e409-conflict "exits 1" test "$(rc e409-conflict)" = 1
expect e409-conflict "does not poll npm view" test "$(views e409-conflict)" = 0

run_case e401 e401 1 true "$WAIT_DEFAULT"
expect e401 "exits 1" test "$(rc e401)" = 1
expect e401 "does not poll npm view" test "$(views e401)" = 0

if [ "$failures" -gt 0 ]; then
  echo "$failures check(s) failed"
  exit 1
fi
echo "all checks passed"
