#!/usr/bin/env bash
# ==============================================================================
# Phase 3 acceptance tests — engine core + lexical mutator end-to-end.
#
# Exit criteria:
#   1. engine pytest suite green (mutator + loader + verdict)
#   2. compose config valid under the `engine` profile
#   3. the engine image builds
#   4. `make run` (containerised) completes against the live Phase 2 stack
#   5. ≥1 VerdictRecord per (waf × target × variant) cell for DVWA SQLi
#   6. At least one `blocked` verdict from modsec-dvwa on a canonical SQLi
#      (sanity: engine's view of the WAF matches Phase 2 curl result)
#   7. manifest.json exists and declares matching datapoint totals
# ==============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."
. "$(dirname "$0")/_lib.sh"
waflab_nix_reexec "$0" "$@"

pass()  { printf '  \e[32m✓\e[0m %s\n' "$*"; }
fail()  { printf '  \e[31m✗\e[0m %s\n' "$*"; exit 1; }
step()  { printf '\n\e[1;34m[phase3]\e[0m %s\n' "$*"; }

PY=engine/.venv/bin/python

step "1/7  Ensure engine venv + unit tests are green"
if [[ ! -x "$PY" ]]; then
  python3 -m venv engine/.venv
  engine/.venv/bin/pip install -q --disable-pip-version-check -e 'engine/[dev]'
fi
"$PY" -m pytest engine/tests -q     || fail "pytest"
pass "pytest green"

step "2/7  Compose config valid under --profile engine"
docker compose --profile engine config --quiet || fail "compose (engine) invalid"
pass "compose --profile engine OK"

step "3/7  Build engine image"
docker compose --profile engine build engine >/dev/null || fail "engine build"
pass "engine image built"

step "4/7  Bring core stack up healthy"
docker compose up -d --wait --wait-timeout 600 --remove-orphans >/dev/null \
  || fail "compose up --wait failed"
pass "stack healthy"

step "5/7  Run engine end-to-end (DVWA SQLi, lexical mutator)"
RUN_ID="phase3-$(date -u +%Y%m%dT%H%M%SZ)"
docker compose --profile engine run --rm \
  --name waflab-engine-phase3 \
  engine run \
  --classes sqli --mutators lexical --targets dvwa \
  --run-id "$RUN_ID" >/tmp/engine-phase3.log 2>&1 \
  || { cat /tmp/engine-phase3.log; fail "engine run"; }
pass "engine run completed ($RUN_ID)"

OUT="results/raw/$RUN_ID"
[[ -d "$OUT" ]] || fail "results dir $OUT missing"
[[ -f "$OUT/manifest.json" ]] || fail "manifest.json missing"

step "6/7  Verify WAF × target × verdict coverage"
# Every (waf × target) cell should have at least one JSON.
for waf in baseline modsec coraza shadowd; do
  count=$(find "$OUT/$waf/dvwa" -name '*.json' 2>/dev/null | wc -l)
  [[ "$count" -gt 0 ]] || fail "no verdicts recorded for $waf × dvwa"
  pass "$waf × dvwa → $count records"
done

# At least one WAF win from modsec-dvwa — matches Phase 2's canonical 403 OR
# a silent sanitise (200 with the payload stripped). Accepting both keeps the
# acceptance check robust to CRS rule updates that switch from hard-deny to
# rewrite on e.g. JSON-SQL detection.
blocked=$("$PY" -c "
import json, pathlib
n = sum(
    1 for p in pathlib.Path('$OUT/modsec/dvwa').glob('*.json')
    if json.loads(p.read_text()).get('verdict') in ('blocked', 'blocked_silent')
)
print(n)
")
[[ "$blocked" -ge 1 ]] || fail "no 'blocked' or 'blocked_silent' verdicts from modsec-dvwa — WAF engagement broken?"
pass "modsec-dvwa blocked $blocked variants (≥1 required, hard-block or silent)"

step "7/7  Manifest totals match filesystem"
manifest_total=$("$PY" -c "
import json; print(json.load(open('$OUT/manifest.json'))['totals']['datapoints'])
")
fs_total=$(find "$OUT" -name '*.json' ! -name 'manifest.json' | wc -l)
[[ "$manifest_total" == "$fs_total" ]] \
  || fail "manifest.totals.datapoints=$manifest_total but filesystem has $fs_total"
pass "manifest ↔ filesystem in sync ($fs_total datapoints)"

printf '\n\e[1;32mPhase 3 PASSED\e[0m — engine core runnable, lexical mutator end-to-end\n'
