#!/usr/bin/env bash
# ==============================================================================
# Phase 6 acceptance tests — FastAPI dashboard backend + React frontend.
#
# Exit criteria:
#   1. Engine pytest suite green (now includes test_api.py)
#   2. Compose config valid under --profile dashboard
#   3. API + dashboard images build
#   4. Stack + --profile dashboard comes up healthy
#   5. API endpoints respond with expected shapes (health, runs, bypass-rates,
#      per-variant, record detail, compare)
#   6. Dashboard nginx serves index.html referencing the Vite bundle, and /api
#      proxy reaches the FastAPI container (end-to-end through nginx)
# ==============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."
. "$(dirname "$0")/_lib.sh"
waflab_nix_reexec "$0" "$@"

pass()  { printf '  \e[32m✓\e[0m %s\n' "$*"; }
fail()  { printf '  \e[31m✗\e[0m %s\n' "$*"; exit 1; }
step()  { printf '\n\e[1;34m[phase6]\e[0m %s\n' "$*"; }

PY=engine/.venv/bin/python

step "1/6  Engine venv + unit tests green (incl. API)"
if [[ ! -x "$PY" ]]; then
  python3 -m venv engine/.venv
  engine/.venv/bin/pip install -q --disable-pip-version-check -e 'engine/[dev]'
fi
"$PY" -m pytest engine/tests -q || fail "pytest"
pass "pytest green"

step "2/6  Compose config valid under --profile dashboard"
docker compose --profile dashboard config --quiet || fail "compose (dashboard) invalid"
pass "compose --profile dashboard OK"

step "3/6  Build api (engine image) + dashboard images"
docker compose --profile dashboard build api dashboard >/dev/null || fail "dashboard build"
pass "api + dashboard images built"

step "4/6  Bring core stack + dashboard profile up healthy"
docker compose --profile dashboard up -d --wait --wait-timeout 600 --remove-orphans >/dev/null \
  || fail "compose up --wait"
pass "stack + dashboard healthy"

API_PORT="${API_PORT:-8001}"
DASHBOARD_PORT="${DASHBOARD_PORT:-3000}"

step "5/6  API endpoint shapes"
# /health → 200, status=ok
code=$(curl -sS -o /tmp/api-health.json -w '%{http_code}' "http://127.0.0.1:$API_PORT/health")
[[ "$code" == "200" ]] || { cat /tmp/api-health.json; fail "/health HTTP $code"; }
"$PY" -c "import json; assert json.load(open('/tmp/api-health.json'))['status']=='ok'" \
  || fail "/health payload unexpected"
pass "/health returns {status:ok}"

# /runs → array
code=$(curl -sS -o /tmp/api-runs.json -w '%{http_code}' "http://127.0.0.1:$API_PORT/runs")
[[ "$code" == "200" ]] || fail "/runs HTTP $code"
n=$("$PY" -c "import json; print(len(json.load(open('/tmp/api-runs.json'))))")
pass "/runs returns $n run(s)"

if [[ "$n" -eq 0 ]]; then
  printf '  \e[33m!\e[0m no pre-existing runs under results/raw — seeding a tiny one\n'
  RUN_ID="phase6-$(date -u +%Y%m%dT%H%M%SZ)"
  docker compose --profile engine run --rm \
    --name waflab-engine-phase6 \
    engine run \
    --classes sqli --mutators lexical --targets dvwa \
    --run-id "$RUN_ID" >/tmp/engine-phase6.log 2>&1 \
    || { tail -30 /tmp/engine-phase6.log; fail "engine seed run"; }
  pass "seed run $RUN_ID written"
else
  RUN_ID=$("$PY" -c "import json; print(json.load(open('/tmp/api-runs.json'))[0]['run_id'])")
  pass "reusing latest run $RUN_ID"
fi

# /runs/{id} → manifest
curl -sSf "http://127.0.0.1:$API_PORT/runs/$RUN_ID" >/tmp/api-manifest.json
"$PY" -c "import json; d=json.load(open('/tmp/api-manifest.json')); assert d.get('run_id')"
pass "/runs/$RUN_ID manifest OK"

# /runs/{id}/live → processed count
curl -sSf "http://127.0.0.1:$API_PORT/runs/$RUN_ID/live" >/tmp/api-live.json
"$PY" -c "
import json,sys
d=json.load(open('/tmp/api-live.json'))
assert d['processed'] >= 1, d
assert 'histogram' in d and 'recent' in d
"
pass "/runs/$RUN_ID/live has histogram + recent"

# /runs/{id}/bypass-rates → list with waf+mutator+lens keys
curl -sSf "http://127.0.0.1:$API_PORT/runs/$RUN_ID/bypass-rates" >/tmp/api-bypass.json
"$PY" -c "
import json,sys
rows=json.load(open('/tmp/api-bypass.json'))
assert isinstance(rows,list), rows
if rows:
    for r in rows: assert {'waf','mutator','lens','rate','ci_lo','ci_hi'}.issubset(r)
"
pass "/runs/$RUN_ID/bypass-rates shape OK"

# /runs/{id}/per-variant paginated + filtered
curl -sSf "http://127.0.0.1:$API_PORT/runs/$RUN_ID/per-variant?limit=5" >/tmp/api-pv.json
"$PY" -c "
import json,sys
d=json.load(open('/tmp/api-pv.json'))
assert 'total' in d and 'rows' in d
assert len(d['rows']) <= 5
"
pass "/runs/$RUN_ID/per-variant paginates"

# pick one record and hit the detail endpoint
PICK=$("$PY" -c "
import json
rows=json.load(open('/tmp/api-pv.json'))['rows']
r=rows[0]
print(r['waf'], r['target'], r['payload_id'], r['variant'])
")
read -r W T P V <<<"$PICK"
curl -sSf "http://127.0.0.1:$API_PORT/runs/$RUN_ID/records/$W/$T/$P/$V" >/tmp/api-rec.json
"$PY" -c "
import json; d=json.load(open('/tmp/api-rec.json'))
assert 'mutated_body' in d and 'verdict' in d
"
pass "/runs/$RUN_ID/records/$W/$T/$P/$V detail OK"

# /runs/compare (same run vs itself → delta is 0 everywhere)
curl -sSf "http://127.0.0.1:$API_PORT/runs/compare?a=$RUN_ID&b=$RUN_ID" >/tmp/api-cmp.json
"$PY" -c "
import json; d=json.load(open('/tmp/api-cmp.json'))
assert d['a']==d['b']
for row in d['rows']:
    if row['delta'] is not None: assert row['delta']==0.0, row
"
pass "/runs/compare reflexive OK"

# /runs/combined (single-run "merge" → provenance has one entry per WAF)
curl -sSf "http://127.0.0.1:$API_PORT/runs/combined?ids=$RUN_ID" >/tmp/api-combined.json
"$PY" -c "
import json; d=json.load(open('/tmp/api-combined.json'))
assert d['run_ids']==['$RUN_ID']
assert isinstance(d['waf_provenance'], dict)
assert isinstance(d['wafs'], list)
# every returned WAF must be traceable back to our one run_id
for w, rid in d['waf_provenance'].items():
    assert rid=='$RUN_ID', (w, rid)
"
pass "/runs/combined single-run OK"

# /runs/combined 400 on empty ids
code=$(curl -sS -o /tmp/api-combined-err -w '%{http_code}' "http://127.0.0.1:$API_PORT/runs/combined?ids=")
[[ "$code" == "400" ]] || fail "/runs/combined empty ids → HTTP $code (expected 400)"
pass "/runs/combined empty ids rejected"

step "6/6  Dashboard nginx serves HTML + proxies /api/"
code=$(curl -sS -o /tmp/dash-index.html -w '%{http_code}' "http://127.0.0.1:$DASHBOARD_PORT/")
[[ "$code" == "200" ]] || fail "dashboard /: HTTP $code"
grep -q 'WAF Evasion Lab' /tmp/dash-index.html || fail "index.html missing 'WAF Evasion Lab'"
grep -qE 'assets/index-[A-Za-z0-9_-]+\.js' /tmp/dash-index.html || fail "no Vite bundle reference"
pass "dashboard index.html served"

code=$(curl -sS -o /tmp/dash-healthz -w '%{http_code}' "http://127.0.0.1:$DASHBOARD_PORT/healthz")
[[ "$code" == "200" ]] || fail "dashboard /healthz HTTP $code"
pass "dashboard /healthz OK"

code=$(curl -sS -o /tmp/dash-api-health.json -w '%{http_code}' "http://127.0.0.1:$DASHBOARD_PORT/api/health")
[[ "$code" == "200" ]] || { cat /tmp/dash-api-health.json; fail "proxy /api/health HTTP $code"; }
"$PY" -c "import json; assert json.load(open('/tmp/dash-api-health.json'))['status']=='ok'" \
  || fail "proxy payload unexpected"
pass "dashboard → /api/health proxy works"

printf '\n\e[1;32mPhase 6 PASSED\e[0m — FastAPI backend + React dashboard end-to-end\n'
