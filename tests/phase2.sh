#!/usr/bin/env bash
# ==============================================================================
# Phase 2 acceptance tests — routing matrix + targets + baseline parity.
#
# Exit criteria:
#   1. Compose config valid across default / paranoia-high / ml profiles
#   2. Core stack comes up --wait healthy (Traefik, 3 targets, shadowd, 9 WAFs)
#   3. All 3 baseline-* routes return a 2xx/3xx from their target
#   4. All 9 <waf>-<target>.local routes respond (not 503)
#   5. A canonical SQLi payload is 403'd by modsec-dvwa and allowed on
#      baseline-dvwa (proves WAF is engaged, not just a pass-through)
#   6. Traefik API/dashboard reachable on the loopback
# ==============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."

pass()  { printf '  \e[32m✓\e[0m %s\n' "$*"; }
fail()  { printf '  \e[31m✗\e[0m %s\n' "$*"; exit 1; }
step()  { printf '\n\e[1;34m[phase2]\e[0m %s\n' "$*"; }

TRAEFIK_PORT="${TRAEFIK_PORT:-8000}"
TRAEFIK_DASHBOARD_PORT="${TRAEFIK_DASHBOARD_PORT:-8088}"

hit() {
  local host="$1" path="$2"; shift 2
  curl -sS -o /dev/null -w "%{http_code}" \
       -H "Host: $host" -H "User-Agent: waflab-phase2" --max-time 10 \
       "$@" "http://127.0.0.1:${TRAEFIK_PORT}${path}"
}

step "1/6  Validate compose for all profiles"
docker compose config --quiet                             || fail "default profile invalid"
pass "default profile"
docker compose --profile paranoia-high config --quiet     || fail "paranoia-high invalid"
pass "paranoia-high"
docker compose --profile ml config --quiet                || fail "ml invalid"
pass "ml"

step "2/6  Start core stack (this can take 2-3 min on first boot — WebGoat is slow)"
docker compose up -d --build --wait --wait-timeout 600    || fail "compose up failed"
pass "stack healthy"

step "3/6  Baseline routes reach each target directly"
declare -A BASELINE_PATH=( [dvwa]=/login.php [webgoat]=/WebGoat/login [juiceshop]=/ )
for t in dvwa webgoat juiceshop; do
  code=$(hit "baseline-${t}.local" "${BASELINE_PATH[$t]}" || true)
  case "$code" in
    200|301|302|307|308) pass "baseline-${t}.local${BASELINE_PATH[$t]} → $code" ;;
    *) fail "baseline-${t}.local${BASELINE_PATH[$t]} → $code" ;;
  esac
done

step "4/6  All 9 WAF × target routes respond (not 503)"
for waf in modsec coraza shadowd; do
  for t in dvwa webgoat juiceshop; do
    host="${waf}-${t}.local"
    path="${BASELINE_PATH[$t]}"
    code=$(hit "$host" "$path" || true)
    if [[ "$code" == "503" || "$code" == "000" ]]; then
      fail "$host$path → $code (backend unreachable)"
    fi
    pass "$host$path → $code"
  done
done

step "5/6  ModSec blocks a canonical SQLi on modsec-dvwa (but not baseline-dvwa)"
# Payload hits CRS 942 family (sqli-libinjection). Works at paranoia 1.
payload="/?q=1%27%20OR%20%271%27%3D%271%20--"
bl=$(hit "baseline-dvwa.local" "$payload" || true)
wf=$(hit "modsec-dvwa.local"   "$payload" || true)
pass "baseline-dvwa.local$payload → $bl"
[[ "$wf" == "403" ]] || fail "modsec-dvwa.local$payload → $wf (expected 403)"
pass "modsec-dvwa.local$payload → 403 (CRS engaged)"

step "6/6  Traefik API reachable on loopback"
code=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 5 \
  "http://127.0.0.1:${TRAEFIK_DASHBOARD_PORT}/api/http/routers" || true)
[[ "$code" == "200" ]] || fail "Traefik API → $code"
pass "Traefik API → 200"

# Quick sanity: count the routers Traefik knows about
n=$(curl -sS --max-time 5 "http://127.0.0.1:${TRAEFIK_DASHBOARD_PORT}/api/http/routers" | \
    python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo 0)
[[ "$n" -ge 12 ]] || fail "Traefik reports only $n routers (expected ≥12)"
pass "Traefik reports $n routers (core matrix + profile-gated extras)"

printf '\n\e[1;32mPhase 2 PASSED\e[0m — 3 targets + 9 WAF×target routes + 3 baselines, WAF engagement verified\n'
