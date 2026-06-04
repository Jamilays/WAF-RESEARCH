#!/usr/bin/env bash
# ==============================================================================
# Phase 1 acceptance tests — WAF liveness & /healthz.
#
# Updated for the Phase 2 architecture: WAFs are now per-target sidecars
# (modsec-dvwa, coraza-dvwa, shadowd-dvwa, …) behind Traefik rather than a
# single host-published container. We verify one representative sidecar per
# WAF type by exec'ing into it and hitting its internal /healthz — no host
# port mapping needed.
#
# Exit criteria:
#   1. `docker compose config` validates under default, paranoia-high, and ml
#      profiles
#   2. Core stack reaches "healthy" via `docker compose up --wait`
#   3. One representative sidecar of each WAF type responds 200 on /healthz
#      (tested in-container to avoid depending on host port mappings)
#   4. All core WAF sidecars + supporting services report healthy
# ==============================================================================
set -euo pipefail

cd "$(dirname "$0")/.."

pass()  { printf '  \033[32m✓\033[0m %s\n' "$*"; }
fail()  { printf '  \033[31m✗\033[0m %s\n' "$*"; exit 1; }
step()  { printf '\n\033[1;34m[phase1]\033[0m %s\n' "$*"; }

step "1/4  Validate compose for all profiles"
docker compose config --quiet                             || fail "default profile invalid"; pass "default profile OK"
docker compose --profile paranoia-high config --quiet     || fail "paranoia-high invalid";   pass "paranoia-high OK"
docker compose --profile ml config --quiet                || fail "ml invalid";              pass "ml OK"

step "2/4  Start core stack and wait for health"
docker compose up -d --build --wait --wait-timeout 600    || fail "compose up --wait failed"
pass "compose up --wait returned OK"

# Representative sidecar per WAF type → container-internal port for /healthz.
# These match the healthchecks defined on the x-*-common anchors in compose.
declare -A PROBE=(
  [modsec-dvwa]=8080
  [coraza-dvwa]=80
  [shadowd-dvwa]=80
)

step "3/4  Verify each WAF type returns 200 on /healthz (in-container probe)"
for svc in "${!PROBE[@]}"; do
  port="${PROBE[$svc]}"
  code=$(docker compose exec -T "$svc" \
           wget -q -U waflab-phase1-test -O /dev/null \
                --server-response "http://127.0.0.1:${port}/healthz" 2>&1 \
         | awk '/HTTP\// {c=$2} END{print c}')
  [[ "$code" == "200" ]] || fail "$svc /healthz → ${code:-no-response} (expected 200)"
  pass "$svc /healthz → 200 (port ${port})"
done

step "4/4  Verify container health state reports 'healthy'"
CORE_SERVICES=(
  traefik
  dvwa-db dvwa webgoat juiceshop
  shadowd-db shadowd
  modsec-dvwa modsec-webgoat modsec-juiceshop
  coraza-dvwa coraza-webgoat coraza-juiceshop
  shadowd-dvwa shadowd-webgoat shadowd-juiceshop
)
for svc in "${CORE_SERVICES[@]}"; do
  cid=$(docker compose ps -q "$svc")
  [[ -n "$cid" ]] || fail "$svc has no container"
  state=$(docker inspect -f '{{.State.Status}}' "$cid")
  health=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$cid")
  if [[ "$state" != "running" ]]; then
    fail "$svc state=$state"
  fi
  if [[ "$health" != "healthy" && "$health" != "none" ]]; then
    fail "$svc health=$health"
  fi
  pass "$svc running (health=$health)"
done

printf '\n\033[1;32mPhase 1 PASSED\033[0m — 3 WAF types healthy across 9 sidecars, ML stub available under --profile ml\n'
