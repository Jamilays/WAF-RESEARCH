#!/usr/bin/env bash
# ==============================================================================
# Paranoia-level ladder automation for ModSecurity + Coraza — TODO.md #1.
#
# Sweeps CRS v4.25 paranoia level through 1 → 2 → 3 → 4 on both CRS-based
# WAFs (modsec + coraza) using the existing ``paranoia-high`` compose
# profile's services. Instead of spinning up PL2/PL3-dedicated services
# (which would mean 12 new compose entries + 12 new Traefik routes) this
# script parameterises the env vars the ``x-modsec-env-ph`` and
# ``x-coraza-ph-directives`` anchors already honour:
#
#   MODSEC_PARANOIA_PH   — the ModSec image's ``PARANOIA`` env (default 4)
#   CORAZA_PARANOIA_PH   — embeds into Coraza's SecAction (both the
#                          blocking_paranoia_level and detection_paranoia_level
#                          setvars) so blocking and detection agree
#
# Each level recreates the six PH services with the new env var values,
# waits for healthchecks, runs the engine corpus, then moves on. Every run
# gets a distinct run_id so ``wafeval ladder`` can aggregate them into a
# single line chart that tells a reader the bypass/FP trade-off at each PL.
#
# Running this needs the default stack (targets + baseline) *and* the
# paranoia-high profile up:
#     make up
#     make up-paranoia
# then:
#     make ladder-paranoia
# Total wall-clock: ~4 × engine-run-time. With the full 201-payload
# corpus × 5 mutators × 3 targets on one CRS pair, budget ~60 min.
# ==============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."
. "$(dirname "$0")/_lib.sh"
waflab_nix_reexec "$0" "$@"

pass()  { printf '  \e[32m✓\e[0m %s\n' "$*"; }
info()  { printf '  \e[34mi\e[0m %s\n' "$*"; }
fail()  { printf '  \e[31m✗\e[0m %s\n' "$*"; exit 1; }
step()  { printf '\n\e[1;34m[paranoia-ladder]\e[0m %s\n' "$*"; }

LEVELS="${LEVELS:-1,2,3,4}"
# shellcheck disable=SC2206 # intentional word splitting on comma
IFS=, read -ra LEVEL_LIST <<< "$LEVELS"
CLASSES="${CLASSES:-sqli,xss,cmdi,lfi,ssti,xxe,nosql,ldap,ssrf,jndi,graphql,crlf}"
MUTATORS="${MUTATORS:-lexical,encoding,structural,context_displacement,multi_request}"
WAFS="${WAFS:-baseline,modsec-ph,coraza-ph}"
MAX_CONCURRENCY="${MAX_CONCURRENCY:-4}"
TARGET="${TARGET:-dvwa}"
RECREATE_WAIT="${RECREATE_WAIT:-120}"  # compose --wait-timeout per recreate

PH_SERVICES=(
  modsec-ph-dvwa modsec-ph-webgoat modsec-ph-juiceshop
  coraza-ph-dvwa coraza-ph-webgoat coraza-ph-juiceshop
)

step "0/4  Prerequisites"
for svc in waflab-traefik waflab-dvwa waflab-juiceshop waflab-webgoat; do
  docker ps --filter "name=^/${svc}$" --filter "status=running" --format '{{.Names}}' \
    | grep -q "$svc" || fail "$svc not running — run 'make up' first"
done
pass "core stack running"

# Make sure the paranoia-high profile has already been brought up once so
# images are built. A fresh-recreate with --no-deps won't trigger the build.
docker compose --profile paranoia-high up -d --build --wait --wait-timeout "$RECREATE_WAIT" \
  "${PH_SERVICES[@]}" >/tmp/paranoia-bootstrap.log 2>&1 \
  || { tail -20 /tmp/paranoia-bootstrap.log; fail "paranoia-high bootstrap"; }
pass "paranoia-high services built"

STEPS_ARG=""
declare -A RUN_IDS

step "1/4  Sweep paranoia-level ∈ {${LEVEL_LIST[*]}}"
for level in "${LEVEL_LIST[@]}"; do
  info "→ setting MODSEC_PARANOIA_PH=$level  CORAZA_PARANOIA_PH=$level"
  export MODSEC_PARANOIA_PH="$level"
  export CORAZA_PARANOIA_PH="$level"

  # --force-recreate applies the new env; --no-deps skips the targets, which
  # stay at the same version across the sweep (CRS ruleset is the variable).
  info "recreating PH services (waiting up to ${RECREATE_WAIT}s for healthy)"
  docker compose --profile paranoia-high up -d \
    --force-recreate --no-deps \
    --wait --wait-timeout "$RECREATE_WAIT" \
    "${PH_SERVICES[@]}" >/tmp/paranoia-recreate-pl$level.log 2>&1 \
    || { tail -20 /tmp/paranoia-recreate-pl$level.log; fail "recreate at PL$level"; }

  RUN_ID="paranoia-pl${level}-$(date -u +%Y%m%dT%H%M%SZ)"
  info "running engine → run_id=$RUN_ID"
  docker compose --profile engine --profile paranoia-high run --rm \
    -e MAX_CONCURRENCY="$MAX_CONCURRENCY" \
    engine run \
    --wafs "$WAFS" \
    --classes "$CLASSES" \
    --mutators "$MUTATORS" \
    --run-id "$RUN_ID" >/tmp/engine-paranoia-pl$level.log 2>&1 \
    || { tail -40 /tmp/engine-paranoia-pl$level.log; fail "engine run at PL$level"; }

  RUN_IDS[$level]="$RUN_ID"
  STEPS_ARG+="pl${level}:${RUN_ID},"
  pass "PL$level → $RUN_ID"
done
STEPS_ARG="${STEPS_ARG%,}"

step "2/4  Per-run reports"
for level in "${LEVEL_LIST[@]}"; do
  engine/.venv/bin/python -m wafeval report --run-id "${RUN_IDS[$level]}" \
    >/tmp/report-paranoia-pl$level.log 2>&1 \
    || { tail -30 /tmp/report-paranoia-pl$level.log; fail "report PL$level"; }
  pass "report PL$level"
done

step "3/4  Ladder aggregate report + figure"
OUT_ID="${OUT_ID:-paranoia-ladder-$(date -u +%Y%m%dT%H%M%SZ)}"
engine/.venv/bin/python -m wafeval ladder \
  --steps "$STEPS_ARG" \
  --target "$TARGET" \
  --lens waf_view \
  --out-id "$OUT_ID" \
  --title "CRS paranoia-level ladder ($TARGET · waf_view)" \
  || fail "ladder aggregator"
pass "ladder artefacts → results/reports/$OUT_ID/"

step "4/4  Summary"
info "run_ids:"
for level in "${LEVEL_LIST[@]}"; do
  info "  PL$level → ${RUN_IDS[$level]}"
done
info "ladder artefact: results/reports/$OUT_ID/report-ladder.md"

# Leave MODSEC_PARANOIA_PH / CORAZA_PARANOIA_PH pointing at the last level
# for the active shell; re-up with `make up-paranoia` to reset to PL4.
printf '\n\e[1;32mParanoia ladder DONE (PH services currently at PL%s; re-run make up-paranoia to reset to PL4)\e[0m\n' \
  "${LEVEL_LIST[-1]}"
