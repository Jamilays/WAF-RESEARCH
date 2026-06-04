#!/usr/bin/env bash
# ==============================================================================
# Multi-generation adaptive mutator evolution.
#
# Each generation runs the adaptive + adaptive3 mutators seeded on the
# previous generation's observed per-mutator bypass rates, producing a
# chain of run_ids where each one encodes the "what bypassed last time"
# prior. Published as the `make run-adaptive ITER=N` wrapper.
#
# Env vars (all mandatory — set by the Makefile target):
#   SEED_RUN                  — seed for generation 1
#   ITER                      — number of generations (>= 2)
#   ADAPTIVE_CORPUS           — e.g. paper_subset
#   ADAPTIVE_CLASSES          — e.g. sqli,xss
#   ADAPTIVE_TARGETS          — e.g. dvwa,juiceshop
#   ADAPTIVE_WAFS             — e.g. baseline,modsec,coraza,shadowd
#   ADAPTIVE_MUTATORS         — e.g. adaptive,adaptive3
#   ADAPTIVE_MAX_CONCURRENCY  — e.g. 4
#
# Exits after the last generation; emits run_ids for a follow-up
# `wafeval report` or `wafeval ladder` call.
# ==============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."

info()  { printf '  \e[34mi\e[0m %s\n' "$*"; }
pass()  { printf '  \e[32m✓\e[0m %s\n' "$*"; }
fail()  { printf '  \e[31m✗\e[0m %s\n' "$*"; exit 1; }
step()  { printf '\n\e[1;34m[adaptive-evo]\e[0m %s\n' "$*"; }

for v in SEED_RUN ITER ADAPTIVE_CORPUS ADAPTIVE_CLASSES ADAPTIVE_TARGETS ADAPTIVE_WAFS ADAPTIVE_MUTATORS; do
  [[ -n "${!v:-}" ]] || fail "env var $v is required"
done
[[ "$ITER" =~ ^[0-9]+$ ]] || fail "ITER must be a positive integer, got '$ITER'"
(( ITER >= 2 )) || fail "ITER=$ITER — use 'make run-adaptive' (no ITER) for one generation"

RUN_IDS=()
seed="$SEED_RUN"

for gen in $(seq 1 "$ITER"); do
  step "generation $gen of $ITER — seed=$seed"
  run_id="adaptive-gen${gen}-$(date -u +%Y%m%dT%H%M%SZ)"
  docker compose --profile engine run --rm \
    -e ADAPTIVE_SEED_RUN="$seed" \
    -e MAX_CONCURRENCY="${ADAPTIVE_MAX_CONCURRENCY:-4}" \
    engine run \
    --corpus "$ADAPTIVE_CORPUS" \
    --classes "$ADAPTIVE_CLASSES" \
    --targets "$ADAPTIVE_TARGETS" \
    --wafs "$ADAPTIVE_WAFS" \
    --mutators "$ADAPTIVE_MUTATORS" \
    --run-id "$run_id" >/tmp/adaptive-evo-${gen}.log 2>&1 \
    || { tail -40 /tmp/adaptive-evo-${gen}.log; fail "engine run gen=$gen"; }
  pass "gen $gen → $run_id"
  RUN_IDS+=("$run_id")
  seed="$run_id"
done

step "summary"
info "generations:"
for i in "${!RUN_IDS[@]}"; do
  info "  gen $((i + 1)) → ${RUN_IDS[$i]}"
done
info "final run_id: ${RUN_IDS[-1]} — feed into \`wafeval report --run-id\` for the markdown/LaTeX table"
info "ladder across generations:"
steps=""
for i in "${!RUN_IDS[@]}"; do
  steps+="gen$((i + 1)):${RUN_IDS[$i]},"
done
steps="${steps%,}"
info "  wafeval ladder --steps $steps --target ${ADAPTIVE_TARGETS%%,*} --out-id adaptive-evo-$(date -u +%Y%m%dT%H%M%SZ)"

printf '\n\e[1;32madaptive evolution complete\e[0m — %d generations\n' "$ITER"
