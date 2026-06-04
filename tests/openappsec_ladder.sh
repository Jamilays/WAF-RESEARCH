#!/usr/bin/env bash
# ==============================================================================
# open-appsec minimum-confidence ladder automation — TODO #2 in TODO.md.
#
# Sweeps the openappsec agent's `minimum-confidence` knob through
# critical → high → medium → low, reruns the engine corpus after each reload,
# and emits a combined ladder report + line chart via `wafeval ladder`.
#
# Invariants the script enforces:
#   - Only the `minimum-confidence:` line in local_policy.yaml is rewritten;
#     every other key stays byte-identical (sed with anchored regex).
#   - The agent is reloaded by signalling the openappsec container (the
#     smart-sync sidecar polls the policy and push it to cp-agent). We wait
#     45 s for the new policy to load before hitting the engine.
#   - Every run lands under a distinct run_id so the analyzer can plot them
#     on one axis without de-duplication surprises.
#
# Running this requires the ml profile up (`make up-ml`) and ~40 min of
# wall-clock on a modest workstation.
# ==============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."
. "$(dirname "$0")/_lib.sh"
waflab_nix_reexec "$0" "$@"

pass()  { printf '  \e[32m✓\e[0m %s\n' "$*"; }
info()  { printf '  \e[34mi\e[0m %s\n' "$*"; }
fail()  { printf '  \e[31m✗\e[0m %s\n' "$*"; exit 1; }
step()  { printf '\n\e[1;34m[ladder]\e[0m %s\n' "$*"; }

POLICY="wafs/openappsec/localconfig/local_policy.yaml"
LEVELS=("${LEVELS:-critical,high,medium,low}")
# shellcheck disable=SC2206 # intentional word splitting on comma
IFS=, read -ra LEVEL_LIST <<< "${LEVELS[0]}"
CLASSES="${CLASSES:-sqli,xss,cmdi,lfi,ssti,xxe,nosql,ldap,ssrf,jndi,graphql,crlf}"
MUTATORS="${MUTATORS:-lexical,encoding,structural,context_displacement,multi_request}"
MAX_CONCURRENCY="${MAX_CONCURRENCY:-4}"
TARGET="${TARGET:-juiceshop}"
POLICY_RELOAD_SLEEP="${POLICY_RELOAD_SLEEP:-45}"

step "0/4  Prerequisites"
[[ -f "$POLICY" ]] || fail "policy yaml missing at $POLICY"
docker compose ps openappsec 2>/dev/null | grep -q "Up" \
  || fail "openappsec container not up — run 'make up-ml' first"
pass "openappsec container running"

STEPS_ARG=""
declare -A RUN_IDS

step "1/4  Sweep minimum-confidence ∈ {${LEVEL_LIST[*]}}"
for level in "${LEVEL_LIST[@]}"; do
  info "→ setting minimum-confidence: $level"
  # Only rewrite the one line — preserve indentation and every other key.
  sed -i -E "s/^( *minimum-confidence: *).*/\1$level/" "$POLICY"
  grep -q "minimum-confidence: $level" "$POLICY" \
    || fail "sed did not apply for $level (check file shape)"

  info "reloading openappsec policy (waiting ${POLICY_RELOAD_SLEEP}s for smart-sync)"
  # Policy is bind-mounted; open-appsec's smart-sync sidecar picks up edits
  # on its next poll. A HUP to the agent forces an immediate reload.
  docker compose exec -T openappsec sh -c \
    'pkill -HUP -f cp-nano-orchestration 2>/dev/null; true' || true
  sleep "$POLICY_RELOAD_SLEEP"

  RUN_ID="openappsec-${level}-$(date -u +%Y%m%dT%H%M%SZ)"
  info "running engine → run_id=$RUN_ID"
  docker compose --profile engine --profile ml run --rm \
    -e MAX_CONCURRENCY="$MAX_CONCURRENCY" \
    engine run \
    --wafs baseline,openappsec \
    --classes "$CLASSES" \
    --mutators "$MUTATORS" \
    --run-id "$RUN_ID" >/tmp/engine-ladder-$level.log 2>&1 \
    || { tail -40 /tmp/engine-ladder-$level.log; fail "engine run at level=$level"; }

  RUN_IDS[$level]="$RUN_ID"
  STEPS_ARG+="${level}:${RUN_ID},"
  pass "level=$level → $RUN_ID"
done
STEPS_ARG="${STEPS_ARG%,}"

step "2/4  Per-run reports"
for level in "${LEVEL_LIST[@]}"; do
  engine/.venv/bin/python -m wafeval report --run-id "${RUN_IDS[$level]}" \
    >/tmp/report-ladder-$level.log 2>&1 \
    || { tail -30 /tmp/report-ladder-$level.log; fail "report $level"; }
  pass "report $level"
done

step "3/4  Ladder aggregate report + figure"
OUT_ID="${OUT_ID:-openappsec-ladder-$(date -u +%Y%m%dT%H%M%SZ)}"
engine/.venv/bin/python -m wafeval ladder \
  --steps "$STEPS_ARG" \
  --target "$TARGET" \
  --lens waf_view \
  --out-id "$OUT_ID" \
  --title "open-appsec min-confidence ladder ($TARGET · waf_view)" \
  || fail "ladder aggregator"
pass "ladder artefacts → results/reports/$OUT_ID/"

step "4/4  Summary"
info "run_ids:"
for level in "${LEVEL_LIST[@]}"; do
  info "  $level → ${RUN_IDS[$level]}"
done
info "ladder artefact: results/reports/$OUT_ID/report-ladder.md"

printf '\n\e[1;32mLadder ablation DONE\e[0m\n'
