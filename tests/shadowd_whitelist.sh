#!/usr/bin/env bash
# ==============================================================================
# Shadow Daemon whitelist-mode experiment — TODO.md #1.
#
# Drives the daemon into whitelist mode with a hand-crafted ruleset for
# DVWA's /vulnerabilities/sqli endpoint, probes benign vs attack
# requests through shadowd-dvwa, and restores blacklist-only at exit.
#
# Hand-crafted rules instead of learning-mode auto-induction because
# shadowd's learner records observed inputs for later human promotion —
# it does not auto-generate strict rules. The seed encodes what a
# realistic operator would write after eyeballing the learning-mode
# `parameters` table: "GET|id is always numeric, ≤10 digits".
#
# Commands:
#   enable  — apply whitelist-seed.sql (whitelist_enabled=1, blacklist_enabled=0)
#   disable — apply whitelist-reset.sql (canonical blacklist-only defaults)
#   probe   — run benign + attack curls, report verdicts
#   test    — enable → probe → disable (smoke test; default)
#
# Preconditions: ``make up`` (stack healthy; shadowd + shadowd-db reachable).
# ==============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."

pass()  { printf '  \e[32m✓\e[0m %s\n' "$*"; }
info()  { printf '  \e[34mi\e[0m %s\n' "$*"; }
fail()  { printf '  \e[31m✗\e[0m %s\n' "$*"; exit 1; }
step()  { printf '\n\e[1;34m[shadowd-whitelist]\e[0m %s\n' "$*"; }

TRAEFIK_PORT="${TRAEFIK_PORT:-8000}"

apply_sql() {
    local file="$1"
    [[ -f "$file" ]] || fail "sql file missing: $file"
    docker compose exec -T shadowd-db psql -U shadowd -d shadowd -v ON_ERROR_STOP=1 \
        < "$file" >/tmp/shadowd-whitelist-sql.log 2>&1 \
        || { cat /tmp/shadowd-whitelist-sql.log; fail "psql applying $(basename "$file")"; }
    grep -E 'shadowd-whitelist-(seeded|reset)' /tmp/shadowd-whitelist-sql.log \
        || fail "status line not found in psql output"
}

verify_running() {
    docker compose ps --format '{{.Name}}\t{{.State}}\t{{.Health}}' \
        | grep -qE '^waflab-shadowd\s+running\s+healthy' \
        || fail "shadowd container not healthy — run 'make up' first"
    docker compose ps --format '{{.Name}}\t{{.State}}\t{{.Health}}' \
        | grep -qE '^waflab-shadowd-dvwa\s+running\s+healthy' \
        || fail "shadowd-dvwa proxy not healthy — run 'make up' first"
}

probe_one() {
    # Args: label querystring expected_code
    local label="$1" qs="$2" expected="$3"
    local code
    code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 \
        -H 'Host: shadowd-dvwa.local' \
        "http://127.0.0.1:${TRAEFIK_PORT}/vulnerabilities/sqli/?${qs}")
    if [[ "$code" == "$expected" ]]; then
        pass "$label → $code"
    else
        fail "$label → $code (expected $expected)"
    fi
}

cmd_enable() {
    verify_running
    step "apply whitelist-seed.sql"
    apply_sql wafs/shadowdaemon/init/whitelist-seed.sql
    pass "whitelist enabled"
}

cmd_disable() {
    verify_running
    step "apply whitelist-reset.sql"
    apply_sql wafs/shadowdaemon/init/whitelist-reset.sql
    pass "blacklist-only restored"
}

cmd_probe() {
    verify_running
    step "probing shadowd-dvwa"
    # Benign: ``id=5&Submit=Submit`` — DVWA auth-walls unauthenticated GETs with
    # 302 to /login.php; that's an app-layer response, not a WAF block. The
    # assertion is "shadowd didn't 403 it".
    probe_one "BENIGN  id=5"            'id=5&Submit=Submit' 302
    probe_one "BENIGN  id=42"           'id=42&Submit=Submit' 302
    # Attack: every payload violates ``GET|id → ^[0-9]*$`` and gets 403 from
    # the whitelist engine (status=5 ATTACK, threat reported as GET|id).
    probe_one "ATTACK  tautology"       "id=1%27%20OR%20%271%27%3D%271&Submit=Submit" 403
    probe_one "ATTACK  union"           "id=1%27%20UNION%20SELECT%20NULL--&Submit=Submit" 403
    probe_one "ATTACK  hex literal"     "id=0x41&Submit=Submit" 403
    probe_one "ATTACK  comment"         "id=1--&Submit=Submit" 403
}

cmd_test() {
    cmd_enable
    cmd_probe
    cmd_disable
    printf '\n\e[1;32mshadowd whitelist PoC PASSED\e[0m — hand-crafted rules block SQLi, let benign numeric through\n'
}

case "${1:-test}" in
    enable)  cmd_enable ;;
    disable) cmd_disable ;;
    probe)   cmd_probe ;;
    test)    cmd_test ;;
    *)
        echo "usage: $0 [enable|disable|probe|test]" >&2
        exit 2
        ;;
esac
