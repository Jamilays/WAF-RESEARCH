#!/bin/sh
# ==============================================================================
# DVWA bootstrapper — runs once on stack bring-up.
# Posts to /setup.php to create the MySQL schema + admin user. Idempotent:
# re-running re-creates the schema, which is safe.
#
# Security-level-low is *not* set here because DVWA stores it in the PHP session
# (a per-cookie property). The engine (Phase 3+) sets security=low each time it
# authenticates as admin, so seeding it here would have no effect on test runs.
# ==============================================================================
set -eu

DVWA="${DVWA_URL:-http://dvwa}"
JAR="$(mktemp)"
trap 'rm -f "$JAR" /tmp/dvwa-setup.html' EXIT

log() { echo "[dvwa-init] $*"; }

# ---- wait for DVWA to respond ------------------------------------------------
log "Waiting for DVWA at $DVWA/login.php …"
i=0
until curl -sf -o /dev/null "$DVWA/login.php"; do
  i=$((i+1))
  if [ "$i" -ge 60 ]; then
    log "ERROR: DVWA unreachable after 120s"; exit 1
  fi
  sleep 2
done
log "DVWA reachable"

# ---- fetch setup.php to pick up PHPSESSID and (maybe) a user_token ----------
curl -s -c "$JAR" -b "$JAR" "$DVWA/setup.php" -o /tmp/dvwa-setup.html
token=$(sed -n "s/.*name=['\"]user_token['\"]\s*value=['\"]\([a-f0-9]\+\)['\"].*/\1/p" /tmp/dvwa-setup.html | head -n1)

# ---- POST create_db (with or without user_token, depending on DVWA build) ---
if [ -n "$token" ]; then
  log "Submitting setup.php with user_token=${token%${token#????????}}…"
  curl -sS -c "$JAR" -b "$JAR" -X POST \
    --data-urlencode "create_db=Create / Reset Database" \
    --data-urlencode "user_token=$token" \
    "$DVWA/setup.php" -o /dev/null
else
  log "Submitting setup.php without user_token"
  curl -sS -c "$JAR" -b "$JAR" -X POST \
    --data-urlencode "create_db=Create / Reset Database" \
    "$DVWA/setup.php" -o /dev/null
fi

# ---- verify: admin/password login succeeds ----------------------------------
log "Verifying admin login works …"
curl -sf -c "$JAR" -b "$JAR" "$DVWA/login.php" -o /dev/null || {
  log "ERROR: login.php unreachable after setup"; exit 1
}
vtoken=$(curl -s -c "$JAR" -b "$JAR" "$DVWA/login.php" | \
  sed -n "s/.*name=['\"]user_token['\"]\s*value=['\"]\([a-f0-9]\+\)['\"].*/\1/p" | head -n1)
[ -n "$vtoken" ] || { log "ERROR: no user_token on login page after setup"; exit 1; }

curl -sS -c "$JAR" -b "$JAR" -X POST -L \
  --data-urlencode "username=admin" \
  --data-urlencode "password=password" \
  --data-urlencode "Login=Login" \
  --data-urlencode "user_token=$vtoken" \
  "$DVWA/login.php" -o /dev/null

# After login, /index.php should return 200 (not 302 → login.php)
code=$(curl -sS -c "$JAR" -b "$JAR" -o /dev/null -w "%{http_code}" "$DVWA/index.php")
if [ "$code" != "200" ]; then
  log "ERROR: admin login failed (index.php → $code)"
  exit 1
fi

log "DONE — DVWA schema initialized, admin/password login verified"
