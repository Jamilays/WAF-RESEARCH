#!/bin/sh
# One-shot DB bootstrap for zecure/shadowd.
#
# Waits for shadowd-db to accept connections (compose healthcheck already
# gates us, but a last-mile retry makes re-runs robust), then applies
# bootstrap.sql. Exits 0 on success so compose's
# ``condition: service_completed_successfully`` gate fires and the rest of
# the shadowd stack can come up.

set -eu

PGHOST="${PGHOST:-shadowd-db}"
PGPORT="${PGPORT:-5432}"
PGUSER="${PGUSER:-shadowd}"
PGDATABASE="${PGDATABASE:-shadowd}"
export PGPASSWORD="${PGPASSWORD:-shadowd_dev_only}"

echo "[shadowd-init] waiting for ${PGHOST}:${PGPORT} …"
for i in $(seq 1 30); do
  if pg_isready -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

echo "[shadowd-init] applying bootstrap.sql"
psql -v ON_ERROR_STOP=1 -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE" \
  -f /init/bootstrap.sql

echo "[shadowd-init] done"
