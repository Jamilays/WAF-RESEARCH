-- Shadow Daemon profile bootstrap (Phase 7 real integration).
--
-- Without a profile the daemon refuses to analyse any request. zecure/shadowd
-- ships its schema but leaves provisioning to the operator; for the lab we
-- want a fixed, documented set-up so the engine and proxy agree on the
-- HMAC key + profile id.
--
-- The HMAC key is non-secret (checked in) because the whole stack binds to
-- 127.0.0.1. In a real deployment it would live in .env and the init
-- container would render it.

-- Idempotent: re-run safe because the init container may replay.
-- shadowd mode semantics (include/shared.h):
--   MODE_ACTIVE   = 1  → evaluate threats + return STATUS_ATTACK / CRITICAL
--   MODE_PASSIVE  = 2  → evaluate + log, but always reply STATUS_OK
--   MODE_LEARNING = 3  → record for whitelist learning
-- Only MODE_ACTIVE blocks. (A previous revision used mode=2 thinking "higher
-- number = stricter" — in shadowd it's the opposite.)
-- server_ip uses ``*`` which prepare_wildcard() converts to SQL ``%``; plain
-- ``%`` gets escaped to a literal ``\%`` and matches nothing.
INSERT INTO profiles (
    id, server_ip, name, hmac_key, mode,
    whitelist_enabled, blacklist_enabled, integrity_enabled, flooding_enabled,
    blacklist_threshold, flooding_timeframe, flooding_threshold, cache_outdated
) VALUES (
    1,
    '*',                                     -- matches any upstream IP via prepare_wildcard
    'waflab',
    'waflab_dev_only_hmac_key_change_me',
    1,                                       -- MODE_ACTIVE — block on threats
    0,                                       -- whitelist disabled
    1,                                       -- blacklist enabled (120 bundled filters)
    0,                                       -- integrity disabled
    0,                                       -- flooding disabled
    5,                                       -- threshold for "attack": sum(impacts) > 5
    60, 100, 0
) ON CONFLICT (id) DO UPDATE SET
    server_ip = EXCLUDED.server_ip,
    hmac_key = EXCLUDED.hmac_key,
    mode = EXCLUDED.mode,
    blacklist_enabled = EXCLUDED.blacklist_enabled,
    blacklist_threshold = EXCLUDED.blacklist_threshold;

-- reset the sequence so subsequent auto-ids don't collide.
SELECT setval('profiles_id_seq', GREATEST(1, (SELECT MAX(id) FROM profiles)));

-- A catch-all blacklist rule: every request parameter gets scanned.
--   path   — matches the input-key shape (``GET|q``, ``HEADER|COOKIE``)
--   caller — matches the proxy-supplied caller (``waflab-proxy``)
-- ``*`` is converted to ``%`` by prepare_wildcard, so these fields match
-- every input. status=1 = enabled. Threshold 5 matches the profile's
-- blacklist_threshold (sum-of-impacts > threshold → attack).
INSERT INTO blacklist_rules (profile_id, path, caller, threshold, status)
SELECT 1, '*', '*', 5, 1
WHERE NOT EXISTS (
    SELECT 1 FROM blacklist_rules WHERE profile_id = 1 AND path = '*' AND caller = '*'
);

-- Clean up any legacy rows from earlier attempts with '%' literals.
DELETE FROM blacklist_rules WHERE profile_id = 1 AND (path = '%' OR caller = '%');

-- Sanity output that the entrypoint script can grep for.
SELECT 'shadowd-bootstrap-ok profile_id=' || id || ' mode=' || mode
FROM profiles WHERE id = 1;
