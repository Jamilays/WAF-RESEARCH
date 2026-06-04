-- Whitelist-mode seed — TODO.md #1 (shadowd whitelist experiments).
--
-- Applied by tests/shadowd_whitelist.sh when a user opts in to the
-- whitelist experiment. The default bootstrap (wafs/shadowdaemon/init/
-- bootstrap.sql) still provisions a blacklist-only profile so the
-- headline research corpus stays reproducible.
--
-- Strategy: one focused endpoint — DVWA's /vulnerabilities/sqli/ — with
-- strict typed rules on the two user-controlled GET params, plus a
-- wide-open catch-all for everything else (headers, SERVER|*). The
-- catch-all uses ``path='*'`` which shadowd's prepare_wildcard() turns
-- into SQL LIKE '%', so any parameter not explicitly ruled finds it.
--
-- whitelist_filters ids we reuse (seeded in the image — confirmed via
--   ``SELECT id, description FROM whitelist_filters``):
--     1  Numeric           ^[0-9]*$
--     4  Alphanumeric      ^[0-9a-z]*$
--     7  Everything        .*
--
-- Idempotent — drop any existing rows for profile_id=1 first so a
-- re-run of the seed cleans up after a prior experiment.

DELETE FROM whitelist_rules WHERE profile_id = 1;

-- GET|id — DVWA SQLi endpoint's vulnerable param. Numeric, ≤10 digits.
INSERT INTO whitelist_rules (profile_id, path, caller, min_length, max_length, filter_id, status)
VALUES (1, 'GET|id', '*', 0, 10, 1, 1);

-- GET|Submit — the form's submit button name. Alphanumeric, short.
INSERT INTO whitelist_rules (profile_id, path, caller, min_length, max_length, filter_id, status)
VALUES (1, 'GET|Submit', '*', 0, 20, 4, 1);

-- Everything else — headers (HEADER|*), SERVER|REQUEST_METHOD, SERVER|REQUEST_URI.
-- Catch-all with the "Everything" filter (id=7, regex ``.*``) so the whitelist
-- doesn't fire on the traffic shapes we aren't deliberately constraining.
INSERT INTO whitelist_rules (profile_id, path, caller, min_length, max_length, filter_id, status)
VALUES (1, '*', '*', 0, 100000, 7, 1);

-- Flip the profile to whitelist-mode + blacklist-off so the test probes
-- only the whitelist engine. Script restores blacklist-only afterwards.
UPDATE profiles
SET whitelist_enabled = 1, blacklist_enabled = 0
WHERE id = 1;

SELECT 'shadowd-whitelist-seeded rules=' || COUNT(*) AS status
FROM whitelist_rules WHERE profile_id = 1;
