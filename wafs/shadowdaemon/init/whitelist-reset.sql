-- Undo whitelist-seed.sql — drop the experimental rules + restore the
-- canonical blacklist-only profile (matches the defaults from
-- bootstrap.sql). Called by tests/shadowd_whitelist.sh on its way out
-- so a whitelist probe doesn't leave the daemon in a different state
-- than the main research corpus expects.

DELETE FROM whitelist_rules WHERE profile_id = 1;

UPDATE profiles
SET whitelist_enabled = 0, blacklist_enabled = 1, mode = 1
WHERE id = 1;

SELECT 'shadowd-whitelist-reset whitelist_enabled=' ||
       (SELECT whitelist_enabled FROM profiles WHERE id = 1) AS status;
