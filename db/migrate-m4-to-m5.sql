-- Run this ONCE if sentinel-db already contains the M4 schema.
ALTER TABLE events ADD COLUMN campaign_id TEXT;
ALTER TABLE events ADD COLUMN request_id TEXT;
ALTER TABLE bans ADD COLUMN strikes INTEGER DEFAULT 1;
CREATE INDEX IF NOT EXISTS idx_events_campaign ON events(campaign_id);
CREATE INDEX IF NOT EXISTS idx_bans_expiry ON bans(expires_at);
CREATE TABLE IF NOT EXISTS blocklist (ip TEXT PRIMARY KEY, created_at INTEGER NOT NULL, reason TEXT);
CREATE TABLE IF NOT EXISTS attackers (
 ip TEXT PRIMARY KEY,
 first_seen INTEGER NOT NULL,
 last_seen INTEGER NOT NULL,
 requests INTEGER DEFAULT 0,
 blocked INTEGER DEFAULT 0,
 reviewed INTEGER DEFAULT 0,
 max_risk INTEGER DEFAULT 0,
 countries TEXT,
 threats TEXT,
 strikes INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_attackers_last_seen ON attackers(last_seen DESC);
CREATE TABLE IF NOT EXISTS incidents (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 campaign_id TEXT NOT NULL UNIQUE,
 created_at INTEGER NOT NULL,
 last_seen INTEGER NOT NULL,
 ip TEXT NOT NULL,
 threat TEXT,
 risk INTEGER DEFAULT 0,
 status TEXT DEFAULT 'open',
 event_count INTEGER DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_incidents_last_seen ON incidents(last_seen DESC);
