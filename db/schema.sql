CREATE TABLE IF NOT EXISTS events (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 ts INTEGER NOT NULL,
 ip TEXT NOT NULL,
 method TEXT NOT NULL,
 path TEXT NOT NULL,
 country TEXT,
 ua TEXT,
 risk INTEGER NOT NULL,
 action TEXT NOT NULL,
 threat TEXT,
 reason TEXT,
 ai TEXT,
 latency_ms INTEGER DEFAULT 0,
 campaign_id TEXT,
 request_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip);
CREATE INDEX IF NOT EXISTS idx_events_action ON events(action);
CREATE INDEX IF NOT EXISTS idx_events_campaign ON events(campaign_id);

CREATE TABLE IF NOT EXISTS bans (
 ip TEXT PRIMARY KEY,
 created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL,
 reason TEXT,
 score INTEGER DEFAULT 0,
 strikes INTEGER DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_bans_expiry ON bans(expires_at);

CREATE TABLE IF NOT EXISTS allowlist (ip TEXT PRIMARY KEY, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS blocklist (ip TEXT PRIMARY KEY, created_at INTEGER NOT NULL, reason TEXT);
CREATE TABLE IF NOT EXISTS policies (
 key TEXT PRIMARY KEY,
 value TEXT NOT NULL,
 updated_at INTEGER NOT NULL
);
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
