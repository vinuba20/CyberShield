-- CyberShield schema. Executed at startup; every statement is idempotent.
-- Timestamps are stored as epoch milliseconds (UTC).

CREATE TABLE IF NOT EXISTS events (
    id          TEXT PRIMARY KEY,
    ts          INTEGER NOT NULL,
    source      TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    user_name   TEXT,
    value       REAL,
    message     TEXT NOT NULL,
    raw_line    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events (ts);

CREATE TABLE IF NOT EXISTS alerts (
    id           TEXT PRIMARY KEY,
    rule_name    TEXT NOT NULL,
    severity     TEXT NOT NULL,
    ts           INTEGER NOT NULL,
    source       TEXT NOT NULL,
    explanation  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts (ts);

-- Which events support which alert. Events must be saved before the alerts that cite them.
CREATE TABLE IF NOT EXISTS alert_evidence (
    alert_id  TEXT NOT NULL,
    event_id  TEXT NOT NULL,
    PRIMARY KEY (alert_id, event_id)
);

CREATE TABLE IF NOT EXISTS incidents (
    id        TEXT PRIMARY KEY,
    title     TEXT NOT NULL,
    severity  TEXT NOT NULL,
    status    TEXT NOT NULL,
    notes     TEXT NOT NULL
);

-- Alerts must be saved before the incidents that group them. position keeps their order.
CREATE TABLE IF NOT EXISTS incident_alerts (
    incident_id  TEXT NOT NULL,
    alert_id     TEXT NOT NULL,
    position     INTEGER NOT NULL,
    PRIMARY KEY (incident_id, alert_id)
);

CREATE TABLE IF NOT EXISTS incident_root_causes (
    incident_id  TEXT NOT NULL,
    rank         INTEGER NOT NULL,
    event_type   TEXT NOT NULL,
    source       TEXT NOT NULL,
    score        REAL NOT NULL,
    explanation  TEXT NOT NULL,
    PRIMARY KEY (incident_id, rank)
);
