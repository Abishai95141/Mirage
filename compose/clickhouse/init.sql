-- MIRAGE storage, schema version 0.2.0. Runs on first start of an empty volume, and again by
-- `make migrate` (every statement is idempotent).

CREATE DATABASE IF NOT EXISTS mirage;

-- One row per normalised event. ReplacingMergeTree on the deterministic event_id makes
-- at-least-once delivery safe: a redelivered batch collapses on merge, and queries that must
-- be exact use FINAL (the sessions view does).
CREATE TABLE IF NOT EXISTS mirage.events
(
    event_id         String,
    ts               DateTime64(6, 'UTC'),
    ingest_ts        DateTime64(6, 'UTC'),
    schema_version   LowCardinality(String),
    source           LowCardinality(String),
    class            LowCardinality(String),
    class_uid        UInt16,
    session_id       String,
    actor_id         String,
    sensor           LowCardinality(String),
    src_ip           String,
    src_pseudonym    String,
    src_port         UInt16,
    src_asn          UInt32,
    src_country      LowCardinality(String),
    dst_ip           String,
    dst_pseudonym    String,
    dst_port         UInt16,
    protocol         LowCardinality(String),
    action           LowCardinality(String),
    outcome          LowCardinality(String),
    payload          String CODEC(ZSTD(3)),
    policy           String,
    labels           String,
    sim_scenario_id  String,
    sim_step_id      String,
    raw              String CODEC(ZSTD(3))
)
ENGINE = ReplacingMergeTree(ingest_ts)
PARTITION BY toYYYYMM(ts)
ORDER BY (source, session_id, ts, event_id);

-- Columns added after schema 0.1.0's first release; no-ops on a fresh volume.
ALTER TABLE mirage.events ADD COLUMN IF NOT EXISTS src_pseudonym String AFTER src_ip;
ALTER TABLE mirage.events ADD COLUMN IF NOT EXISTS src_asn UInt32 AFTER src_port;
ALTER TABLE mirage.events ADD COLUMN IF NOT EXISTS src_country LowCardinality(String) AFTER src_asn;
ALTER TABLE mirage.events ADD COLUMN IF NOT EXISTS dst_pseudonym String AFTER dst_ip;

-- Sessions are derived, not stored, until phase 1 adds actor fingerprinting (WP 1.7).
-- "commands" counts lines entered (command.input); "unknown_commands" counts lines Cowrie
-- reported as not found (command.failed). An unknown command therefore appears in both.
CREATE OR REPLACE VIEW mirage.sessions AS
SELECT
    session_id,
    any(source)                                                         AS source,
    any(protocol)                                                       AS protocol,
    min(ts)                                                             AS start_ts,
    max(ts)                                                             AS end_ts,
    dateDiff('millisecond', min(ts), max(ts)) / 1000.0                  AS duration_s,
    anyIf(src_ip, src_ip != '')                                         AS src_ip,
    anyIf(src_pseudonym, src_pseudonym != '')                           AS src_pseudonym,
    anyIf(src_country, src_country != '')                               AS src_country,
    anyIf(JSONExtractString(payload, 'dataset'), JSONHas(payload, 'dataset')) AS dataset,
    anyIf(JSONExtractString(payload, 'client_version'), action = 'client_version') AS client_version,
    anyIf(JSONExtractString(payload, 'hassh'), action = 'client_kex')   AS hassh,
    countIf(class = 'authentication' AND action = 'login' AND outcome = 'failure') AS failed_logins,
    maxIf(1, class = 'authentication' AND action = 'login' AND outcome = 'success') AS logged_in,
    anyIf(JSONExtractString(payload, 'username'),
          class = 'authentication' AND outcome = 'success')             AS username,
    countIf(class = 'process_activity' AND action = 'command' AND outcome != 'failure') AS commands,
    countIf(class = 'process_activity' AND action = 'command' AND outcome = 'failure') AS unknown_commands,
    countIf(class = 'file_activity')                                    AS file_events,
    arrayMap(x -> x.2, arraySort(x -> x.1, groupArrayIf(
        (ts, JSONExtractString(payload, 'command')),
        class = 'process_activity' AND action = 'command' AND outcome != 'failure'))) AS command_list,
    count()                                                             AS events
FROM mirage.events FINAL
WHERE session_id != ''
GROUP BY session_id;

-- ---------------------------------------------------------------- phase 1 (spec 1.6-1.8)
-- Written by the sessioniser and the artifact indexer. Every table is a ReplacingMergeTree
-- on a version column, so re-running a batch replaces rows instead of adding them.

-- One row per session on any protocol. HTTP sessions group connections by source address and
-- user agent (30 minutes idle); `connections` lists the decoy's connection IDs.
CREATE TABLE IF NOT EXISTS mirage.session_summary
(
    session_id     String,
    version        UInt64,
    protocol       LowCardinality(String),
    source         LowCardinality(String),
    sensor         LowCardinality(String),
    src_ip         String,
    start_ts       DateTime64(6, 'UTC'),
    end_ts         DateTime64(6, 'UTC'),
    inputs         UInt32,
    decisions      UInt32,
    fallbacks      UInt32,
    auth_attempts  UInt32,
    auth_success   UInt8,
    credentials    Array(Tuple(String, String)),
    fingerprints   String,
    tokens         Array(String),
    artifacts      Array(String),
    connections    Array(String),
    actor_id       String
)
ENGINE = ReplacingMergeTree(version)
ORDER BY session_id;

-- Links between sessions; a < b. actor_id in session_summary is the connected component.
CREATE TABLE IF NOT EXISTS mirage.actor_links
(
    a         String,
    b         String,
    reason    LowCardinality(String),   -- honeytoken | ssh_fingerprint_credential | same_source_24h
    strength  UInt8,                    -- 3, 2, 1
    evidence  String,
    ts        DateTime64(6, 'UTC'),
    version   UInt64
)
ENGINE = ReplacingMergeTree(version)
ORDER BY (a, b, reason);

CREATE TABLE IF NOT EXISTS mirage.session_map
(
    conn_id     String,
    session_id  String,
    version     UInt64
)
ENGINE = ReplacingMergeTree(version)
ORDER BY conn_id;

-- Planted honeytokens, loaded from the profile at sessioniser start (spec 1.6).
CREATE TABLE IF NOT EXISTS mirage.tokens
(
    token_id       String,
    type           LowCardinality(String),
    value          String,
    username       String,
    deployment_id  LowCardinality(String),
    planted_at     String,
    minted_at      String,
    note           String,
    loaded_at      DateTime64(6, 'UTC')
)
ENGINE = ReplacingMergeTree(loaded_at)
ORDER BY token_id;

-- A session reached a place a token is planted (read /var/www/html/.env, fetched /.env).
CREATE TABLE IF NOT EXISTS mirage.token_exposures
(
    token_id    String,
    session_id  String,
    ts          DateTime64(6, 'UTC'),
    location    String,
    event_id    String,
    version     UInt64
)
ENGINE = ReplacingMergeTree(version)
ORDER BY (token_id, session_id, event_id);

-- Every stored artifact file, hashed and typed by the indexer.
CREATE TABLE IF NOT EXISTS mirage.artifact_files
(
    sha256        String,
    size          UInt64,
    mime          LowCardinality(String),
    source        LowCardinality(String),
    stored_at     DateTime64(6, 'UTC'),
    name_matches  UInt8,
    indexed_at    DateTime64(6, 'UTC')
)
ENGINE = ReplacingMergeTree(indexed_at)
ORDER BY (sha256, source);

-- spec 1.8's index: each file with the sessions and times its hash appears in events.
CREATE OR REPLACE VIEW mirage.artifacts AS
SELECT
    f.sha256 AS sha256, f.size AS size, f.mime AS mime, f.source AS source,
    f.stored_at AS stored_at, r.first_seen AS first_seen, r.last_seen AS last_seen,
    r.sessions AS sessions
FROM (SELECT * FROM mirage.artifact_files FINAL) AS f
LEFT JOIN
(
    SELECT JSONExtractString(payload, 'sha256') AS sha256, min(ts) AS first_seen,
           max(ts) AS last_seen, groupUniqArray(session_id) AS sessions
    FROM mirage.events
    WHERE class = 'file_activity' AND JSONExtractString(payload, 'sha256') != ''
    GROUP BY sha256
) AS r ON f.sha256 = r.sha256;
