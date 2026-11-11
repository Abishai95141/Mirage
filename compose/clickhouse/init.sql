-- MIRAGE storage, schema version 0.1.0. Runs once, on first start of an empty volume.

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
