-- MIRAGE storage, schema version 0.3.0. Runs on first start of an empty volume, and again by
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
-- Keystroke statistics from Cowrie's TTY logs (phase 2 spec, 2.0), one row per finished log,
-- keyed by the log's SHA-256 (the name Cowrie gives the file when the channel closes).
CREATE TABLE IF NOT EXISTS mirage.tty_stats
(
    sha256              String,
    input_chunks        UInt32,
    input_bytes         UInt32,
    single_byte_chunks  UInt32,
    backspaces          UInt32,
    paste_bursts        UInt32,
    lines               UInt32,
    key_gap_p10_s       Float32,
    key_gap_p50_s       Float32,
    key_gap_p90_s       Float32,
    duration_s          Float32,
    truncated           UInt8,
    indexed_at          DateTime64(6, 'UTC')
)
ENGINE = ReplacingMergeTree(indexed_at)
ORDER BY sha256;

-- The same statistics per decoy session. A session can close several logs (one per channel);
-- counts add up, and the gap quantiles come from the log with the most input.
CREATE OR REPLACE VIEW mirage.tty_by_session AS
SELECT
    c.session_id                        AS session_id,
    count()                             AS tty_logs,
    sum(t.input_chunks)                 AS input_chunks,
    sum(t.input_bytes)                  AS input_bytes,
    sum(t.single_byte_chunks)           AS single_byte_chunks,
    sum(t.backspaces)                   AS backspaces,
    sum(t.paste_bursts)                 AS paste_bursts,
    sum(t.lines)                        AS lines,
    argMax(t.key_gap_p10_s, t.input_chunks) AS key_gap_p10_s,
    argMax(t.key_gap_p50_s, t.input_chunks) AS key_gap_p50_s,
    argMax(t.key_gap_p90_s, t.input_chunks) AS key_gap_p90_s
FROM
(
    SELECT DISTINCT session_id, JSONExtractString(payload, 'sha256') AS sha256
    FROM mirage.events
    WHERE source = 'cowrie' AND action = 'ttylog_closed'
) AS c
INNER JOIN (SELECT * FROM mirage.tty_stats FINAL) AS t ON c.sha256 = t.sha256
GROUP BY c.session_id;

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

-- ---------------------------------------------------------------- phase 2 (spec section 3)
-- The simulation lab's ground truth and the label join's result. Written by sim-join.
-- Rows of one join carry one version; a run's current labels are the rows whose version
-- equals the run's row in sim_runs, so joining a run again replaces its result cleanly.

-- Every ground-truth record as the runner wrote it. kind: step, session or run.
CREATE TABLE IF NOT EXISTS mirage.sim_truth
(
    run_id    String,
    kind      LowCardinality(String),
    key       String,
    ts        DateTime64(6, 'UTC'),
    record    String,
    ingested  DateTime64(6, 'UTC') DEFAULT now64(6)
)
ENGINE = ReplacingMergeTree(ingested)
ORDER BY (run_id, kind, key);

-- One row per run: what produced it, and the join's health. no_event and mismatch must be
-- zero for a run to be used in a dataset.
CREATE TABLE IF NOT EXISTS mirage.sim_runs
(
    run_id                 String,
    version                UInt64,
    mode                   LowCardinality(String),
    started_ts             DateTime64(6, 'UTC'),
    ended_ts               DateTime64(6, 'UTC'),
    seed                   Int64,
    attack_version         LowCardinality(String),
    catalogue_sha256       String,
    scenarios_sha256       String,
    code_version           String,
    scenarios              Array(String),
    sessions               UInt32,
    steps                  UInt32,
    final                  UInt8,
    matched                UInt32,
    no_event               UInt32,
    mismatch               UInt32,
    not_run                UInt32,
    connections            UInt32,
    connections_unmatched  UInt32,
    problems               String
)
ENGINE = ReplacingMergeTree(version)
ORDER BY run_id;

-- One row per scenario step, with the state the join gave it.
CREATE TABLE IF NOT EXISTS mirage.sim_steps
(
    run_id        String,
    session_ref   String,
    step_id       String,
    version       UInt64,
    scenario_id   String,
    procedure_id  String,
    technique_id  LowCardinality(String),
    tactic        LowCardinality(String),
    protocol      LowCardinality(String),
    evidence      LowCardinality(String),
    status        LowCardinality(String),
    outcome       LowCardinality(String),
    state         LowCardinality(String),
    session_id    String,
    events        UInt32,
    detail        String,
    start_ts      DateTime64(6, 'UTC'),
    end_ts        DateTime64(6, 'UTC')
)
ENGINE = ReplacingMergeTree(version)
ORDER BY (run_id, session_ref, step_id);

-- One row per decoy session (connection) that belongs to a simulated session.
-- logical_session_id is the sessioniser's session (it groups HTTP connections).
CREATE TABLE IF NOT EXISTS mirage.sim_sessions
(
    session_id          String,
    version             UInt64,
    run_id              String,
    scenario_id         String,
    session_ref         String,
    logical_session_id  String,
    protocol            LowCardinality(String),
    actor_ref           String,
    actor_class         LowCardinality(String),
    timing_profile      LowCardinality(String),
    real                UInt8,
    mode                LowCardinality(String),
    src_ip              String,
    src_port            UInt16
)
ENGINE = ReplacingMergeTree(version)
ORDER BY session_id;

-- One row per labelled event. role: 'input' for the event that carries the content,
-- 'decision' for a gate decision made for it. An empty technique_id is an explicit negative.
CREATE TABLE IF NOT EXISTS mirage.sim_labels
(
    event_id        String,
    version         UInt64,
    run_id          String,
    scenario_id     String,
    session_ref     String,
    step_id         String,
    procedure_id    String,
    technique_id    LowCardinality(String),
    tactic          LowCardinality(String),
    attack_version  LowCardinality(String),
    role            LowCardinality(String),
    session_id      String
)
ENGINE = ReplacingMergeTree(version)
ORDER BY (event_id, version);

-- The current labels: only rows from each run's latest join.
CREATE OR REPLACE VIEW mirage.sim_labels_current AS
SELECT l.*
FROM mirage.sim_labels AS l
INNER JOIN (SELECT run_id, version FROM mirage.sim_runs FINAL) AS r
    ON l.run_id = r.run_id AND l.version = r.version;

-- Captured events with their ground truth beside them. Never a model input as it stands:
-- the dataset builder takes its features from an allowlist (spec 2.3).
CREATE OR REPLACE VIEW mirage.events_labelled AS
SELECT e.*, l.run_id AS sim_run_id, l.session_ref AS sim_session_ref, l.step_id AS sim_step,
       l.procedure_id AS procedure_id, l.technique_id AS technique_id, l.tactic AS tactic,
       l.attack_version AS attack_version, l.role AS sim_role
FROM mirage.events AS e
INNER JOIN mirage.sim_labels_current AS l ON e.event_id = l.event_id;

-- ---------------------------------------------------------------- phase 2 (spec 2.4, 2.7)
-- Technique labels and session alerts, written by the tagger worker (mirage-tagger-worker).
-- Both are ReplacingMergeTree on a version column, so re-labelling a session replaces its rows.

-- One row per labelled input event: the technique a rule recognised, with its evidence.
CREATE TABLE IF NOT EXISTS mirage.labels
(
    event_id       String,
    version        UInt64,
    session_id     String,
    protocol       LowCardinality(String),
    kind           LowCardinality(String),   -- input | session
    technique      LowCardinality(String),
    tactic         LowCardinality(String),
    confidence     Float32,
    rule_id        String,
    model_version  LowCardinality(String),
    attack_version LowCardinality(String),
    ts             DateTime64(6, 'UTC')
)
ENGINE = ReplacingMergeTree(version)
ORDER BY event_id;

-- One row per session that is worth an analyst's attention: it reached a honeytoken, captured
-- an artifact, or showed Persistence or Impact. reasons lists why.
-- The actor classifier's prediction for a session (phase 2 spec, 2.3), written by the
-- classifier worker and recomputed as the session grows. `decided_by` says whether the scanner
-- rule or the model made the call. This is a prediction: ground truth lives in sim_sessions and
-- nothing here is ever copied from it.
CREATE TABLE IF NOT EXISTS mirage.actor_class
(
    session_id     String,
    version        UInt64,
    actor_class    LowCardinality(String),   -- scanner | scripted_bot | human
    confidence     Float32,
    decided_by     LowCardinality(String),   -- rule | model
    model_version  LowCardinality(String),
    ts             DateTime64(6, 'UTC')
)
ENGINE = ReplacingMergeTree(version)
ORDER BY session_id;

-- The evaluation harness's latest numbers, published so the Lab dashboard can show them beside
-- their baselines (phase 2 spec, 2.7). One row per dataset and metric; `gate` is 1 when the
-- metric is a gate that is met, 0 when it is a gate that is not, 255 when it is not a gate.
CREATE TABLE IF NOT EXISTS mirage.eval_metrics
(
    dataset       String,
    metric        String,
    value         Float64,
    ci_low        Float64,
    ci_high       Float64,
    baseline      Float64,
    gate          UInt8,
    detail        String,
    published_at  DateTime64(6, 'UTC'),
    version       UInt64
)
ENGINE = ReplacingMergeTree(version)
ORDER BY (dataset, metric);

CREATE TABLE IF NOT EXISTS mirage.alerts
(
    session_id   String,
    version      UInt64,
    src_ip       String,
    protocol     LowCardinality(String),
    reasons      Array(String),
    tactics      Array(String),
    techniques   Array(String),
    tokens       Array(String),
    artifacts    Array(String),
    inputs       UInt32,
    start_ts     DateTime64(6, 'UTC'),
    end_ts       DateTime64(6, 'UTC'),
    created_at   DateTime64(6, 'UTC') DEFAULT now64(6)
)
ENGINE = ReplacingMergeTree(version)
ORDER BY session_id;

-- ---------------------------------------------------------------- phase 2 completion (docs/07)
-- Lost ground truth, shown on the run (gap register R2). Written by sim-join.
--   truth_sessions_missing / truth_steps_missing: the run record counts the session and step
--     records the runner wrote; this many of them never arrived.
--   truth_invalid: records of the run that did not validate. They are kept in sim_truth with
--     kind 'invalid' (the key is the hash of the message) instead of being dropped.
--   incomplete: 1 when the run's closing record never arrived and the run was joined, after a
--     wait, with what there was. `sessions` and `steps` are then the records that arrived,
--     `mode` comes from the session records (empty if there were none), and the hashes and
--     the seed are unknown. A run is healthy only with all four at zero.
ALTER TABLE mirage.sim_runs ADD COLUMN IF NOT EXISTS truth_sessions_missing UInt32 DEFAULT 0;
ALTER TABLE mirage.sim_runs ADD COLUMN IF NOT EXISTS truth_steps_missing UInt32 DEFAULT 0;
ALTER TABLE mirage.sim_runs ADD COLUMN IF NOT EXISTS truth_invalid UInt32 DEFAULT 0;
ALTER TABLE mirage.sim_runs ADD COLUMN IF NOT EXISTS incomplete UInt8 DEFAULT 0;

-- One row per actor with at least one alert reason across its sessions (gap register V2),
-- written by the tagger worker beside mirage.alerts and recomputed as the actor changes.
-- session_ids are the sessioniser's sessions (mirage.session_summary.session_id), src_ips
-- every address they came from; actor_classes are the classifier's predictions from
-- mirage.actor_class and may be empty. Every array is sorted and distinct.
-- When the sessioniser links two actors into one, the alert under the ID that went away is
-- replaced by a row with empty arrays and start_ts = end_ts = 1970-01-01. Read live alerts
-- with: FROM mirage.actor_alerts FINAL WHERE notEmpty(reasons)
CREATE TABLE IF NOT EXISTS mirage.actor_alerts
(
    actor_id       String,
    version        UInt64,
    session_ids    Array(String),
    src_ips        Array(String),
    protocols      Array(String),
    actor_classes  Array(String),
    reasons        Array(String),
    tactics        Array(String),
    techniques     Array(String),
    tokens         Array(String),
    artifacts      Array(String),
    inputs         UInt32,
    start_ts       DateTime64(6, 'UTC'),
    end_ts         DateTime64(6, 'UTC'),
    created_at     DateTime64(6, 'UTC') DEFAULT now64(6)
)
ENGINE = ReplacingMergeTree(version)
ORDER BY actor_id;
