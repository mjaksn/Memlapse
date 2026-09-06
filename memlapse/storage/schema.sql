-- Memlapse storage schema. See docs/ARCHITECTURE.md for the data model rationale.
-- Timestamps are integer microseconds since the Unix epoch (UTC).

CREATE TABLE IF NOT EXISTS recording (
    id          INTEGER PRIMARY KEY,
    target_pid  INTEGER NOT NULL,
    target_name TEXT    NOT NULL,
    started_utc INTEGER NOT NULL,
    ended_utc   INTEGER,
    note        TEXT
);

CREATE TABLE IF NOT EXISTS process_snapshot (
    id            INTEGER PRIMARY KEY,
    recording_id  INTEGER NOT NULL REFERENCES recording(id) ON DELETE CASCADE,
    ts_us         INTEGER NOT NULL,
    pid           INTEGER NOT NULL,
    wset_bytes    INTEGER NOT NULL,
    priv_bytes    INTEGER NOT NULL,
    thread_count  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS thread (
    id           INTEGER PRIMARY KEY,
    recording_id INTEGER NOT NULL REFERENCES recording(id) ON DELETE CASCADE,
    tid          INTEGER NOT NULL,
    pid          INTEGER NOT NULL,
    start_ts     INTEGER,
    symbol_hint  TEXT
);

CREATE TABLE IF NOT EXISTS region_snapshot (
    id           INTEGER PRIMARY KEY,
    recording_id INTEGER NOT NULL REFERENCES recording(id) ON DELETE CASCADE,
    ts_us        INTEGER NOT NULL,
    base_addr    INTEGER NOT NULL,
    size         INTEGER NOT NULL,
    protect      INTEGER NOT NULL,
    state        INTEGER NOT NULL,
    type         INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS region_blob (
    region_snapshot_id INTEGER PRIMARY KEY
                       REFERENCES region_snapshot(id) ON DELETE CASCADE,
    content            BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS mem_event (
    id           INTEGER PRIMARY KEY,
    recording_id INTEGER NOT NULL REFERENCES recording(id) ON DELETE CASCADE,
    ts_us        INTEGER NOT NULL,
    tid          INTEGER NOT NULL,
    kind         TEXT    NOT NULL,   -- alloc | free | protect | fault | ...
    addr         INTEGER NOT NULL,
    size         INTEGER NOT NULL,
    protect      INTEGER
);

CREATE INDEX IF NOT EXISTS ix_procsnap_rec_ts   ON process_snapshot(recording_id, ts_us);
CREATE INDEX IF NOT EXISTS ix_regionsnap_rec_ts ON region_snapshot(recording_id, ts_us);
CREATE INDEX IF NOT EXISTS ix_memevent_rec_ts   ON mem_event(recording_id, ts_us);
CREATE INDEX IF NOT EXISTS ix_memevent_rec_tid  ON mem_event(recording_id, tid, ts_us);
