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

-- Captured region heads, stored once per distinct content and shared by every
-- region_snapshot row whose head matched. The key is the SHA-256 digest of the
-- content, which is also what the content-change detector compares between
-- consecutive samples, so a rewrite is visible without touching the bytes.
CREATE TABLE IF NOT EXISTS head (
    hash    BLOB PRIMARY KEY,
    content BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS region_snapshot (
    id           INTEGER PRIMARY KEY,
    recording_id INTEGER NOT NULL REFERENCES recording(id) ON DELETE CASCADE,
    ts_us        INTEGER NOT NULL,
    base_addr    INTEGER NOT NULL,
    size         INTEGER NOT NULL,
    protect      INTEGER NOT NULL,
    state        INTEGER NOT NULL,
    type         INTEGER NOT NULL,
    head_hash    BLOB                -- head.hash, NULL when no head was captured
);

-- Legacy: recordings made before heads were deduplicated stored each head
-- against its own region_snapshot row here. Kept so those recordings still
-- read back; db.py adds the head_hash column to old databases on open and
-- the DAO falls back to this table for rows that have no hash.
CREATE TABLE IF NOT EXISTS region_blob (
    region_snapshot_id INTEGER PRIMARY KEY
                       REFERENCES region_snapshot(id) ON DELETE CASCADE,
    content            BLOB NOT NULL
);

-- Win32 start address of every thread that could be queried, per sample.
-- A sample with no rows is normal: unelevated, another user's threads will
-- not open. The tid is kept because the Phase 5 ETW events join on it.
CREATE TABLE IF NOT EXISTS thread_snapshot (
    id           INTEGER PRIMARY KEY,
    recording_id INTEGER NOT NULL REFERENCES recording(id) ON DELETE CASCADE,
    ts_us        INTEGER NOT NULL,
    tid          INTEGER NOT NULL,
    start_addr   INTEGER NOT NULL
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
CREATE INDEX IF NOT EXISTS ix_threadsnap_rec_ts ON thread_snapshot(recording_id, ts_us);
CREATE INDEX IF NOT EXISTS ix_memevent_rec_ts   ON mem_event(recording_id, ts_us);
CREATE INDEX IF NOT EXISTS ix_memevent_rec_tid  ON mem_event(recording_id, tid, ts_us);
