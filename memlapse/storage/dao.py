"""Typed read/write helpers over the SQLite schema.

A Dao wraps a single connection. Because SQLite connections are not shareable
across threads, each thread (the sampler that writes, the UI that reads back
for playback) constructs its own Dao. WAL mode lets them run concurrently.

A "sample" is all rows sharing one ``ts_us`` within a recording: exactly one
process_snapshot, N region_snapshots, and one thread_snapshot for every thread
whose start address could be read. Playback finds the latest sample at or
before a target time and rebuilds state from it.

Captured region heads are stored once per distinct content in ``head``, keyed
by SHA-256, and each region_snapshot row points at its head by hash. Most
executable regions keep the same first bytes from one tick to the next, so
this costs one 32-byte hash per row instead of a 256-byte copy, and the hash
doubles as the comparison key for the content-change detector. Recordings
made before this scheme keep their heads in ``region_blob``, one per row, and
the readers fall back to it.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from dataclasses import dataclass
from itertools import groupby

from ..analytics import head_hash
from ..model.region import Region


@dataclass(frozen=True, slots=True)
class RecordingRow:
    id: int
    target_pid: int
    target_name: str
    started_utc: int
    ended_utc: int | None
    note: str | None


@dataclass(frozen=True, slots=True)
class ProcState:
    """One sample's process-level facts.

    ``can_read`` and ``created_ft`` describe the sample rather than the
    process: whether the handle that took it could read memory, and which
    instance of the pid answered. Both default to ``None``, which means "not
    recorded" and is deliberately distinct from ``False`` and from 0. A replay
    cannot work either one out afterwards, so a recording that predates the
    columns keeps ``None`` and callers must not read that as a denial.
    """

    ts_us: int
    pid: int
    wset_bytes: int
    priv_bytes: int
    thread_count: int
    can_read: bool | None = None
    created_ft: int | None = None


class Dao:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    # --- writes (sampler side) --------------------------------------------
    def create_recording(self, pid: int, name: str, started_us: int,
                         note: str | None = None) -> int:
        cur = self.conn.execute(
            "INSERT INTO recording(target_pid, target_name, started_utc, note) "
            "VALUES (?, ?, ?, ?)",
            (pid, name, started_us, note),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def end_recording(self, recording_id: int, ended_us: int) -> None:
        self.conn.execute(
            "UPDATE recording SET ended_utc=? WHERE id=?", (ended_us, recording_id)
        )
        self.conn.commit()

    def add_sample(self, recording_id: int, ts_us: int, state: ProcState,
                   regions: list[Region],
                   heads: dict[int, bytes] | None = None,
                   thread_starts: dict[int, int] | None = None) -> None:
        """Persist one full sample (process stats + region map) atomically.

        ``heads`` optionally maps a region's ``base_addr`` to the first bytes
        read from it. Each distinct head is stored once in ``head`` and the
        region row carries its hash, so a head seen in an earlier sample (or
        in another region) costs nothing more than the hash.

        ``thread_starts`` maps thread id to Win32 start address for the
        threads that could be queried. Empty is normal and means unknown,
        not none.
        """
        heads = heads or {}
        self.conn.execute(
            "INSERT INTO process_snapshot"
            "(recording_id, ts_us, pid, wset_bytes, priv_bytes, thread_count,"
            " can_read, created_ft) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (recording_id, ts_us, state.pid, state.wset_bytes,
             state.priv_bytes, state.thread_count,
             None if state.can_read is None else int(state.can_read),
             state.created_ft),
        )
        for r in regions:
            digest = None
            head = heads.get(r.base_addr)
            if head:
                digest = head_hash(head)
                self.conn.execute(
                    "INSERT OR IGNORE INTO head(hash, content) VALUES (?, ?)",
                    (digest, head),
                )
            self.conn.execute(
                "INSERT INTO region_snapshot"
                "(recording_id, ts_us, base_addr, size, protect, state, type, head_hash) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (recording_id, ts_us, r.base_addr, r.size, r.protect, r.state,
                 r.type, digest),
            )
        for tid, start_addr in (thread_starts or {}).items():
            self.conn.execute(
                "INSERT INTO thread_snapshot(recording_id, ts_us, tid, start_addr) "
                "VALUES (?, ?, ?, ?)",
                (recording_id, ts_us, tid, start_addr),
            )
        self.conn.commit()

    # --- reads (playback side) --------------------------------------------
    def list_recordings(self) -> list[RecordingRow]:
        rows = self.conn.execute(
            "SELECT id, target_pid, target_name, started_utc, ended_utc, note "
            "FROM recording ORDER BY started_utc DESC"
        ).fetchall()
        return [RecordingRow(*r) for r in rows]

    def sample_times(self, recording_id: int) -> list[int]:
        """Ordered list of every sample's timestamp, drives the timeline."""
        rows = self.conn.execute(
            "SELECT ts_us FROM process_snapshot WHERE recording_id=? ORDER BY ts_us",
            (recording_id,),
        ).fetchall()
        return [r[0] for r in rows]

    def state_at(self, recording_id: int, ts_us: int) -> ProcState | None:
        """Latest process snapshot at or before ts_us.

        ``can_read`` comes back as ``None`` for a recording written before the
        column existed, never as ``False``: nothing was denied, nothing was
        asked. Callers deciding what to tell an analyst have to keep the two
        apart, so the cast below leaves ``None`` alone.
        """
        row = self.conn.execute(
            "SELECT ts_us, pid, wset_bytes, priv_bytes, thread_count,"
            " can_read, created_ft "
            "FROM process_snapshot WHERE recording_id=? AND ts_us<=? "
            "ORDER BY ts_us DESC LIMIT 1",
            (recording_id, ts_us),
        ).fetchone()
        if row is None:
            return None
        ts, pid, wset, priv, threads, can_read, created = row
        return ProcState(ts, pid, wset, priv, threads,
                         None if can_read is None else bool(can_read), created)

    def instance_changes(self, recording_id: int) -> list[int]:
        """Sample timestamps where the recorded process instance changed.

        The sampler opens a fresh handle every sample, so nothing stops the
        pid being reused mid-recording and a stranger's map being appended
        under the same recording id. The live view guards against exactly this
        and ends the watch; a recording has no equivalent, and until the
        creation time was stored there was no way to notice afterwards. Rows
        with no creation time are skipped rather than treated as a change,
        since an older recording has none anywhere.
        """
        rows = self.conn.execute(
            "SELECT ts_us, created_ft FROM process_snapshot "
            "WHERE recording_id=? AND created_ft IS NOT NULL ORDER BY ts_us",
            (recording_id,),
        ).fetchall()
        changed, previous = [], None
        for ts, created in rows:
            if previous is not None and created != previous:
                changed.append(ts)
            previous = created
        return changed

    def region_samples(
        self, recording_id: int
    ) -> Iterator[tuple[int, list[Region], dict[int, bytes]]]:
        """Every region sample of a recording in order, with its head hashes.

        Yields ``(ts_us, regions, digests)`` per sample, which is what a pass
        over a whole recording wants: the anchored reads below answer for one
        moment each, so walking a recording through them costs two queries
        and two MAX subqueries per sample, where this costs one query for the
        lot. Rows with no hash are left out of ``digests`` exactly as
        :meth:`head_hashes_at` leaves them out, so a row from before hashes
        were stored reads as "cannot tell" rather than as a change.

        A generator on purpose: the caller holds two samples at a time
        (see :meth:`PlaybackEngine.rewrite_history`), never the recording.
        """
        rows = self.conn.execute(
            "SELECT ts_us, base_addr, size, state, protect, type, head_hash "
            "FROM region_snapshot WHERE recording_id=? ORDER BY ts_us, base_addr",
            (recording_id,),
        )
        for ts_us, sample in groupby(rows, key=lambda row: row[0]):
            regions: list[Region] = []
            digests: dict[int, bytes] = {}
            for _, base, size, state, protect, type_, digest in sample:
                regions.append(Region(base_addr=base, size=size, state=state,
                                      protect=protect, type=type_))
                if digest is not None:
                    digests[base] = bytes(digest)
            yield ts_us, regions, digests

    def sample_at(self, recording_id: int, ts_us: int) -> int | None:
        """Timestamp of the region sample at or before ts_us, or None.

        This is the anchor every region read below resolves to, so callers
        that need two reads from the same sample can pin it once.
        """
        return self.conn.execute(
            "SELECT MAX(ts_us) FROM region_snapshot WHERE recording_id=? AND ts_us<=?",
            (recording_id, ts_us),
        ).fetchone()[0]

    def previous_sample_ts(self, recording_id: int, ts_us: int) -> int | None:
        """Timestamp of the region sample strictly before ts_us, or None.

        Read from region_snapshot rather than process_snapshot so a sample
        that recorded no regions cannot put the two out of step.
        """
        return self.conn.execute(
            "SELECT MAX(ts_us) FROM region_snapshot WHERE recording_id=? AND ts_us<?",
            (recording_id, ts_us),
        ).fetchone()[0]

    def regions_at(self, recording_id: int, ts_us: int) -> list[Region]:
        """Region map from the latest sample at or before ts_us."""
        anchor = self.sample_at(recording_id, ts_us)
        if anchor is None:
            return []
        rows = self.conn.execute(
            "SELECT base_addr, size, state, protect, type FROM region_snapshot "
            "WHERE recording_id=? AND ts_us=? ORDER BY base_addr",
            (recording_id, anchor),
        ).fetchall()
        return [Region(base_addr=b, size=s, state=st, protect=p, type=t)
                for (b, s, st, p, t) in rows]

    def heads_at(self, recording_id: int, ts_us: int) -> dict[int, bytes]:
        """Captured region head bytes from the latest sample at or before ts_us.

        Maps ``base_addr -> content`` for regions whose bytes were recorded
        (executable ones); pairs with :meth:`regions_at` to feed content
        heuristics during playback. Empty when nothing was captured. Rows
        from before heads were deduplicated have no hash and are read from
        the legacy ``region_blob`` table instead.
        """
        anchor = self.sample_at(recording_id, ts_us)
        if anchor is None:
            return {}
        rows = self.conn.execute(
            "SELECT rs.base_addr, COALESCE(h.content, rb.content) "
            "FROM region_snapshot rs "
            "LEFT JOIN head h ON h.hash = rs.head_hash "
            "LEFT JOIN region_blob rb ON rb.region_snapshot_id = rs.id "
            "WHERE rs.recording_id=? AND rs.ts_us=? "
            "AND (h.content IS NOT NULL OR rb.content IS NOT NULL)",
            (recording_id, anchor),
        ).fetchall()
        return {b: bytes(c) for (b, c) in rows}

    def head_hashes_at(self, recording_id: int, ts_us: int) -> dict[int, bytes]:
        """Head hashes from the latest sample at or before ts_us.

        Maps ``base_addr -> hash`` for regions that carry one. Cheaper than
        :meth:`heads_at` because no content is read, which is what the
        content-change detector wants when it compares two samples. Legacy
        rows without a hash are left out; the detector treats a missing hash
        as "cannot tell" rather than as a change.
        """
        anchor = self.sample_at(recording_id, ts_us)
        if anchor is None:
            return {}
        rows = self.conn.execute(
            "SELECT base_addr, head_hash FROM region_snapshot "
            "WHERE recording_id=? AND ts_us=? AND head_hash IS NOT NULL",
            (recording_id, anchor),
        ).fetchall()
        return {b: bytes(h) for (b, h) in rows}

    def thread_starts_at(self, recording_id: int, ts_us: int) -> list[int]:
        """Thread start addresses recorded with the sample at or before ts_us.

        Anchored on the region sample, like every other read here, so the
        addresses and the region map they are matched against always come from
        the same tick. An empty list means none could be read at that sample,
        which an unelevated recording of another user's process produces for
        every sample.
        """
        anchor = self.sample_at(recording_id, ts_us)
        if anchor is None:
            return []
        rows = self.conn.execute(
            "SELECT start_addr FROM thread_snapshot "
            "WHERE recording_id=? AND ts_us=? ORDER BY tid",
            (recording_id, anchor),
        ).fetchall()
        return [r[0] for r in rows]
