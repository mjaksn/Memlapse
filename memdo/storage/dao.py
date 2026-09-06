"""Typed read/write helpers over the SQLite schema.

A Dao wraps a single connection. Because SQLite connections are not shareable
across threads, each thread (the sampler that writes, the UI that reads back
for playback) constructs its own Dao. WAL mode lets them run concurrently.

A "sample" is all rows sharing one ``ts_us`` within a recording: exactly one
process_snapshot and N region_snapshots. Playback finds the latest sample at
or before a target time and rebuilds state from it.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

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
    ts_us: int
    pid: int
    wset_bytes: int
    priv_bytes: int
    thread_count: int


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
                   heads: dict[int, bytes] | None = None) -> None:
        """Persist one full sample (process stats + region map) atomically.

        ``heads`` optionally maps a region's ``base_addr`` to the first bytes
        read from it; those are stored in region_blob for content heuristics.
        Regions are inserted one at a time so each blob can reference its row.
        """
        heads = heads or {}
        self.conn.execute(
            "INSERT INTO process_snapshot"
            "(recording_id, ts_us, pid, wset_bytes, priv_bytes, thread_count) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (recording_id, ts_us, state.pid, state.wset_bytes,
             state.priv_bytes, state.thread_count),
        )
        for r in regions:
            cur = self.conn.execute(
                "INSERT INTO region_snapshot"
                "(recording_id, ts_us, base_addr, size, protect, state, type) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (recording_id, ts_us, r.base_addr, r.size, r.protect, r.state, r.type),
            )
            head = heads.get(r.base_addr)
            if head:
                self.conn.execute(
                    "INSERT INTO region_blob(region_snapshot_id, content) "
                    "VALUES (?, ?)",
                    (cur.lastrowid, head),
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
        """Latest process snapshot at or before ts_us."""
        row = self.conn.execute(
            "SELECT ts_us, pid, wset_bytes, priv_bytes, thread_count "
            "FROM process_snapshot WHERE recording_id=? AND ts_us<=? "
            "ORDER BY ts_us DESC LIMIT 1",
            (recording_id, ts_us),
        ).fetchone()
        return ProcState(*row) if row else None

    def regions_at(self, recording_id: int, ts_us: int) -> list[Region]:
        """Region map from the latest sample at or before ts_us."""
        anchor = self.conn.execute(
            "SELECT MAX(ts_us) FROM region_snapshot WHERE recording_id=? AND ts_us<=?",
            (recording_id, ts_us),
        ).fetchone()[0]
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
        heuristics during playback. Empty when nothing was captured.
        """
        anchor = self.conn.execute(
            "SELECT MAX(ts_us) FROM region_snapshot WHERE recording_id=? AND ts_us<=?",
            (recording_id, ts_us),
        ).fetchone()[0]
        if anchor is None:
            return {}
        rows = self.conn.execute(
            "SELECT rs.base_addr, rb.content FROM region_snapshot rs "
            "JOIN region_blob rb ON rb.region_snapshot_id = rs.id "
            "WHERE rs.recording_id=? AND rs.ts_us=?",
            (recording_id, anchor),
        ).fetchall()
        return {b: bytes(c) for (b, c) in rows}
