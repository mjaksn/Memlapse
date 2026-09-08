"""PlaybackEngine, reads a recording back for scrubbing.

Holds a read-only Dao on the UI thread (a separate SQLite connection from the
sampler's; WAL makes concurrent read+write safe). Given a target time it
returns the process state and region map from the latest sample at or before
that time, and can compare that sample with the one before it.
"""

from __future__ import annotations

from ..analytics import (
    regions_with_thread_starts, rewritten_regions, unpacked_regions,
)
from ..storage import connect
from ..storage.dao import Dao, ProcState, RecordingRow
from ..model.region import Region


class PlaybackEngine:
    def __init__(self, db_path=None) -> None:
        self._conn = connect(db_path)
        self._dao = Dao(self._conn)
        self.recording_id: int | None = None
        self.sample_times: list[int] = []

    def list_recordings(self) -> list[RecordingRow]:
        return self._dao.list_recordings()

    def open(self, recording_id: int) -> list[int]:
        """Load a recording; returns its sample timestamps (may be empty)."""
        self.recording_id = recording_id
        self.sample_times = self._dao.sample_times(recording_id)
        return self.sample_times

    def seek(self, ts_us: int) -> tuple[ProcState | None, list[Region]]:
        if self.recording_id is None:
            return None, []
        state = self._dao.state_at(self.recording_id, ts_us)
        regions = self._dao.regions_at(self.recording_id, ts_us)
        return state, regions

    def heads(self, ts_us: int) -> dict[int, bytes]:
        """Captured region head bytes for the sample at or before ts_us.

        Kept separate from :meth:`seek` so its tuple contract is unchanged;
        feeds the content heuristics that colour the region view.
        """
        if self.recording_id is None:
            return {}
        return self._dao.heads_at(self.recording_id, ts_us)

    def rewritten(self, ts_us: int) -> set[int]:
        """Base addresses of executable regions rewritten since the previous sample.

        Compares the head hashes of the sample at or before ``ts_us`` with
        those of the sample before it (see :func:`analytics.rewritten_regions`).
        Empty when nothing is open, at the first sample, or when no head
        changed. Like :meth:`heads`, separate from :meth:`seek` on purpose.
        """
        if self.recording_id is None:
            return set()
        anchor = self._dao.sample_at(self.recording_id, ts_us)
        if anchor is None:
            return set()
        previous = self._dao.previous_sample_ts(self.recording_id, anchor)
        if previous is None:
            return set()
        return rewritten_regions(
            self._dao.regions_at(self.recording_id, previous),
            self._dao.head_hashes_at(self.recording_id, previous),
            self._dao.regions_at(self.recording_id, anchor),
            self._dao.head_hashes_at(self.recording_id, anchor),
        )

    def close(self) -> None:
        self._conn.close()

    def thread_start_regions(self, ts_us: int) -> set[int]:
        """Base addresses of regions a thread starts in, at or before ts_us.

        Both halves come from the same anchored sample. Empty when nothing is
        open, when the recording caught no thread addresses, or when every
        start lands in a region that is gone from the map.
        """
        if self.recording_id is None:
            return set()
        anchor = self._dao.sample_at(self.recording_id, ts_us)
        if anchor is None:
            return set()
        return regions_with_thread_starts(
            self._dao.regions_at(self.recording_id, anchor),
            self._dao.thread_starts_at(self.recording_id, anchor),
        )

    def unpacked(self, ts_us: int, changed: set[int]) -> set[int]:
        """Of ``changed``, the regions whose entropy fell to code-like values.

        Takes the rewritten set from :meth:`rewritten` rather than working it
        out again, and reads no head content at all when that set is empty,
        which is almost every seek.
        """
        if self.recording_id is None or not changed:
            return set()
        anchor = self._dao.sample_at(self.recording_id, ts_us)
        previous = (None if anchor is None
                    else self._dao.previous_sample_ts(self.recording_id, anchor))
        if previous is None:
            return set()
        return unpacked_regions(
            self._dao.heads_at(self.recording_id, previous),
            self._dao.heads_at(self.recording_id, anchor),
            changed,
        )
