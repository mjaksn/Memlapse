"""PlaybackEngine — reads a recording back for scrubbing.

Holds a read-only Dao on the UI thread (a separate SQLite connection from the
sampler's; WAL makes concurrent read+write safe). Given a target time it
returns the process state and region map from the latest sample at or before
that time.
"""

from __future__ import annotations

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

    def close(self) -> None:
        self._conn.close()
