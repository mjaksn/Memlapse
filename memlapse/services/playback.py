"""PlaybackEngine, reads a recording back for scrubbing.

Holds a read-only Dao on the UI thread (a separate SQLite connection from the
sampler's; WAL makes concurrent read+write safe). Given a target time it
returns the process state and region map from the latest sample at or before
that time, and can compare that sample with the one before it.

It also reads the recording as a whole, which is the half a live watch cannot
do: :meth:`PlaybackEngine.rewrite_history` walks every sample once on open and
comes back with each region's rewrites over the whole run.
"""

from __future__ import annotations

from collections.abc import Sequence

from ..analytics import (
    regions_with_thread_starts, rewritten_regions, unpacked_regions,
)
from ..storage import connect
from ..storage.dao import Dao, ProcState, RecordingRow
from ..model.region import Region


def _elapsed(us: int) -> str:
    """Microseconds since the start of a recording as hh:mm:ss."""
    seconds = us // 1_000_000
    minutes, secs = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def describe_rewrites(times: Sequence[int], origin_us: int) -> str:
    """One line saying what :meth:`PlaybackEngine.rewrite_history` found.

    ``times`` is one region's list of rewrite times and ``origin_us`` the
    recording's first sample, so the clock reads as elapsed time and matches
    the timeline that scrubs to it. Empty times give an empty string, which is
    a caller's cue to say nothing rather than to say "never".

    The wording lives here rather than in the widget that shows it because it
    is the whole of what this feature says to an analyst, and here it can be
    tested without starting Qt.
    """
    if not times:
        return ""
    when = _elapsed(times[-1] - origin_us)
    if len(times) == 1:
        return f"rewritten once in this recording, at {when}"
    return (f"rewritten {len(times)} times in this recording, "
            f"most recently at {when}")


class PlaybackEngine:
    def __init__(self, db_path=None) -> None:
        self._conn = connect(db_path)
        self._dao = Dao(self._conn)
        self.recording_id: int | None = None
        self.sample_times: list[int] = []
        #: Image name of the recorded process, which is what an allowlist
        #: entry is keyed on. Playback has to score against the same entries
        #: as live mode or the two disagree about the same process.
        self.target_name: str = ""
        #: Sample timestamps where the recorded process instance changed, so
        #: the samples on either side describe different processes under one
        #: pid. Empty for every well-behaved recording, and empty for one made
        #: before the creation time was stored, which is not the same thing.
        self.instance_changes: list[int] = []
        #: What :meth:`rewrite_history` found when this recording was opened,
        #: base address to the times it was rewritten. Read beside a band
        #: rather than folded into one, since a band answers for the sample
        #: the analyst is standing on and this answers for the whole run.
        self.rewrites: dict[int, list[int]] = {}

    def list_recordings(self) -> list[RecordingRow]:
        return self._dao.list_recordings()

    def open(self, recording_id: int) -> list[int]:
        """Load a recording; returns its sample timestamps (may be empty)."""
        self.recording_id = recording_id
        self.sample_times = self._dao.sample_times(recording_id)
        self.target_name = next(
            (r.target_name for r in self._dao.list_recordings()
             if r.id == recording_id), "")
        self.instance_changes = self._dao.instance_changes(recording_id)
        self.rewrites = self.rewrite_history(recording_id)
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

    def rewrite_history(self, recording_id: int) -> dict[int, list[int]]:
        """Every rewrite the recording holds, base address to the times of it.

        One pass over the recording, comparing each sample with the one before
        it exactly as :meth:`rewritten` compares a single pair, and filing the
        change under the later of the two, which is the sample it was observed
        at and the sample playback puts the flag on. Times come out in order,
        and a region that was never rewritten is absent rather than empty.

        This is the answer live mode cannot give. At any moment a watch knows
        the sample before and the sample it is on, so it can say "rewritten
        just now" and nothing else; a recording holds every sample at once and
        can count. It goes beside the band and never into it: the band still
        answers for one moment (ARCHITECTURE.md, "A band is about a moment"),
        and folding a count into it would cap the recording at what a watch
        could have seen.

        The first sample needs no special case. Nothing precedes it, so the
        empty map it is compared against yields no rewrites, which is the
        right answer rather than a coincidence: a region cannot be shown to
        have changed by a look that has nothing to compare with.
        """
        history: dict[int, list[int]] = {}
        before: list[Region] = []
        before_digests: dict[int, bytes] = {}
        for ts_us, regions, digests in self._dao.region_samples(recording_id):
            for base in rewritten_regions(before, before_digests, regions, digests):
                history.setdefault(base, []).append(ts_us)
            before, before_digests = regions, digests
        return history

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
