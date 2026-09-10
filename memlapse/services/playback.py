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

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal

from ..analytics import (
    Allowlist, EXEC_MASK, region_identity, regions_with_thread_starts,
    rewritten_regions, unpacked_regions,
)
from ..storage import connect
from ..storage.dao import Dao, ProcState, RecordingRow
from ..model.region import MEM_COMMIT, PAGE_GUARD, Region


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


def walk_spells(
    dao: Dao, recording_id: int, should_stop=None
) -> dict[tuple[int, int, int, int], list[tuple[int, int, list[int]]]]:
    """The whole-run walk, keeping each identity's occurrences apart.

    An identity is not quite an allocation either. Windows can free a
    region and hand back one with the same base, size, protection and
    state, and no structural key can tell those apart; only the gap
    between them can, and only a walk that sees every sample has it. So
    each unbroken run of samples an identity appears in is one spell,
    recorded as ``(first_ts, last_ts, times)``, and a region that comes
    back after being gone starts a new one. :meth:`rewrites_at` then hands
    a row the spell it is actually in, rather than everything the address
    has ever done.

    A sample that held no map at all closes nothing. Nothing was seen that
    tick, which is not the same as everything having been freed, and treating
    it as a free would cut every spell in two whenever a sample could not be
    read. The test is whether the sample had region rows, not whether any of
    them were comparable: a map that was seen and holds no executable,
    readable region under this identity has said the region is not there in
    the form the history is about, and the spell ends.

    ``should_stop`` is consulted once per sample, so a walk nobody is waiting
    for stops at the next one rather than reading the rest of the recording.

    That leaves one imprecision, deliberately. A region present in the map but
    with no head captured this tick is not comparable, so its spell ends and a
    new one begins when the bytes come back. That splits a history rather than
    merging two, the same safe direction the identity rule takes with a
    protection change.
    """
    spells: dict[tuple[int, int, int, int],
                 list[list]] = {}
    live: dict[tuple[int, int, int, int], list] = {}
    before: list[Region] = []
    before_digests: dict[int, bytes] = {}
    restarts = set(dao.instance_changes(recording_id))
    walk = dao.region_samples(
        recording_id, state=MEM_COMMIT, protect_any=EXEC_MASK,
        protect_none=PAGE_GUARD)
    for ts_us, regions, digests, observed in walk:
        if should_stop is not None and should_stop():
            # Asked between samples, which is where the walk is cheap to
            # abandon. What is half built is thrown away rather than
            # returned: whoever asked for it has stopped waiting.
            return {}
        if ts_us in restarts:
            # A different process holds the pid now, so nothing that was
            # open belongs to what is about to appear.
            before, before_digests, live = [], {}, {}
        shown = {r.base_addr: r for r in regions}
        if observed:
            present = {region_identity(r) for r in regions}
            for identity in list(live):
                if identity not in present:
                    del live[identity]
            for identity in present:
                spell = live.get(identity)
                if spell is None:
                    spell = [ts_us, ts_us, []]
                    spells.setdefault(identity, []).append(spell)
                    live[identity] = spell
                else:
                    spell[1] = ts_us
        for base in rewritten_regions(before, before_digests, regions, digests):
            live[region_identity(shown[base])][2].append(ts_us)
        before, before_digests = regions, digests
    return {identity: [(a, b, times) for a, b, times in runs]
            for identity, runs in spells.items()}


def _history_pool() -> QThreadPool:
    """The pool the whole-run walk runs on. Patched in tests to run inline."""
    return QThreadPool.globalInstance()


class _HistoryWorker(QRunnable):
    """One recording's whole-run walk, off the GUI thread.

    Opens a connection of its own, because SQLite connections cannot cross
    threads and the engine's belongs to the thread that built it. Carries the
    sequence number it was started with so a result that arrives after the
    analyst has opened something else can be recognised and dropped.

    ``run`` is called directly in tests. Coverage does not trace the threads a
    Qt pool creates, so a runnable exercised only through ``start`` reads as
    dead code (AGENTS.md).
    """

    class Signals(QObject):
        done = Signal(int, object)      # sequence, spells
        failed = Signal(int, str)       # sequence, message

    def __init__(self, db_path, recording_id: int, sequence: int) -> None:
        super().__init__()
        self.signals = self.Signals()
        self._db_path = db_path
        self._recording_id = recording_id
        self._sequence = sequence
        self._stopped = False
        # A QThreadPool deletes an auto-delete runnable the moment run()
        # returns, which leaves the engine holding a Python wrapper around a
        # C++ object that is gone; the next tryTake() on it raises. The
        # engine drops finished workers itself, so ownership stays here.
        self.setAutoDelete(False)

    def stop(self) -> None:
        """Ask a walk already running to give up at the next sample."""
        self._stopped = True

    def run(self) -> None:
        try:
            conn = connect(self._db_path)
            try:
                spells = walk_spells(Dao(conn), self._recording_id,
                                     lambda: self._stopped)
            finally:
                conn.close()
        except Exception as exc:    # never let a pool thread die silently
            # Saying nothing would be read as "this recording holds no
            # rewrites", which is a claim about the process rather than about
            # the walk. The live region loader answers the same way.
            self.signals.failed.emit(self._sequence, str(exc))
        else:
            self.signals.done.emit(self._sequence, spells)


class PlaybackEngine(QObject):
    #: Emitted when the whole-run walk lands, so the marks and the tooltips
    #: can be filled in. A recording is usable before this arrives.
    rewrites_ready = Signal()

    #: Emitted instead when the walk could not finish. Without it an empty
    #: `rewrites` would say "this recording holds no rewrites" when the truth
    #: is that nobody managed to look.
    history_failed = Signal(str)

    #: Looked up per engine so a test can substitute a pool that runs inline.
    pool_factory = staticmethod(_history_pool)

    def __init__(self, db_path=None, parent=None) -> None:
        super().__init__(parent)
        self._db_path = db_path
        self._pool = self.pool_factory()
        #: Bumped on every open and on close, so a walk that finishes after
        #: the analyst moved on is dropped instead of overwriting what is on
        #: screen with a previous recording's history.
        self._sequence = 0
        #: The walk in flight, kept so the next open can take it back off the
        #: pool if it has not started, and ask it to stop if it has.
        self._worker: _HistoryWorker | None = None
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
        #: keyed on :func:`analytics.region_identity`. Read beside a band
        #: rather than folded into one, since a band answers for the sample
        #: the analyst is standing on and this answers for the whole run.
        self.rewrites: dict[tuple[int, int, int, int], list[int]] = {}
        #: The same walk with each identity's occurrences kept apart, which
        #: is what :meth:`rewrites_at` reads. ``rewrites`` above is the whole
        #: recording and drives the marks on the scrubber; a row's tooltip
        #: asks for the spell it is in.
        self._spells: dict[tuple[int, int, int, int],
                           list[tuple[int, int, list[int]]]] = {}
        #: The allowlist the recording was made under, or None when the
        #: recording never wrote one down. None is not an empty allowlist:
        #: it sends the caller back to whatever is in force now, which is how
        #: every replay behaved before this was stored. Test the difference
        #: with ``is None``, never for truth, since a recorded allowlist that
        #: excused nothing is falsy and still governs the replay.
        self.allowlist: Allowlist | None = None

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
        # The walk is the one read here that grows with the recording, so it
        # goes to a pool thread and the answer arrives on `rewrites_ready`.
        self._spells, self.rewrites = {}, {}
        self._sequence += 1
        self._retire_walk()
        worker = _HistoryWorker(self._db_path, recording_id, self._sequence)
        worker.signals.done.connect(self._history_walked)
        worker.signals.failed.connect(self._history_gave_up)
        self._worker = worker
        self._pool.start(worker)
        self.allowlist = self._dao.allowlist_for(recording_id)
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

        Also empty when the recorded process instance changed anywhere
        between the two samples being compared, because the earlier one then
        belongs to a different process that happened to hold the same pid.
        The live view refuses the same comparison by ending the watch when a
        refresh finds another instance; a recording cannot end, so it
        declines the one comparison instead. Two unrelated maps differenced
        against each other would report a stranger's memory as code
        overwritten in place, which is the loudest thing this tool says.
        """
        if self.recording_id is None:
            return set()
        anchor = self._dao.sample_at(self.recording_id, ts_us)
        if anchor is None:
            return set()
        previous = self._dao.previous_sample_ts(self.recording_id, anchor)
        if previous is None:
            return set()
        # Any restart between the two, not only one landing on the anchor.
        # The anchor comes from region_snapshot and a restart timestamp from
        # process_snapshot, so a restart recorded on a sample whose map was
        # empty sits between the pair without ever equalling either end.
        if any(previous < ts <= anchor for ts in self.instance_changes):
            return set()
        return rewritten_regions(
            self._dao.regions_at(self.recording_id, previous),
            self._dao.head_hashes_at(self.recording_id, previous),
            self._dao.regions_at(self.recording_id, anchor),
            self._dao.head_hashes_at(self.recording_id, anchor),
        )

    def rewrite_history(
        self, recording_id: int
    ) -> dict[tuple[int, int, int, int], list[int]]:
        """Every rewrite the recording holds, by region, with the times of it.

        One pass over the recording, comparing each sample with the one before
        it exactly as :meth:`rewritten` compares a single pair, and filing the
        change under the later of the two, which is the sample it was observed
        at and the sample playback puts the flag on. Times come out in order,
        and a region that was never rewritten is absent rather than empty.

        Filed under :func:`analytics.region_identity`, not under the base
        address alone. An address is not a region: one allocation can be freed
        and another put at the same base later in the same recording, and a
        history kept by address would hand the first one's rewrites to the
        second, which is the whole run's version of a tick pointing at a
        sample where nothing happened. The price of that care is a region
        whose protection changes starting a fresh history, since it is a
        fresh identity; that is the safe direction, and a protection change
        is its own signal.

        A sample where the recorded process instance changed starts the walk
        again with nothing behind it, for the reason :meth:`rewritten` gives.
        This surface needs that guard more than the flag does, because a count
        and a tick are shown at every sample of the recording, including the
        ones before the reuse, where the header's warning about it has nothing
        to say yet.

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

        The read is told what a comparable row looks like, and the answer is
        :func:`analytics.is_executable` split into the bits a query can ask
        for: committed, some execute bit set, the guard bit clear. Fetching
        the rest and discarding it costs a fifth of a second on a two minute
        recording and two and a half seconds on a ten minute one, measured in
        ARCHITECTURE.md, "Shipped: rewrite history". Narrowing the read cannot
        change the answer, because every row it leaves behind is one
        :func:`rewritten_regions` would have refused on both sides of the
        comparison.
        """
        return {identity: [t for _, _, times in spells for t in times]
                for identity, spells in self.rewrite_spells(recording_id).items()
                if any(times for _, _, times in spells)}

    def rewrite_spells(
        self, recording_id: int
    ) -> dict[tuple[int, int, int, int], list[tuple[int, int, list[int]]]]:
        """:func:`walk_spells` on this engine's own connection."""
        return walk_spells(self._dao, recording_id)

    def rewrites_at(self, ts_us: int) -> dict[
            tuple[int, int, int, int], list[int]]:
        """What each region on screen has done during the spell it is in now.

        Keyed the same way the row is scored, so the view looks up what it is
        already holding. A region freed and re-allocated at the same base with
        the same shape gets the rewrites of the allocation live at this
        sample, not the ones its predecessor made. Resolved against the
        anchored sample rather than the raw time, because a seek between two
        samples shows the earlier one.

        Empty when the pid was reused between the anchor and the time asked
        about. The anchor comes from region_snapshot and a restart from
        process_snapshot, so a reuse recorded on a sample with no map leaves
        the anchor sitting in the process that is gone, and its history would
        be shown beside the new process's state. :meth:`rewritten` refuses the
        same mismatch between a pair of samples.
        """
        if self.recording_id is None:
            return {}
        anchor = self._dao.sample_at(self.recording_id, ts_us)
        if anchor is None:
            return {}
        if any(anchor < ts <= ts_us for ts in self.instance_changes):
            return {}
        found: dict[tuple[int, int, int, int], list[int]] = {}
        for identity, runs in self._spells.items():
            for first, last, times in runs:
                if first <= anchor <= last and times:
                    found[identity] = list(times)
                    break
        return found

    def _history_walked(self, sequence: int, spells) -> None:
        """Take a finished walk, unless it is answering a stale question."""
        if sequence != self._sequence:
            return
        # It has reported, so there is nothing left to retire and nothing
        # left to take off the pool.
        self._worker = None
        self._spells = spells
        self.rewrites = {
            identity: [t for _, _, times in runs for t in times]
            for identity, runs in spells.items()
            if any(times for _, _, times in runs)}
        self.rewrites_ready.emit()

    def _history_gave_up(self, sequence: int, message: str) -> None:
        """A walk failed. Same staleness rule as a walk that succeeded."""
        if sequence != self._sequence:
            return
        self._worker = None
        self.history_failed.emit(message)

    def _retire_walk(self) -> None:
        """Stop paying for a walk whose answer is no longer wanted.

        The sequence number already drops a stale result, but the work still
        runs, and switching between recordings would otherwise queue a scan
        of each behind the one the analyst is waiting for. Taken off the pool
        if it has not started; asked to stop if it has. Best effort by
        nature: a walk already inside its last sample finishes it.
        """
        worker, self._worker = self._worker, None
        if worker is None:
            return
        if not self._pool.tryTake(worker):
            worker.stop()

    def close(self) -> None:
        # Anything still walking is now answering for a closed connection.
        self._sequence += 1
        self._retire_walk()
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
