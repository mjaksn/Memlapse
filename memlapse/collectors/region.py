"""RegionSampler, records a process's memory map over time.

Runs on its own QThread. Each tick it captures process-wide stats (working
set, private bytes, thread count), the full VirtualQueryEx region map, and the
Win32 start address of every thread it can query, and writes them as one
sample to SQLite. This is the process-wide sampling that
powers playback; per-thread attribution comes later via ETW.

The sampler owns its own DB connection (opened inside run(), on the sampler
thread) because SQLite connections cannot cross threads.
"""

from __future__ import annotations

import time

import psutil
from PySide6.QtCore import QThread, Signal

from ..analytics import is_executable
from ..storage import connect
from ..storage.dao import Dao, ProcState
from ..win32.memory import ProcessAccessError, ProcessMemory
from ..win32.threads import start_addresses

#: Bytes read from the start of each executable region for content heuristics
#: (PE header, NOP sled, entropy). Enough to see the tell without bloating the DB.
HEAD_BYTES = 256


def _now_us() -> int:
    return time.time_ns() // 1000


class RegionSampler(QThread):
    """Samples ``pid`` every ``interval`` seconds into a new recording."""

    #: recording_id, once the recording row exists.
    started = Signal(int)
    #: ts_us (64-bit epoch microseconds), region_count, after each sample.
    sampled = Signal("qlonglong", int)
    #: reason string, emitted when sampling stops (user stop or target exit).
    finished_recording = Signal(str)

    def __init__(self, pid: int, name: str, interval: float,
                 db_path=None, note: str | None = None, parent=None) -> None:
        super().__init__(parent)
        self.pid = pid
        self.name = name
        self.interval = interval
        self.db_path = db_path
        self.note = note
        self._running = False
        self.recording_id: int | None = None

    def run(self) -> None:
        conn = connect(self.db_path)
        dao = Dao(conn)
        rec_id = dao.create_recording(self.pid, self.name, _now_us(), self.note)
        self.recording_id = rec_id
        self.started.emit(rec_id)

        self._running = True
        reason = "stopped"
        try:
            proc = psutil.Process(self.pid)
            while self._running:
                start = time.monotonic()
                try:
                    self._sample_once(dao, rec_id, proc)
                except (psutil.NoSuchProcess, psutil.AccessDenied, ProcessAccessError):
                    reason = "target process exited or became inaccessible"
                    break
                self._sleep_remaining(start)
        except psutil.NoSuchProcess:
            reason = "target process exited or became inaccessible"
        finally:
            dao.end_recording(rec_id, _now_us())
            conn.close()
            self.finished_recording.emit(reason)

    def _sample_once(self, dao: Dao, rec_id: int, proc: psutil.Process) -> None:
        ts = _now_us()
        minfo = proc.memory_info()
        state = ProcState(
            ts_us=ts,
            pid=self.pid,
            wset_bytes=int(getattr(minfo, "wset", getattr(minfo, "rss", 0)) or 0),
            priv_bytes=int(getattr(minfo, "private", getattr(minfo, "vms", 0)) or 0),
            thread_count=proc.num_threads(),
        )
        with ProcessMemory(self.pid, want_read=True) as pm:
            regions = pm.regions()
            heads = self._read_heads(pm, regions)
            # Inside the handle, so one pinned instance supplies the whole
            # sample: released here, the pid could be reused between the map
            # and the thread walk and the two halves would describe different
            # processes. Off the GUI thread, like every other read here.
            thread_starts = start_addresses(self.pid)
        dao.add_sample(rec_id, ts, state, regions, heads, thread_starts)
        self.sampled.emit(ts, len(regions))

    @staticmethod
    def _read_heads(pm: ProcessMemory, regions) -> dict[int, bytes]:
        """Read the head of each executable, readable region for content scans.

        Empty when the handle lacks read access (unelevated target); regions
        that are not executable, unreadable, or return no bytes are skipped.
        """
        heads: dict[int, bytes] = {}
        if not pm.can_read:
            return heads
        for r in regions:
            if is_executable(r.protect) and r.is_readable:
                data = pm.read(r.base_addr, HEAD_BYTES)
                if data:
                    heads[r.base_addr] = data
        return heads

    def _sleep_remaining(self, start: float) -> None:
        remaining = max(0.0, self.interval - (time.monotonic() - start))
        slept = 0.0
        while self._running and slept < remaining:
            step = min(0.05, remaining - slept)
            time.sleep(step)
            slept += step

    def stop(self) -> None:
        self._running = False
