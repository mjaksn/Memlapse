"""RecordingManager, owns the active RegionSampler and its lifecycle.

A thin coordinator so the UI doesn't manage QThread details directly. Re-emits
the sampler's signals and guarantees only one recording runs at a time.

The sampler is created through ``sampler_factory`` (defaulting to
:class:`RegionSampler`) so tests can substitute a fake without spinning up a
real thread.
"""

from __future__ import annotations

from typing import Callable

from PySide6.QtCore import QObject, Signal

from ..analytics import Allowlist
from ..collectors import RegionSampler

DEFAULT_INTERVAL = 1.0

#: (pid, name, interval, db_path, allowlist) -> sampler object (QThread-like:
#: exposes started/sampled/finished_recording signals plus
#: start/stop/wait/isRunning).
SamplerFactory = Callable[[int, str, float, object, object], RegionSampler]


def _default_factory(pid: int, name: str, interval: float, db_path,
                     allowlist) -> RegionSampler:
    return RegionSampler(pid, name, interval, db_path=db_path,
                         allowlist=allowlist)


class RecordingManager(QObject):
    started = Signal(int)               # recording_id
    sampled = Signal("qlonglong", int)  # ts_us (64-bit), region_count
    stopped = Signal(str)               # reason

    def __init__(self, db_path=None, parent=None,
                 sampler_factory: SamplerFactory = _default_factory) -> None:
        super().__init__(parent)
        self.db_path = db_path
        self._sampler_factory = sampler_factory
        self._sampler: RegionSampler | None = None

    @property
    def is_recording(self) -> bool:
        return self._sampler is not None and self._sampler.isRunning()

    def start(self, pid: int, name: str, interval: float = DEFAULT_INTERVAL,
              allowlist: Allowlist | None = None) -> None:
        """Begin recording ``pid``, writing ``allowlist`` into the recording.

        Passing None records no allowlist at all, which a replay reads as
        "nobody wrote one down" and answers by scoring with whatever is in
        force then. An empty Allowlist is the stronger statement that nothing
        was excused, and a replay honours it.
        """
        if self.is_recording:
            return
        sampler = self._sampler_factory(pid, name, interval, self.db_path,
                                        allowlist)
        sampler.started.connect(self.started)
        sampler.sampled.connect(self.sampled)
        sampler.finished_recording.connect(self._on_finished)
        self._sampler = sampler
        sampler.start()

    def stop(self) -> None:
        # Capture locally: _on_finished may null self._sampler synchronously
        # (e.g. a fake sampler that emits finished from stop()).
        sampler = self._sampler
        if sampler is not None:
            sampler.stop()
            sampler.wait(3000)

    def _on_finished(self, reason: str) -> None:
        self._sampler = None
        self.stopped.emit(reason)
