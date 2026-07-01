"""RecordingManager — owns the active RegionSampler and its lifecycle.

A thin coordinator so the UI doesn't manage QThread details directly. Re-emits
the sampler's signals and guarantees only one recording runs at a time.
"""

from __future__ import annotations

from PySide6.QtCore import QObject, Signal

from ..collectors import RegionSampler

DEFAULT_INTERVAL = 1.0


class RecordingManager(QObject):
    started = Signal(int)               # recording_id
    sampled = Signal("qlonglong", int)  # ts_us (64-bit), region_count
    stopped = Signal(str)               # reason

    def __init__(self, db_path=None, parent=None) -> None:
        super().__init__(parent)
        self.db_path = db_path
        self._sampler: RegionSampler | None = None

    @property
    def is_recording(self) -> bool:
        return self._sampler is not None and self._sampler.isRunning()

    def start(self, pid: int, name: str, interval: float = DEFAULT_INTERVAL) -> None:
        if self.is_recording:
            return
        sampler = RegionSampler(pid, name, interval, db_path=self.db_path)
        sampler.started.connect(self.started)
        sampler.sampled.connect(self.sampled)
        sampler.finished_recording.connect(self._on_finished)
        self._sampler = sampler
        sampler.start()

    def stop(self) -> None:
        if self._sampler is not None:
            self._sampler.stop()
            self._sampler.wait(3000)

    def _on_finished(self, reason: str) -> None:
        self._sampler = None
        self.stopped.emit(reason)
