"""System-wide memory collector.

Mirrors :class:`ProcessCollector`: a polling loop on its own QThread that
emits a :class:`SystemSample` every tick over a queued Qt signal, so the GUI
thread stays responsive. Cheap enough (two psutil calls) to run at 1 Hz.
"""

from __future__ import annotations

import time

import psutil
from PySide6.QtCore import QThread, Signal

from ..model import SystemSample


class SystemCollector(QThread):
    """Polls system-wide memory every ``interval`` seconds until stopped."""

    #: Emitted with a fresh :class:`SystemSample` on every poll.
    updated = Signal(object)  # SystemSample

    def __init__(self, interval: float = 1.0, parent=None) -> None:
        super().__init__(parent)
        self.interval = interval
        self._running = False

    def run(self) -> None:  # executed on the collector thread
        self._running = True
        while self._running:
            start = time.monotonic()
            self.updated.emit(self._poll())
            elapsed = time.monotonic() - start
            remaining = max(0.0, self.interval - elapsed)
            slept = 0.0
            while self._running and slept < remaining:
                step = min(0.05, remaining - slept)
                time.sleep(step)
                slept += step

    def stop(self) -> None:
        """Ask the loop to exit; safe to call from any thread."""
        self._running = False

    @staticmethod
    def _poll() -> SystemSample:
        vm = psutil.virtual_memory()
        sw = psutil.swap_memory()
        return SystemSample(
            ts_us=int(time.time() * 1_000_000),
            total=int(vm.total),
            available=int(vm.available),
            used=int(vm.used),
            percent=float(vm.percent),
            swap_total=int(sw.total),
            swap_used=int(sw.used),
            swap_percent=float(sw.percent),
        )
