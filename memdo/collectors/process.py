"""Live process collector.

Runs a polling loop on its own QThread and emits a fresh snapshot of every
visible process on each tick. Emitting over a Qt signal hands the data to the
UI thread via a queued connection, so the GUI stays responsive.
"""

from __future__ import annotations

import time

import psutil
from PySide6.QtCore import QThread, Signal

from ..model import ProcessInfo


class ProcessCollector(QThread):
    """Polls the process list every ``interval`` seconds until stopped."""

    #: Emitted with the full list of processes on every poll.
    updated = Signal(list)  # list[ProcessInfo]

    def __init__(self, interval: float = 1.0, parent=None) -> None:
        super().__init__(parent)
        self.interval = interval
        self._running = False

    def run(self) -> None:  # executed on the collector thread
        self._running = True
        while self._running:
            start = time.monotonic()
            self.updated.emit(self._poll())
            # Sleep the remainder of the interval, staying responsive to stop().
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
    def _poll() -> list[ProcessInfo]:
        results: list[ProcessInfo] = []
        for proc in psutil.process_iter(
            ["pid", "name", "username", "num_threads", "memory_info"]
        ):
            try:
                info = proc.info
                minfo = info.get("memory_info")
                # On Windows, memory_info exposes wset + private; elsewhere we
                # fall back to rss/vms so the app still runs during dev.
                wset = getattr(minfo, "wset", None)
                private = getattr(minfo, "private", None)
                results.append(
                    ProcessInfo(
                        pid=info["pid"],
                        name=info.get("name") or "?",
                        username=(info.get("username") or "").split("\\")[-1],
                        num_threads=info.get("num_threads") or 0,
                        wset_bytes=int(wset if wset is not None
                                       else getattr(minfo, "rss", 0) or 0),
                        private_bytes=int(private if private is not None
                                          else getattr(minfo, "vms", 0) or 0),
                    )
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return results
