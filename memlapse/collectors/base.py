"""Shared polling loop for the live collectors.

A :class:`PollingCollector` runs ``_poll()`` on its own QThread every
``interval`` seconds and hands each snapshot to the GUI thread over the
queued ``updated`` signal.

Delivery is latest-only. Queued signals have no backpressure: if the GUI
thread ever took longer to consume a snapshot than the collector took to
produce the next one, unconsumed snapshots would pile up in the event queue
and the lag would grow without bound. To prevent that, the collector only
emits when the previous snapshot has been dequeued on the GUI thread, and
otherwise drops the poll (counted in :attr:`skipped`). The marker slot is
connected first, so it runs before the widgets' slots for the same emit;
the bound is therefore one snapshot being processed plus at most one more
waiting in the queue.

The dropped count is handed to the GUI on the ``dropped`` signal rather than
read off the attribute across the thread boundary, and it goes out only
alongside a delivered snapshot. Announcing each drop as it happened would
rebuild the backlog this design exists to prevent, since a GUI busy enough to
drop polls is exactly one that is not draining its queue.
"""

from __future__ import annotations

import threading
import time

from PySide6.QtCore import QThread, Signal


class PollingCollector(QThread):
    """Polls ``_poll()`` every ``interval`` seconds until stopped."""

    #: Emitted with the snapshot returned by ``_poll()``; queued to the GUI.
    updated = Signal(object)
    #: Emitted with the running total of dropped polls, on the same gated
    #: path as ``updated`` and only when the total has moved. The count
    #: belongs to this thread, so it is handed over rather than read across
    #: the boundary, and it obeys the same latest-only rule: emitting on each
    #: drop would queue one event per dropped poll for a GUI that is, by
    #: definition, not draining the queue.
    dropped = Signal(int)

    def __init__(self, interval: float = 1.0, parent=None) -> None:
        super().__init__(parent)
        self.interval = interval
        self._running = False
        #: Polls dropped because the GUI had not yet dequeued the last one.
        self.skipped = 0
        self._delivered = threading.Event()
        self._delivered.set()
        # Queued back to this object's (GUI) thread, ahead of any slot the
        # widgets connect later, so it marks delivery as the event is dequeued.
        self.updated.connect(self._mark_delivered)

    def run(self) -> None:  # executed on the collector thread
        self._running = True
        reported = 0
        while self._running:
            start = time.monotonic()
            snapshot = self._poll()
            if self._delivered.is_set():
                self._delivered.clear()
                self.updated.emit(snapshot)
                # The total rides the gated path, never the drop itself: while
                # the GUI is blocked nothing is queued at all, and the first
                # delivery after it recovers carries the current total. Only
                # the latest is ever of interest, and an intermediate count
                # queued behind a blocked GUI is one nobody will read in time.
                if self.skipped != reported:
                    reported = self.skipped
                    self.dropped.emit(self.skipped)
            else:
                self.skipped += 1
            self._sleep_remaining(start)

    def _mark_delivered(self) -> None:  # runs on the GUI thread
        self._delivered.set()

    def _sleep_remaining(self, start: float) -> None:
        """Sleep out the rest of the interval, staying responsive to stop()."""
        remaining = max(0.0, self.interval - (time.monotonic() - start))
        slept = 0.0
        while self._running and slept < remaining:
            step = min(0.05, remaining - slept)
            time.sleep(step)
            slept += step

    def stop(self) -> None:
        """Ask the loop to exit; safe to call from any thread."""
        self._running = False

    def _poll(self):
        raise NotImplementedError
