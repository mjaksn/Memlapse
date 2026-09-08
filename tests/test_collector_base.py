"""Tests for the shared polling loop and its latest-only delivery."""

import time

import pytest
from PySide6.QtCore import Qt

from memlapse.collectors.base import PollingCollector


class Counting(PollingCollector):
    def __init__(self, interval=0.01):
        super().__init__(interval)
        self.polls = 0

    def _poll(self):
        self.polls += 1
        return self.polls


def test_base_poll_is_abstract(qapp):
    with pytest.raises(NotImplementedError):
        PollingCollector()._poll()


def test_stop_sets_flag(qapp):
    c = Counting()
    c._running = True
    c.stop()
    assert c._running is False


def test_drops_polls_until_previous_snapshot_is_dequeued(qtbot):
    c = Counting(interval=0.001)
    received = []
    announced = []
    c.updated.connect(received.append)
    # Direct, so the count is seen on the collector thread as it is announced;
    # the GUI gets it queued and never reads the attribute itself.
    c.dropped.connect(announced.append, Qt.DirectConnection)
    c.start()
    # No event processing here, so the first emit is never dequeued and every
    # later poll must be dropped rather than queued.
    deadline = time.monotonic() + 2.0
    while c.skipped < 3 and time.monotonic() < deadline:
        time.sleep(0.005)
    c.stop()
    c.wait(1000)
    assert c.skipped >= 3
    assert c.polls == c.skipped + 1  # exactly one snapshot was emitted
    assert announced == list(range(1, c.skipped + 1))  # every drop announced

    qtbot.waitUntil(lambda: received == [1], timeout=1000)
    assert c._delivered.is_set()  # marker ran when the event was dequeued


def test_emits_again_once_delivered(qtbot):
    c = Counting(interval=0.01)
    received = []
    c.updated.connect(received.append)
    c.start()
    qtbot.waitUntil(lambda: len(received) >= 2, timeout=2000)
    c.stop()
    c.wait(1000)
    assert received[0] < received[1]
