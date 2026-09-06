"""System-wide memory collector.

Runs the shared polling loop (:class:`PollingCollector`) on its own QThread
and emits a :class:`SystemSample` every tick. Cheap enough (two psutil calls)
to run at 1 Hz.
"""

from __future__ import annotations

import time

import psutil

from ..model import SystemSample
from .base import PollingCollector


class SystemCollector(PollingCollector):
    """Polls system-wide memory every ``interval`` seconds until stopped."""

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
