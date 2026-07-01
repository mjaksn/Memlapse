"""System-wide memory snapshot.

Dependency-free (no Qt, no psutil types) like the rest of ``model`` so it can
cross thread boundaries over a Qt signal. ``ts_us`` is integer epoch
microseconds, matching the recording timeline's convention.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SystemSample:
    """A point-in-time snapshot of system-wide physical + swap memory."""

    ts_us: int
    total: int
    available: int
    used: int
    percent: float
    swap_total: int
    swap_used: int
    swap_percent: float

    @property
    def total_gb(self) -> float:
        return self.total / (1024 ** 3)

    @property
    def used_gb(self) -> float:
        return self.used / (1024 ** 3)
