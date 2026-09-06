"""Plain data structures shared across layers.

These are intentionally dependency-free (no Qt, no psutil types) so they can
cross thread boundaries and be persisted without dragging framework objects
along.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ProcessInfo:
    """A point-in-time snapshot of a single process.

    Byte fields are best-effort: some values require elevation to read and
    fall back to 0 when access is denied.
    """

    pid: int
    name: str
    username: str
    num_threads: int
    wset_bytes: int      # working set (physical RAM currently used)
    private_bytes: int   # committed private (approximate "real" footprint)

    @property
    def label(self) -> str:
        return f"{self.name} ({self.pid})"
