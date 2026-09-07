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

    Byte fields come straight from the bulk NtQuerySystemInformation table and
    need no handle or elevation; only ``username`` is best-effort and is empty
    when psutil is denied access.

    ``parent_pid`` is the creator recorded when the process started. Windows
    does not keep it current, so the parent may have exited or had its pid
    reused; it is a lineage hint, not a live link.
    """

    pid: int
    name: str
    username: str
    num_threads: int
    wset_bytes: int      # working set (physical RAM currently used)
    private_bytes: int   # committed private (approximate "real" footprint)
    parent_pid: int = 0  # creator at creation time; 0 when there is none

    @property
    def label(self) -> str:
        return f"{self.name} ({self.pid})"
