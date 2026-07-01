"""Dependency-free analysis helpers powering the dashboard's interpret layer.

Pure Python (no numpy) to match the project's minimal-dependency model layer,
and unit-testable without Qt. Everything here is small: a ring buffer for time
series, a least-squares slope for leak detection, a z-score for anomaly
spikes, and a top-movers diff.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Sequence


class SeriesBuffer:
    """Fixed-capacity ring buffer of ``(ts_us, value)`` points."""

    def __init__(self, capacity: int) -> None:
        if capacity < 1:
            raise ValueError("capacity must be >= 1")
        self._pts: deque[tuple[int, float]] = deque(maxlen=capacity)

    def append(self, ts_us: int, value: float) -> None:
        self._pts.append((int(ts_us), float(value)))

    def __len__(self) -> int:
        return len(self._pts)

    def times(self) -> list[int]:
        return [t for t, _ in self._pts]

    def values(self) -> list[float]:
        return [v for _, v in self._pts]

    def latest(self) -> float | None:
        return self._pts[-1][1] if self._pts else None


def linreg_slope(xs: Sequence[float], ys: Sequence[float]) -> float:
    """Least-squares slope ``dy/dx``.

    Returns 0.0 for fewer than two points, mismatched lengths, or when ``xs``
    has no spread (vertical — undefined slope).
    """
    n = len(xs)
    if n < 2 or n != len(ys):
        return 0.0
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    denom = sum((x - mean_x) ** 2 for x in xs)
    if denom == 0.0:
        return 0.0
    num = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
    return num / denom


def leak_rate_bytes_per_sec(
    times_us: Sequence[int], used_bytes: Sequence[float]
) -> float:
    """Growth rate of used bytes in **bytes/second** over the given window."""
    if len(times_us) < 2:
        return 0.0
    t0 = times_us[0]
    xs = [(t - t0) / 1_000_000 for t in times_us]  # seconds
    return linreg_slope(xs, used_bytes)


def zscore(values: Sequence[float], latest: float | None = None) -> float:
    """Z-score of ``latest`` (default: the last value) vs sample mean/stdev.

    Returns 0.0 for fewer than two points or zero variance.
    """
    n = len(values)
    if n < 2:
        return 0.0
    x = values[-1] if latest is None else latest
    mean = sum(values) / n
    var = sum((v - mean) ** 2 for v in values) / n
    if var <= 0.0:
        return 0.0
    return (x - mean) / (var ** 0.5)


@dataclass(frozen=True, slots=True)
class Mover:
    pid: int
    name: str
    delta_bytes: int


def top_movers(
    prev: dict[int, tuple[str, int]],
    curr: dict[int, tuple[str, int]],
    n: int = 5,
) -> list[Mover]:
    """Processes whose working set changed most since the previous snapshot.

    ``prev``/``curr`` map ``pid -> (name, wset_bytes)``. Only pids present in
    both are considered; result is sorted by absolute delta, descending.
    """
    movers: list[Mover] = []
    for pid, (name, cur_ws) in curr.items():
        if pid in prev:
            delta = cur_ws - prev[pid][1]
            if delta != 0:
                movers.append(Mover(pid, name, delta))
    movers.sort(key=lambda m: abs(m.delta_bytes), reverse=True)
    return movers[:n]
