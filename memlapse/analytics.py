"""Dependency-free analysis helpers powering the dashboard's interpret layer.

Pure Python (no numpy) to match the project's minimal-dependency model layer,
and unit-testable without Qt. Everything here is small: a ring buffer for time
series, a least-squares slope for leak detection, a z-score for anomaly
spikes, and a top-movers diff.
"""

from __future__ import annotations

import hashlib
import math
from bisect import bisect_right
from collections import Counter, deque
from dataclasses import dataclass
from typing import Sequence

from .model.region import (
    MEM_COMMIT,
    MEM_IMAGE,
    MEM_MAPPED,
    MEM_PRIVATE,
    PAGE_EXECUTE,
    PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY,
    PAGE_GUARD,
    Region,
)


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
    has no spread (vertical, undefined slope).
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
class WindowStats:
    count: int
    minimum: float
    maximum: float
    average: float


def window_stats(values: Sequence[float]) -> WindowStats:
    """min / max / mean over a value window (all zeros for an empty window)."""
    n = len(values)
    if n == 0:
        return WindowStats(0, 0.0, 0.0, 0.0)
    return WindowStats(n, min(values), max(values), sum(values) / n)


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


# --- in-memory injection heuristics ----------------------------------------
# Structural + content signals for code-injection detection, in the spirit of
# Volatility's malfind and the "unbacked executable memory" indicator EDRs use.
# Everything here is a pure function of a Region plus optional bytes, so it runs
# against live samples *and* replayed recordings, and unit-tests without Win32.

_EXEC_MASK = (
    PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
)
_WRITE_EXEC = PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY

#: bits/byte above which a buffer looks packed or encrypted (max is 8.0).
ENTROPY_PACKED = 7.2
#: bits/byte at or below which a buffer looks like plain code rather than a
#: packed payload. Compiled x86 sits well under this; the gap between it and
#: ENTROPY_PACKED is deliberate, so a small wobble is not a decryption.
ENTROPY_CODE_MAX = 6.5
#: minimum run of 0x90 bytes to count as a shellcode NOP sled.
NOP_SLED_MIN = 16
#: points for a region whose head fell from packed entropy to code-like
#: entropy between two samples: a payload that decrypted itself in place.
UNPACKED_POINTS = 20

#: points for a committed, executable region that is not image-backed and
#: that a thread starts in. Every legitimate thread starts inside a mapped
#: image, so a start anywhere else is the shellcode-with-a-thread case.
THREAD_START_POINTS = 25

#: Score at or above which a region is worth a second look, and the score at
#: which it is worth acting on. Three bands rather than one threshold: the
#: lower edge is deliberately low, because a signal that scores 30 and is
#: never shown as anything but a number is a signal nobody triages.
REVIEW_SCORE = 30
LIKELY_SCORE = 75

#: MITRE ATT&CK technique each reason maps to, appended to the reason string
#: so a tooltip and an export both name the technique the same way. Signals
#: with no honest mapping carry none.
ATTACK_INJECTION = "T1055"      # Process Injection
ATTACK_REFLECTIVE = "T1620"     # Reflective Code Loading
ATTACK_PACKING = "T1027.002"    # Obfuscated Files or Information: Software Packing

#: points for an executable region whose head bytes changed between samples
#: while its protection and size did not (see :func:`rewritten_regions`).
REWRITTEN_POINTS = 15
#: the same, for an image-backed region. Legitimate code is not rewritten in
#: place; an inline hook or module stomping is, so this carries more weight.
IMAGE_REWRITTEN_POINTS = 40


def is_executable(protect: int) -> bool:
    """True if ``protect`` grants execute and the page is not a guard page."""
    return bool(protect & _EXEC_MASK) and not (protect & PAGE_GUARD)


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte (0.0..8.0); 0.0 for empty input.

    High values (see :data:`ENTROPY_PACKED`) suggest packed or encrypted
    payloads rather than plain code or data.
    """
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())


def head_hash(data: bytes) -> bytes:
    """SHA-256 digest of a captured region head, the key it is stored under.

    Thirty-two bytes that identify the content exactly, so equal heads share
    one row and a changed head is a changed hash.
    """
    return hashlib.sha256(data).digest()


def longest_nop_run(data: bytes) -> int:
    """Length of the longest run of ``0x90`` bytes (shellcode NOP sled)."""
    best = run = 0
    for b in data:
        run = run + 1 if b == 0x90 else 0
        if run > best:
            best = run
    return best


@dataclass(frozen=True, slots=True)
class RegionVerdict:
    """Suspicion score (0..100) and human-readable reasons for one region."""

    base_addr: int
    size: int
    score: int
    reasons: tuple[str, ...]

    @property
    def suspicious(self) -> bool:
        return self.score > 0

    @property
    def band(self) -> str:
        """Triage band: "", "low", "review" or "likely injection".

        The empty string is for a region that scored nothing at all, which
        is most of them. "low" is a region that tripped something without
        reaching :data:`REVIEW_SCORE`: still shown, still tinted, but not
        asking for the analyst's time.
        """
        if self.score >= LIKELY_SCORE:
            return "likely injection"
        if self.score >= REVIEW_SCORE:
            return "review"
        return "low" if self.score > 0 else ""


def score_region(region: Region, *, head: bytes = b"",
                 rewritten: bool = False,
                 thread_start: bool = False,
                 unpacked: bool = False) -> RegionVerdict:
    """Heuristic injection score for a single region.

    ``head`` is the first bytes of the region (from ReadProcessMemory) when
    available; pass ``b""`` to run structural checks only. ``rewritten`` says
    the head changed between two looks at the region, a previous sample in
    playback or a previous refresh while watching live, with the region
    otherwise unchanged (see :func:`rewritten_regions`).
    ``thread_start`` says a thread's Win32 start address falls inside this
    region (see :func:`regions_with_thread_starts`); it only scores when the
    region is not image-backed, since that is where threads normally start.
    ``unpacked`` says the head's entropy fell from packed to code-like
    between samples (see :func:`unpacked_regions`). It stacks with
    ``rewritten``, deliberately: the bytes changing is one fact and what they
    changed into is another, and a private region that did both reaches 85.
    Scores are additive and capped at 100. A non-executable or non-committed
    region always scores 0.
    """
    if region.state != MEM_COMMIT or not is_executable(region.protect):
        return RegionVerdict(region.base_addr, region.size, 0, ())

    score = 0
    reasons: list[str] = []

    # Structural: executable memory that is not backed by an image file is the
    # core injection tell (reflective loading, hollowing, raw shellcode).
    if region.type == MEM_PRIVATE:
        score += 50
        reasons.append(
            f"executable private (unbacked) memory [{ATTACK_INJECTION}]"
        )
    elif region.type == MEM_MAPPED:
        score += 30
        reasons.append(
            "executable mapped memory (possible module stomping) "
            f"[{ATTACK_INJECTION}]"
        )

    if region.protect & _WRITE_EXEC:
        score += 25
        reasons.append("writable + executable (RWX)")

    if thread_start and region.type != MEM_IMAGE:
        score += THREAD_START_POINTS
        reasons.append(
            f"a thread starts here, in memory no image backs "
            f"[{ATTACK_INJECTION}]"
        )

    # Content: only meaningful when the region's head was actually read.
    if head[:2] == b"MZ":
        score += 20
        reasons.append(
            f"PE header (MZ) in memory, reflective DLL [{ATTACK_REFLECTIVE}]"
        )
    if longest_nop_run(head) >= NOP_SLED_MIN:
        score += 10
        reasons.append("NOP sled")
    if head and shannon_entropy(head) >= ENTROPY_PACKED:
        score += 10
        reasons.append(f"high entropy (packed/encrypted) [{ATTACK_PACKING}]")

    # Temporal: the bytes changed but nothing about the region did. A loader
    # that overwrites an existing executable region never allocates and never
    # flips a protection, so this is the only signal it leaves. JIT engines
    # rewrite private code legitimately; image code is not rewritten at all.
    if unpacked:
        score += UNPACKED_POINTS
        reasons.append(
            "entropy fell from packed to code-like, unpacked in place "
            f"[{ATTACK_PACKING}]"
        )

    if rewritten:
        if region.type == MEM_IMAGE:
            score += IMAGE_REWRITTEN_POINTS
            reasons.append(
                "image code rewritten in memory (inline hook or module "
                f"stomping) [{ATTACK_INJECTION}]"
            )
        else:
            score += REWRITTEN_POINTS
            reasons.append(
                "executable memory rewritten in place "
                f"[{ATTACK_INJECTION}]"
            )

    return RegionVerdict(
        region.base_addr, region.size, min(score, 100), tuple(reasons)
    )


def rewritten_regions(prev_regions: Sequence[Region],
                      prev_hashes: dict[int, bytes],
                      curr_regions: Sequence[Region],
                      curr_hashes: dict[int, bytes]) -> set[int]:
    """Base addresses of executable regions rewritten between two looks.

    The two looks are consecutive samples in playback and consecutive live
    refreshes while watching; the comparison is the same either way.

    A region counts when it is committed and executable in both looks with
    the same base, size and protection, both looks captured its head, and
    the two hashes differ. Anything else is not this detector's business: a
    region that appeared, grew, or changed protection belongs to the
    allocation and transition signals, and a head missing on either side
    means the comparison cannot be made, not that the bytes changed.
    """
    before = {r.base_addr: r for r in prev_regions}
    changed: set[int] = set()
    for curr in curr_regions:
        prev = before.get(curr.base_addr)
        if prev is None:
            continue
        if (prev.size, prev.protect, prev.state) != (curr.size, curr.protect, curr.state):
            continue
        if curr.state != MEM_COMMIT or not is_executable(curr.protect):
            continue
        old, new = prev_hashes.get(curr.base_addr), curr_hashes.get(curr.base_addr)
        if old is None or new is None or old == new:
            continue
        changed.add(curr.base_addr)
    return changed


def regions_with_thread_starts(regions: Sequence[Region],
                               starts) -> set[int]:
    """Base addresses of the regions that a thread's start address falls in.

    ``starts`` is any iterable of addresses (see
    :func:`memlapse.win32.threads.start_addresses`). An address that matches no
    region is ignored: the map and the thread list are read a moment apart, so
    one can name memory the other has not got. Whether a hit means anything is
    :func:`score_region`'s decision, not this function's.

    Each address is placed by binary search rather than by scanning the map,
    which matters because playback calls this on the GUI thread for every
    seek and a busy process has thousands of regions and hundreds of threads.
    Regions never overlap, so the last one starting at or below an address is
    the only candidate. The sort is what makes that safe for any caller and
    costs almost nothing for the ordered maps both sources already produce.
    """
    ordered = sorted(regions, key=lambda r: r.base_addr)
    bases = [r.base_addr for r in ordered]
    hits: set[int] = set()
    for address in starts:
        index = bisect_right(bases, address) - 1
        if index < 0:
            continue  # below every region
        region = ordered[index]
        if address < region.base_addr + region.size:
            hits.add(region.base_addr)
    return hits


def unpacked_regions(prev_heads: dict[int, bytes],
                     curr_heads: dict[int, bytes],
                     changed) -> set[int]:
    """Base addresses whose head fell from packed entropy to code-like entropy.

    ``changed`` is the set of regions already known to have been rewritten (see
    :func:`rewritten_regions`), which is the only place this can happen: heads
    are stored once per distinct content, so a head that did not change cannot
    have changed entropy. Scanning only those keeps the cost proportional to
    what moved rather than to the size of the map.

    A payload that decrypts itself in place goes from close to eight bits per
    byte to something a disassembler would recognise. The reverse, code turning
    into noise, is not this signal: that is a region being overwritten with a
    new packed payload, which :func:`rewritten_regions` already reports.

    The two heads must be the same length to be compared at all. A head is
    stored with however many bytes the read returned, so a full 256-byte
    packed head followed by a short read would otherwise look like a collapse
    in entropy when nothing changed but how much of the region could be read.
    """
    fell: set[int] = set()
    for base in changed:
        before, after = prev_heads.get(base), curr_heads.get(base)
        if not before or not after or len(before) != len(after):
            continue
        if (shannon_entropy(before) >= ENTROPY_PACKED
                and shannon_entropy(after) <= ENTROPY_CODE_MAX):
            fell.add(base)
    return fell
