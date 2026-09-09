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
from typing import Collection, Sequence

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
#: entropy between two looks: a payload that decrypted itself in place.
UNPACKED_POINTS = 20

#: points for a committed, executable region that is not image-backed and
#: that a thread starts in. Every legitimate thread starts inside a mapped
#: image, so a start anywhere else is the shellcode-with-a-thread case.
THREAD_START_POINTS = 25

#: Score at or above which a region is worth a second look, and the points
#: floor for the band worth acting on. The floor is necessary and not
#: sufficient: reaching :data:`LIKELY_SCORE` earns the top band only with a
#: point from outside :data:`MAP_SHAPE_RULES` as well, and 50 + 25 on private
#: RWX is exactly the case that does not qualify. See
#: :attr:`RegionVerdict.band`, which is the only thing that decides a band.
#: The lower edge is deliberately low, because a signal that scores 30 and is
#: never shown as anything but a number is a signal nobody triages.
REVIEW_SCORE = 30
LIKELY_SCORE = 75

#: MITRE ATT&CK technique each reason maps to, appended to the reason string
#: so a tooltip and an export both name the technique the same way. Signals
#: with no honest mapping carry none.
ATTACK_INJECTION = "T1055"      # Process Injection
ATTACK_REFLECTIVE = "T1620"     # Reflective Code Loading
ATTACK_PACKING = "T1027.002"    # Obfuscated Files or Information: Software Packing

#: points for an executable region whose head bytes changed between two looks
#: while its protection and size did not (see :func:`rewritten_regions`).
REWRITTEN_POINTS = 15
#: the same, for an image-backed region. Legitimate code is not rewritten in
#: place; an inline hook or module stomping is, so this carries more weight.
IMAGE_REWRITTEN_POINTS = 40

#: Stable identifier for each scoring rule. An allowlist entry names one of
#: these to exempt a process from that rule and no other, and they will key
#: rows in a recording, so treat them as schema: a shipped id is never
#: renamed. The prose beside them can be reworded freely; the id cannot.
RULE_PRIVATE_EXEC = "private-exec"
RULE_MAPPED_EXEC = "mapped-exec"
RULE_RWX = "rwx"
RULE_THREAD_START = "thread-start"
RULE_PE_HEADER = "pe-header"
RULE_NOP_SLED = "nop-sled"
RULE_HIGH_ENTROPY = "high-entropy"
RULE_UNPACKED = "unpacked"
RULE_REWRITTEN = "rewritten"
RULE_IMAGE_REWRITTEN = "image-rewritten"

#: The rules a single VirtualQueryEx answers on its own, with no read, no
#: thread query and no second look in time. They describe the shape of the
#: map and nothing about what is in the memory or what it did, which is why
#: they cannot carry a region into the top band by themselves: see
#: :attr:`RegionVerdict.band`.
MAP_SHAPE_RULES = frozenset({RULE_PRIVATE_EXEC, RULE_MAPPED_EXEC, RULE_RWX})

#: Band for a region that scored only on rules an allowlist entry excused.
#: Named rather than spelled out at each use, since the UI switches on it.
ALLOWLISTED = "allowlisted"


@dataclass(frozen=True, slots=True)
class Reason:
    """One scoring rule that fired, with what it contributed.

    ``text`` is the sentence an analyst reads. ``rule`` is the identifier
    an allowlist entry names, and ``points`` is what the rule added, which
    is what lets a suppressed rule be subtracted without scoring twice.
    """

    rule: str
    text: str
    points: int
    #: an allowlist entry named this rule for this process, so it still
    #: fired and still shows, but it does not count towards the band
    allowed: bool = False


@dataclass(frozen=True, slots=True)
class AllowlistEntry:
    """One exemption: a process, the single rule it excuses, and why.

    ``note`` is the analyst's reason for the entry. It is not decoration:
    an exemption nobody can justify later is one nobody dares delete.
    """

    image_name: str
    rule: str
    note: str = ""


class Allowlist:
    """Which rules are exempted for which processes.

    Keyed on the process image name, which the bulk process query already
    returns for every process without needing a handle and which a recording
    already stores, so a replay on another machine reads the same key. The
    name is matched case-insensitively, since Windows treats it that way.

    An image path plus its publisher would be a stronger key: a name alone
    excuses anything that adopts it, which is a real evasion and the reason
    this is a triage aid rather than a control. That upgrade is the intended
    next step. A pid is never a key, since Windows reuses those in minutes.
    """

    def __init__(self, entries: Collection[AllowlistEntry] = ()) -> None:
        #: The entries as given, kept so a caller can show what was excused
        #: and on whose say-so rather than applying it silently. The lookup
        #: below throws the notes away, and an allowlist nobody can read back
        #: is the kind that quietly hides a finding.
        self.entries = tuple(entries)
        self._by_image: dict[str, frozenset[str]] = {}
        for entry in self.entries:
            key = entry.image_name.casefold()
            self._by_image[key] = self._by_image.get(
                key, frozenset()) | {entry.rule}

    def rules_for(self, image_name: str) -> frozenset[str]:
        """The rule ids exempted for this process, empty when none are."""
        return self._by_image.get(image_name.casefold(), frozenset())

    def __bool__(self) -> bool:
        return bool(self._by_image)


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
    """Suspicion score (0..100) and human-readable reasons for one region.

    ``score`` is the sum of its reasons' points, capped. Keeping that true
    is what lets an allowlisted rule be subtracted from the band without a
    second set of books, so a verdict built by hand should honour it.
    """

    base_addr: int
    size: int
    score: int
    reasons: tuple[Reason, ...]

    @property
    def suspicious(self) -> bool:
        return self.score > 0

    @property
    def effective_score(self) -> int:
        """The score with the allowlisted rules taken out.

        This is what bands the region. :attr:`score` stays raw so the table
        still shows what the heuristics said, which is the one thing an
        analyst reviewing a false positive needs to see. Nothing is
        recomputed or discarded, so deleting an allowlist entry restores
        the original verdict on the spot.
        """
        return min(sum(r.points for r in self.reasons if not r.allowed), 100)

    @property
    def map_shape_only(self) -> bool:
        """Every rule still counting came from the memory map alone.

        This is about what counts, not about what was observed. A content or
        temporal rule that fired and was then excused by an allowlist entry
        leaves the region map-shape-only just as surely as one that never
        fired, because the band follows the points that are left. Read it as
        "nothing outside the map is still counting", never as "nothing
        outside the map was found". See :data:`MAP_SHAPE_RULES`.

        It also cannot say why a rule stayed silent, and the reasons are not
        equivalent. A head that was read and matched nothing is evidence; a
        head that could not be read is the absence of it. Where no bytes are
        available at all, which is an unelevated target that denies
        ``PROCESS_VM_READ`` and any recording made against one, no content or
        temporal rule can fire for any region. The top band is not out of
        reach even then: :data:`RULE_THREAD_START` needs no bytes, only a
        thread query, so private memory with a thread starting in it still
        reaches 75 without the map carrying it. What is lost is every rule
        that depends on the content. The caller knows whether it got bytes,
        and the region view says so on the row.
        """
        counting = {r.rule for r in self.reasons if not r.allowed}
        return bool(counting) and counting <= MAP_SHAPE_RULES

    @property
    def band(self) -> str:
        """Triage band: "", "low", "review", "likely injection", "allowlisted".

        The empty string is for a region that scored nothing at all, which
        is most of them. "low" is a region that tripped something without
        reaching :data:`REVIEW_SCORE`: still shown, still tinted, but not
        asking for the analyst's time. "allowlisted" is a region with no
        points left once the excused rules are subtracted: the row and the
        number stay, the verdict does not. Since every rule scores something,
        that is the same as every rule that fired having been excused.

        The top band asks for one thing more than the points. A region whose
        whole case is :data:`MAP_SHAPE_RULES` stops at "review" however far
        it clears :data:`LIKELY_SCORE`, because the map alone cannot tell a
        JIT arena from a payload: both are private, both are executable, and
        a great many of the first exist on an ordinary machine. Reaching
        "likely injection" takes a signal from somewhere else: bytes that
        matched a content rule, a thread found starting in the region, or a
        change between two looks at it. Measured on this machine on
        2026-09-08, across the processes whose memory could be read, that is
        the whole of the difference: every region in the top band scored on
        nothing but private plus RWX. Where nothing can be read the top band
        is unreachable; see :attr:`map_shape_only`.
        """
        if self.score <= 0:
            return ""
        effective = self.effective_score
        if effective == 0:
            return ALLOWLISTED
        if effective >= LIKELY_SCORE and not self.map_shape_only:
            return "likely injection"
        if effective >= REVIEW_SCORE:
            return "review"
        return "low"


def score_region(region: Region, *, head: bytes = b"",
                 rewritten: bool = False,
                 thread_start: bool = False,
                 unpacked: bool = False,
                 allowed: Collection[str] = ()) -> RegionVerdict:
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
    between the same two looks (see :func:`unpacked_regions`). It stacks with
    ``rewritten``, deliberately: the bytes changing is one fact and what they
    changed into is another, and a private region that did both reaches 85.
    ``allowed`` is the rule ids an allowlist entry exempts for the process
    this region belongs to (see :class:`Allowlist`). A rule named there still
    fires and still appears in the reasons, marked; it just does not count
    towards :attr:`RegionVerdict.effective_score`, which is what bands the
    region. Suppressing the verdict rather than the row is deliberate: a JIT
    host exempted from the executable-private rule still scores on an ``MZ``
    header or a NOP sled, so a stomped CLR is not hidden by its own entry.
    Scores are additive and capped at 100. A non-executable or non-committed
    region always scores 0.
    """
    if region.state != MEM_COMMIT or not is_executable(region.protect):
        return RegionVerdict(region.base_addr, region.size, 0, ())

    reasons: list[Reason] = []

    def fired(rule: str, points: int, text: str) -> None:
        reasons.append(Reason(rule, text, points, rule in allowed))

    # Structural: executable memory that is not backed by an image file is the
    # core injection tell (reflective loading, hollowing, raw shellcode).
    if region.type == MEM_PRIVATE:
        fired(RULE_PRIVATE_EXEC, 50,
              f"executable private (unbacked) memory [{ATTACK_INJECTION}]")
    elif region.type == MEM_MAPPED:
        fired(RULE_MAPPED_EXEC, 30,
              "executable mapped memory (possible module stomping) "
              f"[{ATTACK_INJECTION}]")

    if region.protect & _WRITE_EXEC:
        fired(RULE_RWX, 25, "writable + executable (RWX)")

    # Not structural, whatever its place in this function: the map does not
    # answer it, and a thread executing in unbacked memory is the one
    # single-snapshot signal strong enough to reach the top band on its own
    # (see MAP_SHAPE_RULES).
    if thread_start and region.type != MEM_IMAGE:
        fired(RULE_THREAD_START, THREAD_START_POINTS,
              f"a thread starts here, in memory no image backs "
              f"[{ATTACK_INJECTION}]")

    # Content: only meaningful when the region's head was actually read.
    if head[:2] == b"MZ":
        fired(RULE_PE_HEADER, 20,
              f"PE header (MZ) in memory, reflective DLL [{ATTACK_REFLECTIVE}]")
    if longest_nop_run(head) >= NOP_SLED_MIN:
        fired(RULE_NOP_SLED, 10, "NOP sled")
    if head and shannon_entropy(head) >= ENTROPY_PACKED:
        fired(RULE_HIGH_ENTROPY, 10,
              f"high entropy (packed/encrypted) [{ATTACK_PACKING}]")

    # Temporal: the bytes changed but nothing about the region did. A loader
    # that overwrites an existing executable region never allocates and never
    # flips a protection, so this is the only signal it leaves. JIT engines
    # rewrite private code legitimately; image code is not rewritten at all.
    if unpacked:
        fired(RULE_UNPACKED, UNPACKED_POINTS,
              "entropy fell from packed to code-like, unpacked in place "
              f"[{ATTACK_PACKING}]")

    if rewritten:
        if region.type == MEM_IMAGE:
            fired(RULE_IMAGE_REWRITTEN, IMAGE_REWRITTEN_POINTS,
                  "image code rewritten in memory (inline hook or module "
                  f"stomping) [{ATTACK_INJECTION}]")
        else:
            fired(RULE_REWRITTEN, REWRITTEN_POINTS,
                  "executable memory rewritten in place "
                  f"[{ATTACK_INJECTION}]")

    score = sum(r.points for r in reasons)
    return RegionVerdict(
        region.base_addr, region.size, min(score, 100), tuple(reasons)
    )


def rewritten_regions(prev_regions: Sequence[Region],
                      prev_digests: dict[int, bytes],
                      curr_regions: Sequence[Region],
                      curr_digests: dict[int, bytes]) -> set[int]:
    """Base addresses of executable regions rewritten between two looks.

    The two looks are consecutive samples in playback and consecutive live
    refreshes while watching; the comparison is the same either way. A digest
    is whatever identifies a head's content: the stored SHA-256 in playback,
    the head bytes themselves in live mode, where they are already in memory
    for the entropy rule. Only equality is asked of it, so either works.

    A region counts when it is committed and executable in both looks with
    the same base, size and protection, both looks captured its head, and
    the two digests differ. Anything else is not this detector's business: a
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
        old = prev_digests.get(curr.base_addr)
        new = curr_digests.get(curr.base_addr)
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

    ``changed`` is the set of regions rewritten between the same two looks
    (see :func:`rewritten_regions`), which is the only place this can happen:
    a head whose bytes did not change cannot have changed entropy. Scanning
    only those keeps the cost proportional to what moved rather than to the
    size of the map, which is what makes the rule affordable once a second in
    live mode. Pass the regions that changed on this look, not a set carried
    over from an earlier one, or the two heads compared are the same bytes.

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
