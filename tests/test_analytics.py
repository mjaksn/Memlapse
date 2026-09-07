"""Tests for the dependency-free analytics helpers."""

import pytest

from memlapse.analytics import (
    ENTROPY_PACKED, Mover, RegionVerdict, SeriesBuffer, is_executable,
    leak_rate_bytes_per_sec, linreg_slope, longest_nop_run, score_region,
    shannon_entropy, top_movers, zscore,
)
from memlapse.model.region import (
    MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE, MEM_RESERVE, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, PAGE_GUARD, PAGE_READONLY, PAGE_READWRITE, Region,
)


def _region(protect, type_, state=MEM_COMMIT, base=0x1000, size=0x2000):
    return Region(base_addr=base, size=size, state=state, protect=protect, type=type_)


# --- SeriesBuffer ----------------------------------------------------------
def test_series_buffer_requires_positive_capacity():
    with pytest.raises(ValueError):
        SeriesBuffer(0)


def test_series_buffer_append_and_accessors():
    b = SeriesBuffer(3)
    assert len(b) == 0
    assert b.latest() is None
    b.append(1, 10.0)
    b.append(2, 20.0)
    assert len(b) == 2
    assert b.times() == [1, 2]
    assert b.values() == [10.0, 20.0]
    assert b.latest() == 20.0


def test_series_buffer_evicts_oldest():
    b = SeriesBuffer(2)
    b.append(1, 1.0)
    b.append(2, 2.0)
    b.append(3, 3.0)  # evicts (1, 1.0)
    assert b.times() == [2, 3]


# --- linreg_slope ----------------------------------------------------------
def test_linreg_slope_normal():
    assert linreg_slope([0, 1, 2], [0, 2, 4]) == pytest.approx(2.0)


def test_linreg_slope_degenerate_cases():
    assert linreg_slope([1], [1]) == 0.0            # < 2 points
    assert linreg_slope([1, 2], [1]) == 0.0         # mismatched lengths
    assert linreg_slope([5, 5, 5], [1, 2, 3]) == 0.0  # no spread in xs


# --- leak_rate_bytes_per_sec ----------------------------------------------
def test_leak_rate_normal():
    times = [0, 1_000_000, 2_000_000]  # microseconds -> 0,1,2 s
    used = [0.0, 100.0, 200.0]
    assert leak_rate_bytes_per_sec(times, used) == pytest.approx(100.0)


def test_leak_rate_too_few_points():
    assert leak_rate_bytes_per_sec([0], [1.0]) == 0.0


# --- zscore ----------------------------------------------------------------
def test_zscore_default_latest():
    # values [0,0,0,3]: mean 0.75, population var 1.6875, std ~1.299
    assert zscore([0.0, 0.0, 0.0, 3.0]) == pytest.approx((3 - 0.75) / (1.6875 ** 0.5))


def test_zscore_explicit_latest():
    assert zscore([1.0, 2.0, 3.0], latest=2.0) == pytest.approx(0.0)


def test_zscore_degenerate_cases():
    assert zscore([1.0]) == 0.0             # < 2 points
    assert zscore([5.0, 5.0, 5.0]) == 0.0   # zero variance


# --- top_movers ------------------------------------------------------------
def test_top_movers_sorted_by_absolute_delta():
    prev = {1: ("a", 100), 2: ("b", 100), 3: ("c", 100)}
    curr = {1: ("a", 150), 2: ("b", 40), 3: ("c", 100)}  # +50, -60, 0
    movers = top_movers(prev, curr)
    assert [m.pid for m in movers] == [2, 1]  # |−60| > |+50|; pid 3 unchanged dropped
    assert movers[0] == Mover(2, "b", -60)


def test_top_movers_ignores_new_pids_and_limits():
    prev = {i: ("p", 0) for i in range(10)}
    curr = {i: ("p", i + 1) for i in range(10)}
    curr[999] = ("new", 500)  # not in prev -> ignored
    movers = top_movers(prev, curr, n=3)
    assert len(movers) == 3
    assert all(m.pid != 999 for m in movers)


# --- is_executable ---------------------------------------------------------
def test_is_executable_true_for_exec_page():
    assert is_executable(PAGE_EXECUTE_READ) is True


def test_is_executable_false_for_non_exec_page():
    assert is_executable(PAGE_READONLY) is False


def test_is_executable_false_for_guarded_exec_page():
    assert is_executable(PAGE_EXECUTE_READ | PAGE_GUARD) is False


# --- shannon_entropy -------------------------------------------------------
def test_shannon_entropy_empty_is_zero():
    assert shannon_entropy(b"") == 0.0


def test_shannon_entropy_uniform_bytes_is_max():
    assert shannon_entropy(bytes(range(256))) == pytest.approx(8.0)


def test_shannon_entropy_single_symbol_is_zero():
    assert shannon_entropy(b"\x00" * 64) == 0.0


# --- longest_nop_run -------------------------------------------------------
def test_longest_nop_run_counts_and_resets():
    assert longest_nop_run(b"\x90\x90\x00\x90") == 2


def test_longest_nop_run_no_nops():
    assert longest_nop_run(b"\x01\x02\x03") == 0


def test_longest_nop_run_empty():
    assert longest_nop_run(b"") == 0


# --- RegionVerdict ---------------------------------------------------------
def test_region_verdict_suspicious_flag():
    assert RegionVerdict(0, 0, 0, ()).suspicious is False
    assert RegionVerdict(0, 0, 10, ("x",)).suspicious is True


# --- score_region ----------------------------------------------------------
def test_score_region_ignores_non_committed():
    v = score_region(_region(PAGE_EXECUTE_READ, MEM_PRIVATE, state=MEM_RESERVE))
    assert v.score == 0 and v.reasons == ()


def test_score_region_ignores_non_executable():
    v = score_region(_region(PAGE_READWRITE, MEM_PRIVATE))
    assert v.score == 0 and v.reasons == ()


def test_score_region_private_exec_is_core_signal():
    v = score_region(_region(PAGE_EXECUTE_READ, MEM_PRIVATE))
    assert v.score == 50
    assert "unbacked" in v.reasons[0]


def test_score_region_mapped_exec_scores_lower():
    v = score_region(_region(PAGE_EXECUTE_READ, MEM_MAPPED))
    assert v.score == 30
    assert "stomping" in v.reasons[0]


def test_score_region_image_exec_is_benign():
    v = score_region(_region(PAGE_EXECUTE_READ, MEM_IMAGE))
    assert v.score == 0 and v.reasons == ()


def test_score_region_rwx_adds_points():
    v = score_region(_region(PAGE_EXECUTE_READWRITE, MEM_PRIVATE))
    assert v.score == 75  # 50 private + 25 RWX
    assert any("RWX" in r for r in v.reasons)


def test_score_region_mz_header_flagged():
    v = score_region(_region(PAGE_EXECUTE_READ, MEM_PRIVATE), head=b"MZ" + b"\x00" * 10)
    assert v.score == 70  # 50 + 20 MZ
    assert any("PE header" in r for r in v.reasons)


def test_score_region_nop_sled_flagged():
    v = score_region(_region(PAGE_EXECUTE_READ, MEM_PRIVATE), head=b"\x90" * 16)
    assert v.score == 60  # 50 + 10 NOP
    assert any("NOP" in r for r in v.reasons)


def test_score_region_high_entropy_flagged():
    v = score_region(_region(PAGE_EXECUTE_READ, MEM_PRIVATE), head=bytes(range(256)))
    assert v.score == 60  # 50 + 10 entropy
    assert any("entropy" in r for r in v.reasons)


def test_score_region_low_entropy_not_flagged():
    v = score_region(_region(PAGE_EXECUTE_READ, MEM_PRIVATE), head=b"\x00" * 64)
    assert v.score == 50
    assert not any("entropy" in r for r in v.reasons)


def test_score_region_caps_at_100():
    head = b"MZ" + b"\x90" * 20 + bytes(range(256))
    v = score_region(_region(PAGE_EXECUTE_READWRITE, MEM_PRIVATE), head=head)
    assert v.score == 100  # 50 + 25 + 20 + 10 + 10 = 115, capped


def test_entropy_packed_threshold_is_below_max():
    assert 0.0 < ENTROPY_PACKED < 8.0


# --- head_hash / rewritten_regions -----------------------------------------
import hashlib  # noqa: E402

from memlapse.analytics import (  # noqa: E402
    IMAGE_REWRITTEN_POINTS, REWRITTEN_POINTS, head_hash, rewritten_regions,
)
from memlapse.model.region import (  # noqa: E402
    MEM_COMMIT as _COMMIT, MEM_IMAGE as _IMAGE, MEM_PRIVATE as _PRIVATE,
    MEM_RESERVE as _RESERVE, PAGE_EXECUTE_READ as _RX, PAGE_READWRITE as _RW,
    Region as _Region,
)


def test_head_hash_is_sha256_digest():
    assert head_hash(b"MZ") == hashlib.sha256(b"MZ").digest()
    assert len(head_hash(b"")) == 32


def _snap(protect=_RX, type=_PRIVATE, size=4096, state=_COMMIT, base=0x1000):
    return _Region(base, size, state, protect, type)


def test_rewritten_regions_flags_changed_hash_with_same_shape():
    found = rewritten_regions([_snap()], {0x1000: b"a"}, [_snap()], {0x1000: b"b"})
    assert found == {0x1000}


def test_rewritten_regions_ignores_equal_hash():
    assert rewritten_regions([_snap()], {0x1000: b"a"}, [_snap()], {0x1000: b"a"}) == set()


def test_rewritten_regions_needs_a_hash_on_both_sides():
    assert rewritten_regions([_snap()], {}, [_snap()], {0x1000: b"b"}) == set()
    assert rewritten_regions([_snap()], {0x1000: b"a"}, [_snap()], {}) == set()


def test_rewritten_regions_ignores_region_that_just_appeared():
    assert rewritten_regions([], {}, [_snap()], {0x1000: b"b"}) == set()


def test_rewritten_regions_ignores_size_change():
    found = rewritten_regions([_snap(size=4096)], {0x1000: b"a"},
                              [_snap(size=8192)], {0x1000: b"b"})
    assert found == set()


def test_rewritten_regions_ignores_protection_change():
    # RW to RX with new bytes is the transition detector's case, not this one.
    found = rewritten_regions([_snap(protect=_RW)], {0x1000: b"a"},
                              [_snap(protect=_RX)], {0x1000: b"b"})
    assert found == set()


def test_rewritten_regions_ignores_non_executable_and_reserved():
    assert rewritten_regions([_snap(protect=_RW)], {0x1000: b"a"},
                             [_snap(protect=_RW)], {0x1000: b"b"}) == set()
    assert rewritten_regions([_snap(state=_RESERVE)], {0x1000: b"a"},
                             [_snap(state=_RESERVE)], {0x1000: b"b"}) == set()


def test_rewritten_regions_checks_each_region_independently():
    prev = [_snap(base=0x1000), _snap(base=0x2000)]
    curr = [_snap(base=0x1000), _snap(base=0x2000)]
    found = rewritten_regions(prev, {0x1000: b"a", 0x2000: b"c"},
                              curr, {0x1000: b"b", 0x2000: b"c"})
    assert found == {0x1000}


def test_score_region_rewritten_private_adds_points():
    v = score_region(_snap(), rewritten=True)
    assert v.score == 50 + REWRITTEN_POINTS
    assert any("rewritten since previous sample" in r for r in v.reasons)


def test_score_region_rewritten_image_weighs_more():
    v = score_region(_snap(type=_IMAGE), rewritten=True)
    assert v.score == IMAGE_REWRITTEN_POINTS
    assert v.reasons == (
        "image code rewritten in memory (inline hook or module stomping) [T1055]",
    )


def test_score_region_rewritten_ignored_for_non_executable():
    v = score_region(_snap(protect=_RW), rewritten=True)
    assert v.score == 0 and v.reasons == ()


# --- ATT&CK technique tags on the reason strings ---------------------------
def test_reasons_carry_their_attack_technique():
    from memlapse.analytics import (
        ATTACK_INJECTION, ATTACK_PACKING, ATTACK_REFLECTIVE,
    )
    v = score_region(_snap(), head=b"MZ" + bytes(range(256)))
    tagged = {r.rsplit("[", 1)[-1].rstrip("]") for r in v.reasons if r.endswith("]")}
    assert tagged == {ATTACK_INJECTION, ATTACK_REFLECTIVE, ATTACK_PACKING}
    mapped = score_region(_snap(type=MEM_MAPPED))
    assert mapped.reasons[0].endswith(f"[{ATTACK_INJECTION}]")


def test_rwx_and_nop_sled_carry_no_technique():
    """Neither maps to an ATT&CK technique, so neither invents one."""
    reasons = score_region(_snap(protect=PAGE_EXECUTE_READWRITE), head=b"\x90" * 64).reasons
    assert [r for r in reasons if not r.endswith("]")] == [
        "writable + executable (RWX)", "NOP sled",
    ]


# --- triage bands ----------------------------------------------------------
def test_verdict_band_edges():
    from memlapse.analytics import LIKELY_SCORE, REVIEW_SCORE
    band = lambda score: RegionVerdict(0, 0, score, ()).band
    assert band(0) == ""
    assert band(1) == "low"
    assert band(REVIEW_SCORE - 1) == "low"
    assert band(REVIEW_SCORE) == "review"
    assert band(LIKELY_SCORE - 1) == "review"
    assert band(LIKELY_SCORE) == "likely injection"
    assert band(100) == "likely injection"


def test_rewritten_image_region_lands_in_the_review_band():
    """40 points is deliberately review, not likely injection: EDR hooks live here."""
    assert score_region(_snap(type=_IMAGE), rewritten=True).band == "review"


# --- thread start addresses ------------------------------------------------
def test_regions_with_thread_starts_matches_the_containing_region():
    from memlapse.analytics import regions_with_thread_starts
    regions = [_snap(base=0x1000, size=0x1000), _snap(base=0x9000, size=0x1000)]
    assert regions_with_thread_starts(regions, [0x1500]) == {0x1000}
    assert regions_with_thread_starts(regions, [0x1000]) == {0x1000}   # first byte
    assert regions_with_thread_starts(regions, [0x1FFF]) == {0x1000}   # last byte
    assert regions_with_thread_starts(regions, [0x2000]) == set()      # one past
    assert regions_with_thread_starts(regions, [0x1500, 0x9500]) == {0x1000, 0x9000}


def test_regions_with_thread_starts_ignores_addresses_in_no_region():
    """The map and the thread list are read a moment apart."""
    from memlapse.analytics import regions_with_thread_starts
    assert regions_with_thread_starts([_snap()], [0xDEAD0000]) == set()
    assert regions_with_thread_starts([], [0x1000]) == set()


def test_score_region_thread_start_in_unbacked_memory():
    from memlapse.analytics import THREAD_START_POINTS
    v = score_region(_snap(), thread_start=True)
    assert v.score == 50 + THREAD_START_POINTS
    assert v.band == "likely injection"
    assert any("a thread starts here" in r for r in v.reasons)


def test_score_region_thread_start_in_an_image_is_normal():
    """Every legitimate thread starts inside a mapped image."""
    v = score_region(_snap(type=_IMAGE), thread_start=True)
    assert v.score == 0 and v.reasons == ()
