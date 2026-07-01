"""Tests for the dependency-free data models."""

from memdo.model.process import ProcessInfo
from memdo.model.region import (
    MEM_COMMIT, MEM_FREE, MEM_MAPPED, MEM_RESERVE, PAGE_EXECUTE_READ,
    PAGE_GUARD, PAGE_NOACCESS, PAGE_NOCACHE, PAGE_READWRITE, PAGE_WRITECOMBINE,
    Region, protect_str,
)


def test_process_label():
    p = ProcessInfo(pid=42, name="x.exe", username="me", num_threads=1,
                    wset_bytes=0, private_bytes=0)
    assert p.label == "x.exe (42)"


def test_region_geometry_and_labels(make_region):
    r = make_region(base_addr=0x1000, size=0x2000)
    assert r.end_addr == 0x3000
    assert r.state_str == "Commit"
    assert r.type_str == "Private"
    assert r.protect_str == "RW-"


def test_region_state_and_type_strings():
    assert Region(0, 1, MEM_RESERVE, 0, MEM_MAPPED).state_str == "Reserve"
    assert Region(0, 1, MEM_FREE, 0, 0).state_str == "Free"
    # Unknown state/type fall back to hex; type 0 renders empty.
    r = Region(0, 1, 0x999, PAGE_READWRITE, 0)
    assert r.state_str == hex(0x999)
    assert r.type_str == ""
    assert Region(0, 1, MEM_COMMIT, 0, 0x777).type_str == hex(0x777)


def test_protect_str_variants():
    assert protect_str(0) == "—"
    assert protect_str(PAGE_READWRITE) == "RW-"
    assert protect_str(PAGE_EXECUTE_READ) == "R-X"
    assert protect_str(PAGE_NOACCESS) == "---"
    # Guard / no-cache / write-combine flags are appended.
    assert protect_str(PAGE_EXECUTE_READ | PAGE_GUARD) == "R-X +G"
    assert protect_str(PAGE_READWRITE | PAGE_NOCACHE) == "RW- +NC"
    assert protect_str(PAGE_READWRITE | PAGE_WRITECOMBINE) == "RW- +WC"
    # Unknown base protection renders as hex.
    assert protect_str(0x55) == "0x55"


def test_is_readable():
    assert Region(0, 1, MEM_COMMIT, PAGE_READWRITE, MEM_COMMIT).is_readable
    # Not committed -> not readable.
    assert not Region(0, 1, MEM_RESERVE, PAGE_READWRITE, 0).is_readable
    # No-access / guard pages -> not readable even when committed.
    assert not Region(0, 1, MEM_COMMIT, PAGE_NOACCESS, 0).is_readable
    assert not Region(0, 1, MEM_COMMIT, PAGE_READWRITE | PAGE_GUARD, 0).is_readable
