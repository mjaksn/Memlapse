"""Tests for the region table model and the region/hex inspector view."""

import pytest

import memlapse.ui.region_view as region_view_mod
from memlapse.ui.region_view import RegionTableModel, RegionView, _fmt_size
from memlapse.win32.memory import ProcessAccessError


def test_fmt_size():
    assert _fmt_size(0) == "0B"
    assert _fmt_size(512) == "512B"
    assert _fmt_size(4096) == "4.0K"
    assert _fmt_size(1536) == "1.5K"
    assert _fmt_size(5 * 1024 * 1024) == "5.0M"
    assert _fmt_size(2 * 1024**4) == "2.0T"
    assert _fmt_size(3 * 1024**5) == "3.0P"


@pytest.fixture
def rmodel(qapp):
    return RegionTableModel()


def test_region_model(rmodel, sample_regions):
    from PySide6.QtCore import Qt, QModelIndex
    rmodel.set_regions(sample_regions)
    assert rmodel.rowCount() == 2
    assert rmodel.columnCount() == 6
    assert rmodel.headerData(0, Qt.Horizontal, Qt.DisplayRole) == "Base Address"
    assert rmodel.headerData(5, Qt.Horizontal, Qt.DisplayRole) == "Score"
    assert rmodel.headerData(0, Qt.Vertical, Qt.DisplayRole) is None
    assert rmodel.data(rmodel.index(0, 0), Qt.DisplayRole) == "0x000000010000"
    assert rmodel.data(rmodel.index(0, 1), Qt.DisplayRole) == "4.0K"
    assert rmodel.data(rmodel.index(0, 2), Qt.DisplayRole) == "Commit"
    # Both sample regions are non-executable -> benign: blank score, no colour.
    assert rmodel.data(rmodel.index(0, 5), Qt.DisplayRole) == ""
    assert rmodel.data(rmodel.index(0, 0), Qt.BackgroundRole) is None
    # Size column is right-aligned; other role/invalid index -> None.
    from PySide6.QtCore import Qt as _Qt
    assert rmodel.data(rmodel.index(0, 1), _Qt.TextAlignmentRole) is not None
    assert rmodel.data(QModelIndex()) is None
    # A role we don't handle returns None.
    assert rmodel.data(rmodel.index(0, 0), Qt.DecorationRole) is None
    assert rmodel.region_at(5) is None
    assert rmodel.region_at(0) is sample_regions[0]


def test_region_model_flags_suspicious_region(rmodel):
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QColor
    from memlapse.model.region import (
        MEM_COMMIT, MEM_PRIVATE, PAGE_EXECUTE_READ, Region,
    )
    r = Region(0x30000, 4096, MEM_COMMIT, PAGE_EXECUTE_READ, MEM_PRIVATE)
    rmodel.set_regions([r])
    # Executable private memory scores 50 (structural, no head bytes needed).
    assert rmodel.data(rmodel.index(0, 5), Qt.DisplayRole) == "50"
    assert rmodel.data(rmodel.index(0, 5), Qt.TextAlignmentRole) is not None
    bg = rmodel.data(rmodel.index(0, 0), Qt.BackgroundRole)
    assert isinstance(bg, QColor)
    assert "unbacked" in rmodel.data(rmodel.index(0, 0), Qt.ToolTipRole)
    # A flagged row still returns None for roles we don't special-case.
    assert rmodel.data(rmodel.index(0, 0), Qt.DecorationRole) is None


def test_region_model_content_score_with_heads(rmodel):
    from PySide6.QtCore import Qt
    from memlapse.model.region import (
        MEM_COMMIT, MEM_PRIVATE, PAGE_EXECUTE_READ, Region,
    )
    r = Region(0x40000, 4096, MEM_COMMIT, PAGE_EXECUTE_READ, MEM_PRIVATE)
    rmodel.set_regions([r], {0x40000: b"MZ" + b"\x00" * 8})
    assert rmodel.data(rmodel.index(0, 5), Qt.DisplayRole) == "70"  # 50 + 20 (MZ)


def _wait_regions(qtbot, view, count):
    """Live enumeration is async; wait for the queued result to land."""
    qtbot.waitUntil(lambda: view.model.rowCount() == count)


def test_on_region_selected_invalid_clears_hex(qtbot, view, sample_regions, monkeypatch):
    from PySide6.QtCore import QModelIndex
    monkeypatch.setattr(region_view_mod, "ProcessMemory",
                        _fake_pm_class(sample_regions, read_bytes=b"QQ"))
    view.show_live_process(1, "p")
    _wait_regions(qtbot, view, 2)
    view.table.selectRow(0)
    assert view.hex.toPlainText() != ""
    view._on_region_selected(QModelIndex(), QModelIndex())  # region None -> clear
    assert view.hex.toPlainText() == ""


# --- fake ProcessMemory used to drive the live view ------------------------
def _fake_pm_class(regions, readable=True, read_bytes=b"\x01\x02\x03\x04"):
    class FakePM:
        def __init__(self, pid, want_read=True):
            self.pid = pid
            self.can_read = readable
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def regions(self, include_free=False):
            return list(regions)
        def read(self, addr, size):
            return read_bytes
    return FakePM


@pytest.fixture
def view(qtbot):
    v = RegionView()
    qtbot.addWidget(v)
    return v


def test_show_live_process_lists_regions(qtbot, view, sample_regions, monkeypatch):
    monkeypatch.setattr(region_view_mod, "ProcessMemory",
                        _fake_pm_class(sample_regions))
    view.show_live_process(1234, "proc.exe")
    _wait_regions(qtbot, view, 2)
    assert "2 regions" in view.header.text()
    assert "no read access" not in view.header.text()


def test_show_live_process_map_only(qtbot, view, sample_regions, monkeypatch):
    monkeypatch.setattr(region_view_mod, "ProcessMemory",
                        _fake_pm_class(sample_regions, readable=False))
    view.show_live_process(1234, "proc.exe")
    _wait_regions(qtbot, view, 2)
    assert "no read access" in view.header.text()


def test_show_live_process_access_error(qtbot, view, monkeypatch):
    class Boom:
        def __init__(self, *a, **k):
            raise ProcessAccessError("denied")
    monkeypatch.setattr(region_view_mod, "ProcessMemory", Boom)
    view.show_live_process(1234, "proc.exe")
    qtbot.waitUntil(lambda: "cannot open" in view.header.text())
    assert view.model.rowCount() == 0


def test_stale_load_result_is_ignored(qtbot, view, sample_regions, monkeypatch):
    """A late enumeration for a superseded selection must not overwrite the view."""
    monkeypatch.setattr(region_view_mod, "ProcessMemory",
                        _fake_pm_class(sample_regions))
    view.show_live_process(1234, "proc.exe")
    stale_req = view._load_seq
    _wait_regions(qtbot, view, 2)
    # Simulate the first (now stale) load arriving after a newer selection.
    view.show_live_process(5678, "other.exe")  # bumps _load_seq
    view._on_regions_loaded(stale_req, [], True)
    assert "other.exe" in view.header.text()  # header reflects the newest request


def test_stale_failed_result_is_ignored(qtbot, view, sample_regions, monkeypatch):
    """A late failure for a superseded selection must not touch the view."""
    monkeypatch.setattr(region_view_mod, "ProcessMemory",
                        _fake_pm_class(sample_regions))
    view.show_live_process(1234, "proc.exe")
    _wait_regions(qtbot, view, 2)
    header = view.header.text()
    view._on_regions_failed(view._load_seq - 1, "late error")  # stale req id
    assert view.header.text() == header
    assert view.model.rowCount() == 2


def test_region_load_task_reports_unexpected_error(qapp, monkeypatch):
    """The worker turns any unexpected error into a failed signal, not a crash."""
    class Boom:
        def __init__(self, *a, **k):
            raise ValueError("kaboom")
    monkeypatch.setattr(region_view_mod, "ProcessMemory", Boom)
    task = region_view_mod._RegionLoadTask(7, 1234)
    captured = []
    task.signals.failed.connect(lambda rid, msg: captured.append((rid, msg)))
    task.run()
    assert captured == [(7, "kaboom")]


def test_selecting_readable_region_shows_hexdump(qtbot, view, sample_regions, monkeypatch):
    monkeypatch.setattr(region_view_mod, "ProcessMemory",
                        _fake_pm_class(sample_regions, read_bytes=b"ABCD"))
    view.show_live_process(1234, "proc.exe")
    _wait_regions(qtbot, view, 2)
    view.table.selectRow(0)  # readable region
    assert "ABCD" in view.hex.toPlainText()


def test_selecting_unreadable_region_notes_it(qtbot, view, sample_regions, monkeypatch):
    monkeypatch.setattr(region_view_mod, "ProcessMemory",
                        _fake_pm_class(sample_regions))
    view.show_live_process(1234, "proc.exe")
    _wait_regions(qtbot, view, 2)
    view.table.selectRow(1)  # PAGE_NOACCESS region
    assert "not readable" in view.hex.toPlainText()


def test_selection_read_failure(qtbot, view, sample_regions, monkeypatch):
    monkeypatch.setattr(region_view_mod, "ProcessMemory",
                        _fake_pm_class(sample_regions))
    view.show_live_process(1234, "proc.exe")
    _wait_regions(qtbot, view, 2)

    class Boom:
        def __init__(self, *a, **k):
            raise ProcessAccessError("gone")
    monkeypatch.setattr(region_view_mod, "ProcessMemory", Boom)
    view.table.selectRow(0)
    assert "read failed" in view.hex.toPlainText()


def test_playback_mode_regions_and_no_hex(view, sample_regions):
    view.show_recorded_regions(sample_regions, "Recording #1")
    assert view.model.rowCount() == 2
    assert view.header.text() == "Recording #1"
    assert "live only" in view.hex.toPlainText()
    # Selecting in playback mode must not attempt a live read.
    view.table.selectRow(0)
    assert "live only" in view.hex.toPlainText()


def test_clearing_regions_clears_hex(qtbot, view, sample_regions, monkeypatch):
    monkeypatch.setattr(region_view_mod, "ProcessMemory",
                        _fake_pm_class(sample_regions, read_bytes=b"XY"))
    view.show_live_process(1234, "proc.exe")
    _wait_regions(qtbot, view, 2)
    view.table.selectRow(0)
    assert view.hex.toPlainText() != ""
    # Emptying the model deselects -> hex is cleared.
    view.model.set_regions([])
    assert view.hex.toPlainText() == ""


# --- rewritten regions feed the Score column ---------------------------------
def _exec_private(base=0x40000):
    from memlapse.model.region import MEM_COMMIT, MEM_PRIVATE, PAGE_EXECUTE_READ, Region
    return Region(base, 4096, MEM_COMMIT, PAGE_EXECUTE_READ, MEM_PRIVATE)


def test_region_model_rewritten_adds_points(rmodel):
    from PySide6.QtCore import Qt
    rmodel.set_regions([_exec_private()], None, {0x40000})
    assert rmodel.data(rmodel.index(0, 5), Qt.DisplayRole) == "65"  # 50 + 15 rewritten
    rmodel.set_regions([_exec_private()], None, {0x99999})  # some other region changed
    assert rmodel.data(rmodel.index(0, 5), Qt.DisplayRole) == "50"


def test_show_recorded_regions_passes_rewritten_through(view):
    from PySide6.QtCore import Qt
    view.show_recorded_regions([_exec_private()], "Recording #1", None, {0x40000})
    assert view.model.data(view.model.index(0, 5), Qt.DisplayRole) == "65"
    assert "rewritten" in view.model.data(view.model.index(0, 5), Qt.ToolTipRole)


# --- the tooltip leads with the triage band --------------------------------
def test_tooltip_starts_with_the_band(rmodel):
    from PySide6.QtCore import Qt
    from memlapse.model.region import (
        MEM_COMMIT, MEM_PRIVATE, PAGE_EXECUTE_READ, Region,
    )
    rmodel.set_regions([Region(0x40000, 4096, MEM_COMMIT, PAGE_EXECUTE_READ,
                               MEM_PRIVATE)])
    tip = rmodel.data(rmodel.index(0, 0), Qt.ToolTipRole)
    assert tip.startswith("review: ")  # 50 points
    assert "unbacked" in tip
