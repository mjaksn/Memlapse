"""Tests for the region table model and the region/hex inspector view."""

import pytest

import memdo.ui.region_view as region_view_mod
from memdo.ui.region_view import RegionTableModel, RegionView, _fmt_size
from memdo.win32.memory import ProcessAccessError


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
    assert rmodel.columnCount() == 5
    assert rmodel.headerData(0, Qt.Horizontal, Qt.DisplayRole) == "Base Address"
    assert rmodel.headerData(0, Qt.Vertical, Qt.DisplayRole) is None
    assert rmodel.data(rmodel.index(0, 0), Qt.DisplayRole) == "0x000000010000"
    assert rmodel.data(rmodel.index(0, 1), Qt.DisplayRole) == "4.0K"
    assert rmodel.data(rmodel.index(0, 2), Qt.DisplayRole) == "Commit"
    # Size column is right-aligned; other role/invalid index -> None.
    from PySide6.QtCore import Qt as _Qt
    assert rmodel.data(rmodel.index(0, 1), _Qt.TextAlignmentRole) is not None
    assert rmodel.data(QModelIndex()) is None
    # A role we don't handle returns None.
    assert rmodel.data(rmodel.index(0, 0), Qt.DecorationRole) is None
    assert rmodel.region_at(5) is None
    assert rmodel.region_at(0) is sample_regions[0]


def test_on_region_selected_invalid_clears_hex(view, sample_regions, monkeypatch):
    from PySide6.QtCore import QModelIndex
    monkeypatch.setattr(region_view_mod, "ProcessMemory",
                        _fake_pm_class(sample_regions, read_bytes=b"QQ"))
    view.show_live_process(1, "p")
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


def test_show_live_process_lists_regions(view, sample_regions, monkeypatch):
    monkeypatch.setattr(region_view_mod, "ProcessMemory",
                        _fake_pm_class(sample_regions))
    view.show_live_process(1234, "proc.exe")
    assert view.model.rowCount() == 2
    assert "2 regions" in view.header.text()
    assert "no read access" not in view.header.text()


def test_show_live_process_map_only(view, sample_regions, monkeypatch):
    monkeypatch.setattr(region_view_mod, "ProcessMemory",
                        _fake_pm_class(sample_regions, readable=False))
    view.show_live_process(1234, "proc.exe")
    assert "no read access" in view.header.text()


def test_show_live_process_access_error(view, monkeypatch):
    class Boom:
        def __init__(self, *a, **k):
            raise ProcessAccessError("denied")
    monkeypatch.setattr(region_view_mod, "ProcessMemory", Boom)
    view.show_live_process(1234, "proc.exe")
    assert view.model.rowCount() == 0
    assert "cannot open" in view.header.text()


def test_selecting_readable_region_shows_hexdump(view, sample_regions, monkeypatch):
    monkeypatch.setattr(region_view_mod, "ProcessMemory",
                        _fake_pm_class(sample_regions, read_bytes=b"ABCD"))
    view.show_live_process(1234, "proc.exe")
    view.table.selectRow(0)  # readable region
    assert "ABCD" in view.hex.toPlainText()


def test_selecting_unreadable_region_notes_it(view, sample_regions, monkeypatch):
    monkeypatch.setattr(region_view_mod, "ProcessMemory",
                        _fake_pm_class(sample_regions))
    view.show_live_process(1234, "proc.exe")
    view.table.selectRow(1)  # PAGE_NOACCESS region
    assert "not readable" in view.hex.toPlainText()


def test_selection_read_failure(view, sample_regions, monkeypatch):
    monkeypatch.setattr(region_view_mod, "ProcessMemory",
                        _fake_pm_class(sample_regions))
    view.show_live_process(1234, "proc.exe")

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
    assert "not captured" in view.hex.toPlainText()
    # Selecting in playback mode must not attempt a live read.
    view.table.selectRow(0)
    assert "not captured" in view.hex.toPlainText()


def test_clearing_regions_clears_hex(view, sample_regions, monkeypatch):
    monkeypatch.setattr(region_view_mod, "ProcessMemory",
                        _fake_pm_class(sample_regions, read_bytes=b"XY"))
    view.show_live_process(1234, "proc.exe")
    view.table.selectRow(0)
    assert view.hex.toPlainText() != ""
    # Emptying the model deselects -> hex is cleared.
    view.model.set_regions([])
    assert view.hex.toPlainText() == ""
