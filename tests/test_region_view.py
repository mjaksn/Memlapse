"""Tests for the region table model and the region/hex inspector view."""

import os

import pytest


@pytest.fixture(autouse=True)
def _no_thread_query(monkeypatch):
    """Keep the live loader off the real system table unless a test wants it."""
    import memlapse.ui.region_view as mod
    monkeypatch.setattr(mod, "start_addresses", lambda pid: {})

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
def _fake_pm_class(regions, readable=True, read_bytes=b"\x01\x02\x03\x04",
                   created=1000):
    class FakePM:
        instance_created = created   # a test can move this to fake pid reuse

        def __init__(self, pid, want_read=True):
            self.pid = pid
            self.can_read = readable
        def creation_time(self):
            return type(self).instance_created
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
    view._on_regions_loaded(stale_req, [], {}, set(), 1000, True)
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


def test_the_thread_walk_happens_while_the_process_handle_is_open(qapp,
                                                                  monkeypatch):
    """The pid stays pinned across the walk, or the starts can come from the
    process that inherited the number."""
    order = []
    pm_class = _fake_pm_class([])

    class TrackingPM(pm_class):
        def __exit__(self, *a):
            order.append("handle closed")
            return super().__exit__(*a)

    monkeypatch.setattr(region_view_mod, "ProcessMemory", TrackingPM)
    monkeypatch.setattr(region_view_mod, "start_addresses",
                        lambda pid: order.append("thread walk") or {})
    region_view_mod._RegionLoadTask(1, 1234).run()
    assert order == ["thread walk", "handle closed"]


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


def _exec_private_rwx(base=0x40000):
    """50 + 25 = 75 on the map alone, which is where the band rule bites."""
    from memlapse.model.region import (
        MEM_COMMIT, MEM_PRIVATE, PAGE_EXECUTE_READWRITE, Region)
    return Region(base, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE, MEM_PRIVATE)


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


# --- a thread starting in a region feeds the Score column ------------------
def test_region_model_scores_a_thread_start(rmodel):
    from PySide6.QtCore import Qt
    from memlapse.model.region import (
        MEM_COMMIT, MEM_PRIVATE, PAGE_EXECUTE_READ, Region,
    )
    region = Region(0x40000, 4096, MEM_COMMIT, PAGE_EXECUTE_READ, MEM_PRIVATE)
    rmodel.set_regions([region], thread_starts={0x40000})
    assert rmodel.data(rmodel.index(0, 5), Qt.DisplayRole) == "75"  # 50 + 25
    assert "a thread starts here" in rmodel.data(rmodel.index(0, 0), Qt.ToolTipRole)


def test_live_load_carries_thread_starts_into_the_model(qtbot, view, monkeypatch):
    from PySide6.QtCore import Qt
    from memlapse.model.region import (
        MEM_COMMIT, MEM_PRIVATE, PAGE_EXECUTE_READ, Region,
    )
    region = Region(0x40000, 4096, MEM_COMMIT, PAGE_EXECUTE_READ, MEM_PRIVATE)
    monkeypatch.setattr(region_view_mod, "ProcessMemory", _fake_pm_class([region]))
    monkeypatch.setattr(region_view_mod, "start_addresses",
                        lambda pid: {5: 0x40100})
    view.show_live_process(1234, "proc.exe")
    _wait_regions(qtbot, view, 1)
    assert view.model.data(view.model.index(0, 5), Qt.DisplayRole) == "75"


def test_show_recorded_regions_passes_thread_starts_through(view):
    from PySide6.QtCore import Qt
    from memlapse.model.region import (
        MEM_COMMIT, MEM_PRIVATE, PAGE_EXECUTE_READ, Region,
    )
    region = Region(0x40000, 4096, MEM_COMMIT, PAGE_EXECUTE_READ, MEM_PRIVATE)
    view.show_recorded_regions([region], "Recording #1", None, None, {0x40000})
    assert view.model.data(view.model.index(0, 5), Qt.DisplayRole) == "75"


# --- the unpacking signal reaches the Score column -------------------------
def test_region_model_scores_an_unpacked_region(rmodel):
    from PySide6.QtCore import Qt
    from memlapse.model.region import (
        MEM_COMMIT, MEM_PRIVATE, PAGE_EXECUTE_READ, Region,
    )
    region = Region(0x40000, 4096, MEM_COMMIT, PAGE_EXECUTE_READ, MEM_PRIVATE)
    rmodel.set_regions([region], unpacked={0x40000})
    assert rmodel.data(rmodel.index(0, 5), Qt.DisplayRole) == "70"  # 50 + 20
    tip = rmodel.data(rmodel.index(0, 0), Qt.ToolTipRole)
    assert "unpacked in place" in tip


def test_show_recorded_regions_passes_unpacked_through(view):
    from PySide6.QtCore import Qt
    from memlapse.model.region import (
        MEM_COMMIT, MEM_PRIVATE, PAGE_EXECUTE_READ, Region,
    )
    region = Region(0x40000, 4096, MEM_COMMIT, PAGE_EXECUTE_READ, MEM_PRIVATE)
    view.show_recorded_regions([region], "Recording #1", None, None, None,
                               {0x40000})
    assert view.model.data(view.model.index(0, 5), Qt.DisplayRole) == "70"


# --- saving a region's bytes -----------------------------------------------
def _dialog(monkeypatch, path):
    """Patch the save dialog to answer with ``path`` (empty means cancelled)."""
    monkeypatch.setattr(region_view_mod.QFileDialog, "getSaveFileName",
                        staticmethod(lambda *a, **k: (path, "")))


def test_save_region_writes_the_bytes(qtbot, view, sample_regions, monkeypatch,
                                      tmp_path):
    whole = b"A" * 4096  # the first sample region is 4096 bytes
    monkeypatch.setattr(region_view_mod, "ProcessMemory",
                        _fake_pm_class(sample_regions, read_bytes=whole))
    view.show_live_process(1234, "proc.exe")
    _wait_regions(qtbot, view, 2)
    view.table.selectRow(0)
    target = tmp_path / "region.bin"
    _dialog(monkeypatch, str(target))
    view.save_selected_region()
    assert target.read_bytes() == whole
    assert view.header.text() == "saved 4.0K from 0x000000010000"


# --- pid reuse: the bytes must come from the process that was selected ------
def test_a_reused_pid_is_refused_for_a_save(qtbot, view, sample_regions,
                                            monkeypatch, tmp_path):
    """The target exited and something else now answers to its pid."""
    pm_class = _fake_pm_class(sample_regions, read_bytes=b"B" * 4096)
    monkeypatch.setattr(region_view_mod, "ProcessMemory", pm_class)
    view.show_live_process(1234, "proc.exe")
    _wait_regions(qtbot, view, 2)
    view.table.selectRow(0)
    target = tmp_path / "region.bin"
    _dialog(monkeypatch, str(target))

    pm_class.instance_created = 9999    # a different process, same pid
    view.save_selected_region()
    assert "save refused" in view.header.text()
    assert "belongs to another process" in view.header.text()
    assert not target.exists()          # nothing of the replacement was kept


def test_a_reused_pid_is_refused_for_the_hex_preview(qtbot, view, sample_regions,
                                                     monkeypatch):
    pm_class = _fake_pm_class(sample_regions, read_bytes=b"ABCD")
    monkeypatch.setattr(region_view_mod, "ProcessMemory", pm_class)
    view.show_live_process(1234, "proc.exe")
    _wait_regions(qtbot, view, 2)
    view.table.selectRow(0)
    assert "ABCD" in view.hex.toPlainText()

    pm_class.instance_created = 9999
    view.table.selectRow(1)   # move away and back, so the preview is re-read
    view.table.selectRow(0)
    assert "belongs to another process" in view.hex.toPlainText()


def test_save_region_reports_a_short_read(qtbot, view, sample_regions,
                                          monkeypatch, tmp_path):
    """The target gave back less than the region holds, which is its doing."""
    monkeypatch.setattr(region_view_mod, "ProcessMemory",
                        _fake_pm_class(sample_regions, read_bytes=b"PAYLOAD"))
    view.show_live_process(1234, "proc.exe")
    _wait_regions(qtbot, view, 2)
    view.table.selectRow(0)
    target = tmp_path / "region.bin"
    _dialog(monkeypatch, str(target))
    view.save_selected_region()
    assert target.read_bytes() == b"PAYLOAD"
    assert "short read of 4.0K" in view.header.text()


def test_save_region_reports_the_cap(qtbot, view, sample_regions, monkeypatch,
                                     tmp_path):
    monkeypatch.setattr(region_view_mod, "ProcessMemory",
                        _fake_pm_class(sample_regions, read_bytes=b"12345678"))
    monkeypatch.setattr(region_view_mod, "REGION_DUMP_MAX", 8)
    view.show_live_process(1234, "proc.exe")
    _wait_regions(qtbot, view, 2)
    view.table.selectRow(0)  # a 4096-byte region
    target = tmp_path / "region.bin"
    _dialog(monkeypatch, str(target))
    view.save_selected_region()
    assert len(target.read_bytes()) == 8
    assert "capped at 8B" in view.header.text()
    assert "short read" not in view.header.text()   # the cap was met exactly


def test_save_region_reports_the_cap_and_a_short_read_together(qtbot, view,
                                                               sample_regions,
                                                               monkeypatch,
                                                               tmp_path):
    """Our cap must not hide the target's short read: both, or neither is true."""
    monkeypatch.setattr(region_view_mod, "ProcessMemory",
                        _fake_pm_class(sample_regions, read_bytes=b"123"))
    monkeypatch.setattr(region_view_mod, "REGION_DUMP_MAX", 8)
    view.show_live_process(1234, "proc.exe")
    _wait_regions(qtbot, view, 2)
    view.table.selectRow(0)  # a 4096-byte region, capped to 8, only 3 readable
    target = tmp_path / "region.bin"
    _dialog(monkeypatch, str(target))
    view.save_selected_region()
    assert target.read_bytes() == b"123"
    text = view.header.text()
    assert "capped at 8B of 4.0K" in text
    assert "short read of 8B" in text


def test_save_region_without_a_selection(view, monkeypatch, tmp_path):
    _dialog(monkeypatch, str(tmp_path / "unused.bin"))
    view.save_selected_region()
    assert "Select a region first" in view.header.text()
    assert not (tmp_path / "unused.bin").exists()


def test_save_region_is_refused_in_playback(view, sample_regions, monkeypatch,
                                            tmp_path):
    view.show_recorded_regions(sample_regions, "Recording #1")
    view.table.selectRow(0)
    _dialog(monkeypatch, str(tmp_path / "unused.bin"))
    view.save_selected_region()
    assert "live only" in view.header.text()
    assert not (tmp_path / "unused.bin").exists()


def test_save_region_cancelled_writes_nothing(qtbot, view, sample_regions,
                                              monkeypatch):
    monkeypatch.setattr(region_view_mod, "ProcessMemory",
                        _fake_pm_class(sample_regions, read_bytes=b"X"))
    view.show_live_process(1234, "proc.exe")
    _wait_regions(qtbot, view, 2)
    view.table.selectRow(0)
    header = view.header.text()
    _dialog(monkeypatch, "")
    view.save_selected_region()
    assert view.header.text() == header  # nothing happened, nothing reported


def test_save_region_read_failure_and_empty_read(qtbot, view, sample_regions,
                                                 monkeypatch, tmp_path):
    monkeypatch.setattr(region_view_mod, "ProcessMemory",
                        _fake_pm_class(sample_regions, read_bytes=b"X"))
    view.show_live_process(1234, "proc.exe")
    _wait_regions(qtbot, view, 2)
    view.table.selectRow(0)
    target = tmp_path / "region.bin"
    _dialog(monkeypatch, str(target))

    monkeypatch.setattr(region_view_mod, "ProcessMemory",
                        _fake_pm_class(sample_regions, read_bytes=b""))
    view.save_selected_region()
    assert "nothing readable" in view.header.text()
    assert not target.exists()

    class Boom:
        def __init__(self, *a, **k):
            raise ProcessAccessError("gone")
    monkeypatch.setattr(region_view_mod, "ProcessMemory", Boom)
    view.save_selected_region()
    assert "save failed" in view.header.text()
    assert not target.exists()


def test_save_region_reports_a_write_failure(qtbot, view, sample_regions,
                                             monkeypatch, tmp_path):
    """A full disk is reported, and the file already there is left alone."""
    monkeypatch.setattr(region_view_mod, "ProcessMemory",
                        _fake_pm_class(sample_regions, read_bytes=b"A" * 4096))
    view.show_live_process(1234, "proc.exe")
    _wait_regions(qtbot, view, 2)
    view.table.selectRow(0)
    target = tmp_path / "region.bin"
    target.write_bytes(b"evidence from an earlier save")
    _dialog(monkeypatch, str(target))

    real_fdopen = os.fdopen

    class _FullDisk:
        """Takes the real fd, writes a little, then fails like a full disk."""

        def __init__(self, fd):
            self._fd = fd

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            os.close(self._fd)   # release it so the cleanup can remove the file
            return False

        def write(self, payload):
            os.write(self._fd, payload[:16])   # some bytes reach the temp file
            raise OSError(28, "No space left on device")

    monkeypatch.setattr(region_view_mod.os, "fdopen",
                        lambda fd, mode: _FullDisk(fd))
    assert real_fdopen is not region_view_mod.os.fdopen

    view.save_selected_region()
    assert "save failed" in view.header.text()
    assert "No space left on device" in view.header.text()
    # The chosen file is untouched, and no partial file is left beside it.
    assert target.read_bytes() == b"evidence from an earlier save"
    assert [f.name for f in tmp_path.iterdir()] == ["region.bin"]


def test_save_region_reports_a_failure_before_the_write(qtbot, view,
                                                        sample_regions,
                                                        monkeypatch, tmp_path):
    """A destination that cannot be opened at all reports the same way."""
    monkeypatch.setattr(region_view_mod, "ProcessMemory",
                        _fake_pm_class(sample_regions, read_bytes=b"A" * 4096))
    view.show_live_process(1234, "proc.exe")
    _wait_regions(qtbot, view, 2)
    view.table.selectRow(0)
    _dialog(monkeypatch, str(tmp_path / "region.bin"))

    def denied(*a, **k):
        raise OSError(13, "Permission denied")
    monkeypatch.setattr(region_view_mod.tempfile, "mkstemp", denied)

    view.save_selected_region()
    assert "save failed" in view.header.text()
    assert "Permission denied" in view.header.text()
    assert list(tmp_path.iterdir()) == []


# --- live mode: heads, the refresh timer and the rewritten-while-watching set ---
class _MutablePM:
    """Fake ProcessMemory whose map and per-address reads a test can change."""

    regions_now: list = []
    heads_now: dict = {}
    instance_created = 1000   # a test can move this to fake pid reuse

    def __init__(self, pid, want_read=True):
        self.pid = pid
        self.can_read = True

    def creation_time(self):
        return type(self).instance_created

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def regions(self, include_free=False):
        return list(type(self).regions_now)

    def read(self, addr, size):
        return type(self).heads_now.get(addr, b"")


def _wait_load(qtbot, view):
    qtbot.waitUntil(lambda: not view._in_flight)


@pytest.fixture
def live_view(qtbot, monkeypatch):
    """A visible live view on a fake process, with the timer under test control."""
    from PySide6.QtCore import Qt
    _MutablePM.regions_now = [_exec_private()]
    _MutablePM.heads_now = {0x40000: b"aaa"}
    _MutablePM.instance_created = 1000
    monkeypatch.setattr(region_view_mod, "ProcessMemory", _MutablePM)
    v = RegionView()
    qtbot.addWidget(v)
    v.show()
    v.show_live_process(1234, "proc.exe")
    v._refresh.stop()  # ticks are driven by hand so the sequence is deterministic
    _wait_load(qtbot, v)

    def score():
        return v.model.data(v.model.index(0, 5), Qt.DisplayRole)

    def tick():
        v._on_refresh_tick()
        _wait_load(qtbot, v)

    return v, score, tick


def test_load_task_emits_heads_of_executable_regions(qapp, monkeypatch):
    _MutablePM.regions_now = [_exec_private(), _exec_private(0x50000)]
    _MutablePM.heads_now = {0x40000: b"MZ"}
    _MutablePM.instance_created = 1000
    monkeypatch.setattr(region_view_mod, "ProcessMemory", _MutablePM)
    task = region_view_mod._RegionLoadTask(3, 1234)
    got = []
    task.signals.loaded.connect(lambda *args: got.append(args))
    task.run()
    assert got == [(3, _MutablePM.regions_now, {0x40000: b"MZ"}, set(),
                    1000, True)]


def test_live_heads_feed_the_content_signals(qtbot, monkeypatch):
    _MutablePM.regions_now = [_exec_private()]
    _MutablePM.heads_now = {0x40000: b"MZ" + b"\x00" * 8}
    monkeypatch.setattr(region_view_mod, "ProcessMemory", _MutablePM)
    from PySide6.QtCore import Qt
    v = RegionView()
    qtbot.addWidget(v)
    v.show_live_process(1234, "proc.exe")
    assert v._refresh.isActive()  # live mode refreshes on the timer
    _wait_load(qtbot, v)
    assert v.model.data(v.model.index(0, 5), Qt.DisplayRole) == "70"  # 50 + 20 MZ
    assert "rewritten" not in v.header.text()


def test_refresh_flags_rewritten_code_and_keeps_the_flag(live_view):
    v, score, tick = live_view
    assert score() == "50"
    tick()  # same bytes: nothing changed
    assert score() == "50"
    _MutablePM.heads_now = {0x40000: b"bbb"}
    tick()  # bytes changed in place: 50 + 15
    assert score() == "65"
    assert "1 rewritten while watching" in v.header.text()
    tick()  # unchanged since, but still flagged while the region is there
    assert score() == "65"
    _MutablePM.regions_now = [_exec_private(0x50000)]
    _MutablePM.heads_now = {0x50000: b"ccc"}
    tick()  # the rewritten region is gone: the flag goes with it
    assert v._live_rewritten == set()
    assert "rewritten" not in v.header.text()


def test_reselecting_a_process_starts_the_history_afresh(qtbot, live_view):
    v, score, tick = live_view
    _MutablePM.heads_now = {0x40000: b"bbb"}
    tick()
    assert v._live_rewritten == {0x40000}
    v.show_live_process(1234, "proc.exe")  # same pid, new watch
    assert v._live_rewritten == set() and v._prev_heads == {}
    v._refresh.stop()
    _wait_load(qtbot, v)
    assert score() == "50"  # the first load of a watch has nothing to compare


def test_refresh_tick_skips_when_hidden_or_busy(live_view):
    v, score, tick = live_view
    seq = v._load_seq
    v._in_flight = True
    v._on_refresh_tick()  # previous load still running: no backlog
    assert v._load_seq == seq
    v._in_flight = False
    v.hide()
    v._on_refresh_tick()  # not on screen: not worth a VirtualQueryEx walk
    assert v._load_seq == seq


def test_refresh_tick_stops_when_not_watching(live_view):
    v, score, tick = live_view
    v._refresh.start()
    v._pid = None
    v._on_refresh_tick()
    assert not v._refresh.isActive()
    v._refresh.start()
    v._pid = 1234
    v._live = False
    v._on_refresh_tick()
    assert not v._refresh.isActive()


def test_refresh_keeps_selection_and_clears_hex_when_it_vanishes(live_view):
    v, score, tick = live_view
    v.table.selectRow(0)
    assert "61 61 61" in v.hex.toPlainText()  # b"aaa" previewed
    _MutablePM.heads_now = {0x40000: b"zzz"}
    tick()
    assert v.table.currentIndex().row() == 0  # still on the same region
    assert "7a 7a 7a" in v.hex.toPlainText()  # and its preview was refreshed
    _MutablePM.regions_now = [_exec_private(0x50000)]
    tick()
    assert v.hex.toPlainText() == ""  # the selected region is gone


def test_load_failure_stops_the_refresh(qtbot, live_view, monkeypatch):
    v, score, tick = live_view
    v._refresh.start()

    class Boom:
        def __init__(self, *a, **k):
            raise ProcessAccessError("gone")
    monkeypatch.setattr(region_view_mod, "ProcessMemory", Boom)
    v._on_refresh_tick()
    qtbot.waitUntil(lambda: "cannot open" in v.header.text())
    assert not v._refresh.isActive()
    assert not v._in_flight


def test_playback_stops_the_refresh(live_view):
    v, score, tick = live_view
    v._refresh.start()
    v.show_recorded_regions([], "Recording #1")
    assert not v._refresh.isActive()
    assert not v._in_flight


def test_live_entropy_fall_scores_as_unpacked(live_view):
    """A head that decrypts itself in place stacks the unpack on the rewrite."""
    from memlapse.analytics import (
        ENTROPY_CODE_MAX, ENTROPY_PACKED, shannon_entropy,
    )
    v, score, tick = live_view
    packed = bytes(range(256))                     # 8.0 bits per byte
    code = bytes(range(64)) * 4                    # 6.0 bits per byte
    assert shannon_entropy(packed) >= ENTROPY_PACKED
    assert shannon_entropy(code) <= ENTROPY_CODE_MAX
    _MutablePM.heads_now = {0x40000: packed}
    tick()  # rewritten, and packed enough to score the entropy threshold too
    assert score() == "75"  # 50 private + 15 rewritten + 10 high entropy
    _MutablePM.heads_now = {0x40000: code}
    tick()  # the payload decrypted itself: 50 + 15 rewritten + 20 unpacked
    assert score() == "85"
    assert v._live_unpacked == {0x40000}
    tick()  # unchanged since, but the finding stays while the region is there
    assert score() == "85"
    _MutablePM.regions_now = [_exec_private(0x50000)]
    _MutablePM.heads_now = {0x50000: code}
    tick()  # the region is gone and so is its finding
    assert v._live_unpacked == set()


def test_a_refresh_onto_a_reused_pid_stops_instead_of_comparing(live_view):
    """The rewrite rule must not fire on a stranger that inherited the pid."""
    v, score, tick = live_view
    tick()
    assert v._created == 1000
    _MutablePM.instance_created = 9999   # the target exited, the pid was reused
    _MutablePM.heads_now = {0x40000: b"bbb"}   # a rewrite, if it were compared
    tick()
    assert v._live_rewritten == set()    # nothing is claimed about a stranger
    assert "has exited" in v.header.text()
    assert not v._refresh.isActive()    # and the watch is over
    assert v.model.rowCount() == 1      # the target's last map is still there


def test_watching_another_process_compares_it_with_itself(qtbot, live_view):
    """A new selection has no creation time to be stale against."""
    v, score, tick = live_view
    tick()
    _MutablePM.instance_created = 9999   # a different process this time
    v.show_live_process(5678, "other.exe")
    v._refresh.stop()
    _wait_load(qtbot, v)
    assert "has exited" not in v.header.text()
    assert v._created == 9999


# --- a held-back row says why ------------------------------------------------
def test_a_row_held_back_by_the_band_rule_says_so(rmodel):
    """The Score column shows 75 and the band says review. Explain that."""
    from PySide6.QtCore import Qt
    region = _exec_private_rwx()
    rmodel.set_regions([region], None)
    assert rmodel.data(rmodel.index(0, 5), Qt.DisplayRole) == "75"
    tip = rmodel.data(rmodel.index(0, 0), Qt.ToolTipRole)
    assert tip.startswith("review: ")
    assert "held at review" in tip


def test_a_row_that_earned_its_band_says_nothing_extra(rmodel):
    """The note belongs only where the number and the band disagree."""
    from PySide6.QtCore import Qt
    region = _exec_private_rwx()
    heads = {region.base_addr: b"MZ"}
    rmodel.set_regions([region], heads)
    tip = rmodel.data(rmodel.index(0, 0), Qt.ToolTipRole)
    assert tip.startswith("likely injection: ")
    assert "held at review" not in tip


def test_a_low_scoring_shape_only_row_says_nothing_extra(rmodel):
    """Nothing was held back from a region that never reached the top."""
    from PySide6.QtCore import Qt
    from memlapse.model.region import MEM_COMMIT, MEM_MAPPED, PAGE_EXECUTE_READ, Region
    region = Region(0x50000, 4096, MEM_COMMIT, PAGE_EXECUTE_READ, MEM_MAPPED)
    rmodel.set_regions([region], None)
    tip = rmodel.data(rmodel.index(0, 0), Qt.ToolTipRole)
    assert tip.startswith("review: ")       # mapped exec alone is 30
    assert "held at review" not in tip


def test_the_held_back_note_keys_on_the_points_that_are_left(rmodel):
    """The note must not fire on a row the allowlist already brought down.

    Every other tooltip test runs with an empty allowlist, where score and
    effective_score are equal and nothing tells the two apart. Excusing the
    only non-map rule leaves a 50-point row that no rule held back: saying
    it was held back would be a lie about a row nobody capped.
    """
    from PySide6.QtCore import Qt
    from memlapse.analytics import RULE_PE_HEADER, RULE_RWX
    region = _exec_private_rwx()
    heads = {region.base_addr: b"MZ"}
    rmodel.set_regions([region], heads,
                       allowed={RULE_PE_HEADER, RULE_RWX})
    tip = rmodel.data(rmodel.index(0, 0), Qt.ToolTipRole)
    assert rmodel.data(rmodel.index(0, 5), Qt.DisplayRole) == "95"   # raw
    assert tip.startswith("review: ")            # 50 left, under the floor
    assert "held at review" not in tip


# --- a held-back row distinguishes 'found nothing' from 'could not look' ----
def test_a_held_back_row_that_was_read_says_the_map_was_the_whole_case(rmodel):
    from PySide6.QtCore import Qt
    region = _exec_private_rwx()
    rmodel.set_regions([region], {region.base_addr: bytes(64)})
    tip = rmodel.data(rmodel.index(0, 0), Qt.ToolTipRole)
    assert "nothing here but the shape of the map" in tip
    assert "no bytes could be read" not in tip


def test_a_held_back_row_with_no_head_says_nothing_could_be_read(rmodel):
    """An unelevated target denies PROCESS_VM_READ and no head arrives.

    The row is held back either way, but the reason differs and only one of
    them is evidence. Claiming the content rules came back clean when no
    byte was ever read is the kind of thing an analyst would act on.
    """
    from PySide6.QtCore import Qt
    region = _exec_private_rwx()
    rmodel.set_regions([region], None)          # no heads at all
    tip = rmodel.data(rmodel.index(0, 0), Qt.ToolTipRole)
    assert "no bytes could be read" in tip
    assert "nothing here but the shape of the map" not in tip


def test_the_read_flag_is_per_region_not_per_refresh(rmodel):
    """One region read and one not, in the same call, must read differently.

    A read can fail for a single region: it goes away between the
    VirtualQueryEx walk and the read, or its pages are inaccessible while the
    rest of the process reads fine. An all-or-nothing flag would tell the
    analyst the content rules came back clean on bytes nobody fetched.
    """
    from PySide6.QtCore import Qt
    read = _exec_private_rwx(0x40000)
    unread = _exec_private_rwx(0x50000)
    rmodel.set_regions([read, unread], {read.base_addr: bytes(64)})
    first = rmodel.data(rmodel.index(0, 0), Qt.ToolTipRole)
    second = rmodel.data(rmodel.index(1, 0), Qt.ToolTipRole)
    assert "nothing here but the shape of the map" in first
    assert "no bytes could be read" in second


def test_an_excused_signal_is_not_reported_as_an_absent_one(rmodel):
    """Held back because a rule was allowlisted, not because nothing fired.

    The row lists the PE header it found and then has to explain a review
    band. Saying there was nothing but the map would contradict the line
    above it in the same tooltip.
    """
    from PySide6.QtCore import Qt
    from memlapse.analytics import RULE_PE_HEADER
    region = _exec_private_rwx()
    heads = {region.base_addr: b"MZ" + bytes(62)}
    rmodel.set_regions([region], heads, allowed={RULE_PE_HEADER})
    tip = rmodel.data(rmodel.index(0, 0), Qt.ToolTipRole)
    assert "PE header" in tip and "(allowlisted)" in tip
    assert "are allowlisted here" in tip
    assert "nothing here but the shape of the map" not in tip
    assert "no bytes could be read" not in tip


# --- playback scores against the same entries as live ----------------------
def test_playback_applies_the_allowlist_like_live_does(qtbot):
    """A replay of a watch has to reach the watch's verdict."""
    from PySide6.QtCore import Qt
    from memlapse.analytics import (
        Allowlist, AllowlistEntry, RULE_PRIVATE_EXEC, RULE_RWX)
    book = Allowlist([AllowlistEntry("jit.exe", rule, "JIT host")
                      for rule in (RULE_PRIVATE_EXEC, RULE_RWX)])
    v = RegionView(allowlist=book)
    qtbot.addWidget(v)
    region = _exec_private_rwx()
    v.show_recorded_regions([region], "Recording #1", image_name="jit.exe")
    assert v.model.data(v.model.index(0, 0), Qt.ToolTipRole).startswith(
        "allowlisted: ")
    # and a recording of a process no entry names is untouched
    v.show_recorded_regions([region], "Recording #2", image_name="other.exe")
    tip = v.model.data(v.model.index(0, 0), Qt.ToolTipRole)
    assert tip.startswith("review: ") and "(allowlisted)" not in tip


# --- the allowlist: the row and the score stay, the verdict goes -----------
def test_allowlisted_row_keeps_its_score_and_loses_the_heat(rmodel):
    from PySide6.QtCore import Qt
    from memlapse.analytics import RULE_PRIVATE_EXEC, RULE_RWX
    region = _exec_private()          # private and executable: 50, no RWX
    rmodel.set_regions([region])
    hot = rmodel.data(rmodel.index(0, 0), Qt.BackgroundRole)
    assert rmodel.data(rmodel.index(0, 5), Qt.DisplayRole) == "50"

    rmodel.set_regions([region], allowed={RULE_PRIVATE_EXEC, RULE_RWX})
    tip = rmodel.data(rmodel.index(0, 0), Qt.ToolTipRole)
    muted = rmodel.data(rmodel.index(0, 0), Qt.BackgroundRole)
    assert rmodel.data(rmodel.index(0, 5), Qt.DisplayRole) == "50"  # raw, kept
    assert tip.startswith("allowlisted: ")
    assert tip.count("(allowlisted)") == 1   # marked, not hidden
    assert muted != hot                      # neutral, not a heat colour
    assert muted.red() == muted.green() == muted.blue()


def test_allowlisting_one_rule_still_tints_on_what_is_left(rmodel):
    """A stomped JIT host has to stay visible."""
    from PySide6.QtCore import Qt
    from memlapse.analytics import RULE_PRIVATE_EXEC, RULE_RWX
    region = _exec_private()
    heads = {region.base_addr: b"MZ" + bytes(range(256))}
    rmodel.set_regions([region], heads,
                       allowed={RULE_PRIVATE_EXEC, RULE_RWX})
    tip = rmodel.data(rmodel.index(0, 0), Qt.ToolTipRole)
    assert tip.startswith("review: ")        # MZ and entropy still count
    assert "PE header" in tip and "(allowlisted)" in tip
    colour = rmodel.data(rmodel.index(0, 0), Qt.BackgroundRole)
    assert not (colour.red() == colour.green() == colour.blue())


def test_the_tint_comes_from_the_points_that_are_left(rmodel):
    """Excusing a rule has to cool the row, not merely leave it coloured.

    The test above asks only that the tint is not the allowlisted grey, which
    the raw score would satisfy just as well. This pins which number paints
    it: a region excused down to 30 has to look like a 30, or a mostly
    forgiven JIT host would go on burning as brightly as a real finding.
    """
    from PySide6.QtCore import Qt
    from memlapse.analytics import RULE_PRIVATE_EXEC
    from memlapse.ui.theme import heat_color
    region = _exec_private()
    heads = {region.base_addr: b"MZ" + bytes(range(256))}
    rmodel.set_regions([region], heads, allowed={RULE_PRIVATE_EXEC})
    # 50 unbacked exec excused; 20 PE header and 10 entropy still counting.
    assert rmodel.data(rmodel.index(0, 5), Qt.DisplayRole) == "80"  # raw, shown
    colour = rmodel.data(rmodel.index(0, 0), Qt.BackgroundRole)
    rgb = (colour.red(), colour.green(), colour.blue())
    assert rgb == heat_color(0.30)   # what is left
    assert rgb != heat_color(0.80)   # what the raw score would have painted


def test_the_header_does_not_count_an_excused_rewrite(qtbot, monkeypatch):
    """The band and the header have to agree, or the header shouts about
    findings the allowlist has already excused."""
    from memlapse.analytics import (
        Allowlist, AllowlistEntry, RULE_PRIVATE_EXEC, RULE_REWRITTEN, RULE_RWX,
    )
    _MutablePM.regions_now = [_exec_private()]
    _MutablePM.heads_now = {0x40000: b"aaa"}
    _MutablePM.instance_created = 1000
    monkeypatch.setattr(region_view_mod, "ProcessMemory", _MutablePM)
    book = Allowlist([
        AllowlistEntry("jit.exe", rule, "JIT host")
        for rule in (RULE_PRIVATE_EXEC, RULE_RWX, RULE_REWRITTEN)
    ])
    v = RegionView(allowlist=book)
    qtbot.addWidget(v)
    v.show()
    v.show_live_process(1234, "jit.exe")
    v._refresh.stop()
    _wait_load(qtbot, v)
    _MutablePM.heads_now = {0x40000: b"bbb"}   # a rewrite, and an excused one
    v._on_refresh_tick()
    _wait_load(qtbot, v)
    assert v._live_rewritten == {0x40000}      # the detector still saw it
    assert v.model.rewritten_count() == 0      # but it is not a finding
    assert "rewritten while watching" not in v.header.text()


def test_the_header_still_counts_a_rewrite_that_was_not_excused(qtbot,
                                                                monkeypatch):
    from memlapse.analytics import (
        Allowlist, AllowlistEntry, RULE_PRIVATE_EXEC,
    )
    _MutablePM.regions_now = [_exec_private()]
    _MutablePM.heads_now = {0x40000: b"aaa"}
    _MutablePM.instance_created = 1000
    monkeypatch.setattr(region_view_mod, "ProcessMemory", _MutablePM)
    book = Allowlist([AllowlistEntry("jit.exe", RULE_PRIVATE_EXEC)])
    v = RegionView(allowlist=book)
    qtbot.addWidget(v)
    v.show()
    v.show_live_process(1234, "jit.exe")
    v._refresh.stop()
    _wait_load(qtbot, v)
    _MutablePM.heads_now = {0x40000: b"bbb"}
    v._on_refresh_tick()
    _wait_load(qtbot, v)
    assert v.model.rewritten_count() == 1
    assert "1 rewritten while watching" in v.header.text()


def test_a_process_with_no_entry_scores_as_it_always_did(qtbot, monkeypatch):
    from memlapse.analytics import Allowlist, AllowlistEntry, RULE_PRIVATE_EXEC
    from PySide6.QtCore import Qt
    _MutablePM.regions_now = [_exec_private()]
    _MutablePM.heads_now = {0x40000: b"aaa"}
    _MutablePM.instance_created = 1000
    monkeypatch.setattr(region_view_mod, "ProcessMemory", _MutablePM)
    book = Allowlist([AllowlistEntry("jit.exe", RULE_PRIVATE_EXEC)])
    v = RegionView(allowlist=book)
    qtbot.addWidget(v)
    v.show()
    v.show_live_process(1234, "other.exe")   # not the allowlisted image
    v._refresh.stop()
    _wait_load(qtbot, v)
    tip = v.model.data(v.model.index(0, 0), Qt.ToolTipRole)
    assert tip.startswith("review: ")        # 50, exactly as before
    assert "(allowlisted)" not in tip

