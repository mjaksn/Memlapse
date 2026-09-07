"""Integration tests for the main window's mode switching and wiring.

The real ProcessCollector, SystemCollector and RegionSampler are replaced with
fakes so no background threads run; playback reads from a temp DB seeded via
the DAO.
"""

import os

import pytest

import memlapse.storage.db as dbmod
import memlapse.ui.main_window as mw
from memlapse.services.recording import RecordingManager
from memlapse.storage import connect
from memlapse.storage.dao import Dao, ProcState
from conftest import FakeCollector, FakeSampler


def _seed(db_path, *, with_samples=True, sample_regions=None):
    conn = connect(db_path)
    dao = Dao(conn)
    rid = dao.create_recording(1000, "proc.exe", 1_000)
    if with_samples:
        dao.add_sample(rid, 1_000, ProcState(1_000, 1000, 100, 50, 3), sample_regions)
        dao.add_sample(rid, 2_000, ProcState(2_000, 1000, 200, 60, 4), sample_regions)
    dao.end_recording(rid, 3_000)
    conn.close()
    return rid


@pytest.fixture
def main_window(qtbot, tmp_path, monkeypatch):
    db = str(tmp_path / "mw.db")
    monkeypatch.setattr(dbmod, "default_db_path", lambda: db)
    monkeypatch.setattr(mw, "ProcessCollector", FakeCollector)
    monkeypatch.setattr(mw, "SystemCollector", FakeCollector)

    def rm_factory(parent=None):
        return RecordingManager(parent=parent, sampler_factory=FakeSampler)
    monkeypatch.setattr(mw, "RecordingManager", rm_factory)
    FakeSampler.instances.clear()

    win = mw.MainWindow()
    qtbot.addWidget(win)
    return win, db


def test_starts_in_live_mode(main_window):
    win, _ = main_window
    assert win._mode == "live"
    assert win.collector.started_flag  # collector was started
    assert "Administrator" in win.statusBar().currentMessage()


def test_live_process_update(main_window, make_process):
    win, _ = main_window
    win.collector.updated.emit([make_process(pid=1), make_process(pid=2)])
    assert win.process_view.model.rowCount() == 2
    assert "2 processes" in win._status_label.text()


def test_process_update_ignored_in_playback(main_window, make_process, sample_regions):
    win, db = main_window
    rid = _seed(db, sample_regions=sample_regions)
    win._open_recording(rid)
    win.collector.updated.emit([make_process(pid=9)])
    # In playback mode the live list must not be repopulated.
    assert win.process_view.model.rowCount() == 0


def test_selecting_process_enables_record(main_window):
    win, _ = main_window
    win._on_process_selected(os.getpid(), "me")
    assert win._selected_pid == os.getpid()
    assert win.record_action.isEnabled()


def test_record_toggle_updates_toolbar(main_window):
    win, _ = main_window
    win._on_process_selected(os.getpid(), "me")
    win._toggle_record()  # start
    assert win.recorder.is_recording
    assert win.record_action.text() == "■ Stop"
    assert "recording" in win._status_label.text()
    win._toggle_record()  # stop
    assert not win.recorder.is_recording
    assert win.record_action.text() == "● Record"


def test_toggle_record_without_selection_noops(main_window):
    win, _ = main_window
    win._selected_pid = None
    win._toggle_record()
    assert not win.recorder.is_recording


def test_open_recording_enters_playback(main_window, sample_regions):
    win, db = main_window
    rid = _seed(db, sample_regions=sample_regions)
    win._open_recording(rid)
    assert win._mode == "playback"
    assert win._timeline_dock.isVisibleTo(win) or win._timeline_dock.isVisible()
    assert not win.record_action.isEnabled()
    assert win.live_action.isEnabled()
    # The initial seek populated the region view from the recording.
    assert win.region_view.model.rowCount() == len(sample_regions)
    assert "Recording #" in win.region_view.header.text()


def test_playback_seek_updates_view(main_window, sample_regions):
    win, db = main_window
    rid = _seed(db, sample_regions=sample_regions)
    win._open_recording(rid)
    win._on_seek(2_000)
    assert "threads" in win.region_view.header.text()


def test_seek_before_first_sample_shows_no_data(main_window, sample_regions):
    win, db = main_window
    rid = _seed(db, sample_regions=sample_regions)
    win._open_recording(rid)
    win._on_seek(1)  # earlier than the first sample
    assert "no data" in win.region_view.header.text()


def test_seek_ignored_when_not_playback(main_window):
    win, _ = main_window
    win._on_seek(1_000)  # live mode -> no-op, must not raise
    assert win._mode == "live"


def test_open_empty_recording(main_window):
    win, db = main_window
    rid = _seed(db, with_samples=False)
    win._open_recording(rid)
    assert win._mode == "playback"
    assert "no samples" in win.region_view.header.text()


def test_return_to_live_mode(main_window, sample_regions):
    win, db = main_window
    rid = _seed(db, sample_regions=sample_regions)
    win._open_recording(rid)
    win._enter_live_mode()
    assert win._mode == "live"
    assert win.playback is None
    assert not win._timeline_dock.isVisible()
    assert win.region_view.model.rowCount() == 0


def test_populate_recordings_menu(main_window, sample_regions):
    win, db = main_window
    _seed(db, sample_regions=sample_regions)
    win._populate_recordings()
    actions = [a for a in win._recordings_menu.actions()]
    assert len(actions) == 1
    assert actions[0].isEnabled()
    assert "proc.exe" in actions[0].text()


def test_populate_recordings_menu_empty(main_window):
    win, _ = main_window
    win._populate_recordings()
    actions = win._recordings_menu.actions()
    assert len(actions) == 1
    assert not actions[0].isEnabled()  # "(no recordings yet)"


def test_open_recording_blocked_while_recording(main_window, sample_regions, monkeypatch):
    win, db = main_window
    rid = _seed(db, sample_regions=sample_regions)
    infos = []
    monkeypatch.setattr(mw.QMessageBox, "information",
                        lambda *a, **k: infos.append(a))
    win._on_process_selected(os.getpid(), "me")
    win._toggle_record()  # start recording
    win._open_recording(rid)
    assert infos  # user was told to stop first
    assert win._mode == "live"  # stayed in live mode


def test_fmt_bytes_scales_units():
    assert mw._fmt_bytes(0) == "0 B"
    assert mw._fmt_bytes(1536) == "1.5 KB"
    assert mw._fmt_bytes(3 * 1024**5) == "3.0 PB"  # loops past TB into PB


def test_select_process_while_recording_keeps_button(main_window):
    win, _ = main_window
    win._on_process_selected(os.getpid(), "me")
    win._toggle_record()  # recording -> is_recording True
    # Selecting again while recording must not toggle Record's enabled state.
    win._on_process_selected(os.getpid(), "me")
    assert win.recorder.is_recording


def test_select_process_in_playback_skips_live_read(main_window, sample_regions):
    win, db = main_window
    rid = _seed(db, sample_regions=sample_regions)
    win._open_recording(rid)
    header_before = win.region_view.header.text()
    win._on_process_selected(4321, "other")  # mode is playback -> no live read
    assert win.region_view.header.text() == header_before


def test_enter_live_mode_blocked_while_recording(main_window):
    win, _ = main_window
    win._on_process_selected(os.getpid(), "me")
    win._toggle_record()
    win._enter_live_mode()  # should be a no-op while recording
    assert win._mode == "live"  # (already live) and recording still active
    assert win.recorder.is_recording


def test_enter_live_mode_without_playback(main_window):
    win, _ = main_window
    win._enter_live_mode()  # playback is None -> close branch skipped
    assert win.playback is None
    assert win._mode == "live"


def test_reopen_recording_closes_previous(main_window, sample_regions):
    win, db = main_window
    rid = _seed(db, sample_regions=sample_regions)
    win._open_recording(rid)
    first = win.playback
    win._open_recording(rid)  # playback not None -> previous engine closed
    assert win.playback is not first


def test_dashboard_activate_drills_into_monitor(main_window, make_process):
    win, _ = main_window
    win.process_view.update_processes([make_process(pid=4242, name="x.exe")])
    win.tabs.setCurrentWidget(win.dashboard)
    win._on_dashboard_activate(4242, "x.exe")
    assert win.tabs.currentWidget() is win._monitor_tab
    assert win.process_view._selected_pid == 4242


def test_close_event_stops_everything(main_window):
    win, _ = main_window
    win.close()
    assert not win.collector.started_flag
    assert not win.system_collector.started_flag


# --- playback seeks carry the content-change detector into the region view ---
from memlapse.model.region import (  # noqa: E402
    MEM_COMMIT, MEM_PRIVATE, PAGE_EXECUTE_READ, Region,
)


def test_playback_seek_scores_rewritten_regions(main_window):
    from PySide6.QtCore import Qt
    win, db = main_window
    exec_region = Region(0x40000, 4096, MEM_COMMIT, PAGE_EXECUTE_READ, MEM_PRIVATE)
    conn = connect(db)
    dao = Dao(conn)
    rid = dao.create_recording(1000, "proc.exe", 1_000)
    dao.add_sample(rid, 1_000, ProcState(1_000, 1000, 100, 50, 3), [exec_region],
                   {0x40000: b"aaa"})
    dao.add_sample(rid, 2_000, ProcState(2_000, 1000, 100, 50, 3), [exec_region],
                   {0x40000: b"bbb"})
    dao.end_recording(rid, 3_000)
    conn.close()

    win._open_recording(rid)
    model = win.region_view.model
    win._on_seek(2_000)  # bytes changed since the sample before: 50 + 15
    assert model.data(model.index(0, 5), Qt.DisplayRole) == "65"
    win._on_seek(1_000)  # first sample has nothing to compare with: 50
    assert model.data(model.index(0, 5), Qt.DisplayRole) == "50"


# --- dropped polls are surfaced, not swallowed -----------------------------
def test_status_bar_reports_dropped_polls(main_window, make_process):
    win, _ = main_window
    win.collector.skipped = 3
    win.collector.updated.emit([make_process(pid=1)])
    assert "3 polls dropped" in win._status_label.text()
    win.collector.skipped = 0
    win.collector.updated.emit([make_process(pid=1)])
    assert "dropped" not in win._status_label.text()
