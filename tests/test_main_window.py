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


def _seed(db_path, *, with_samples=True, sample_regions=None, allowlist=None):
    conn = connect(db_path)
    dao = Dao(conn)
    rid = dao.create_recording(1000, "proc.exe", 1_000, allowlist=allowlist)
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


def test_playback_seek_scores_against_the_allowlist_end_to_end(main_window):
    """The whole chain, not just the RegionView end of it.

    Three links have to hold for a replay to agree with the watch it records:
    the engine keeps the recorded image name, the window passes it to the
    view, and the view looks it up. Testing the view alone leaves the first
    two free to be deleted, and deleting either ships a playback that scores
    against an empty allowlist while the live watch scores against the real
    one.
    """
    from PySide6.QtCore import Qt
    from memlapse.analytics import (
        Allowlist, AllowlistEntry, RULE_PRIVATE_EXEC, RULE_RWX)
    from memlapse.model.region import (
        MEM_COMMIT, MEM_PRIVATE, PAGE_EXECUTE_READWRITE, Region)
    win, db = main_window
    rwx = Region(0x40000, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE, MEM_PRIVATE)
    rid = _seed(db, sample_regions=[rwx])          # _seed records "proc.exe"
    win.region_view._allowlist = Allowlist([
        AllowlistEntry("proc.exe", rule, "JIT host")
        for rule in (RULE_PRIVATE_EXEC, RULE_RWX)])
    win._open_recording(rid)
    assert win.playback.target_name == "proc.exe"
    win._on_seek(2_000)
    tip = win.region_view.model.data(
        win.region_view.model.index(0, 0), Qt.ToolTipRole)
    assert tip.startswith("allowlisted: ")
    # The raw number survives the suppression, as it does in live mode.
    assert win.region_view.model.data(
        win.region_view.model.index(0, 5), Qt.DisplayRole) == "75"


def test_leaving_playback_restores_the_live_map_and_record(main_window):
    """Coming back to Live must land where live mode left off.

    The selection never changed, so re-picking the same row emits nothing:
    an analyst who glances at a recording and clicks Live would otherwise be
    stuck with a blank map and a dead Record button.
    """
    win, db = main_window
    win._on_process_selected(os.getpid(), "me")
    rid = _seed(db, sample_regions=[])
    win._open_recording(rid)
    assert not win.record_action.isEnabled()
    win._enter_live_mode()
    assert win._mode == "live"
    assert win.record_action.isEnabled()
    assert str(os.getpid()) in win.region_view.header.text()


def test_leaving_playback_with_nothing_selected_prompts_for_one(main_window):
    win, db = main_window
    rid = _seed(db, sample_regions=[])
    win._open_recording(rid)
    win._enter_live_mode()
    assert not win.record_action.isEnabled()
    assert "Select a process" in win.region_view.header.text()


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
    win.collector.updated.emit([make_process(pid=1)])
    win.collector.dropped.emit(3)
    assert "3 process polls dropped" in win._status_label.text()


def test_status_bar_names_the_stream_that_fell_behind(main_window, make_process):
    """Both collectors drop independently; a silent one is indistinguishable
    from one that is keeping up."""
    win, _ = main_window
    win.collector.updated.emit([make_process(pid=1)])
    win.system_collector.dropped.emit(2)
    text = win._status_label.text()
    assert "2 system polls dropped" in text
    assert "process polls" not in text
    win.collector.dropped.emit(4)
    assert ("1 processes, 4 process polls dropped, 2 system polls dropped"
            == win._status_label.text())


def test_status_bar_is_quiet_while_nothing_is_dropped(main_window, make_process):
    win, _ = main_window
    win.collector.updated.emit([make_process(pid=1), make_process(pid=2)])
    assert win._status_label.text() == "2 processes"


def test_a_drop_during_playback_leaves_the_recording_status_alone(main_window,
                                                                  make_process):
    """The collectors keep running in playback, where the line is not theirs."""
    win, _ = main_window
    win.collector.updated.emit([make_process(pid=1)])
    win._mode = "playback"
    win._status_label.setText("WS 12.0 MB  |  7 threads")
    win.collector.dropped.emit(5)
    assert win._status_label.text() == "WS 12.0 MB  |  7 threads"
    win._enter_live_mode()   # returning to live shows the total that was kept
    assert "5 process polls dropped" in win._status_label.text()


# --- a recorded thread start reaches the region view -----------------------
def test_playback_seek_scores_a_recorded_thread_start(main_window):
    from PySide6.QtCore import Qt
    from memlapse.model.region import (
        MEM_COMMIT, MEM_PRIVATE, PAGE_EXECUTE_READ, Region,
    )
    win, db = main_window
    region = Region(0x40000, 4096, MEM_COMMIT, PAGE_EXECUTE_READ, MEM_PRIVATE)
    conn = connect(db)
    dao = Dao(conn)
    rid = dao.create_recording(1000, "proc.exe", 1_000)
    dao.add_sample(rid, 1_000, ProcState(1_000, 1000, 100, 50, 3), [region],
                   None, {7: 0x40080})
    dao.end_recording(rid, 2_000)
    conn.close()

    win._open_recording(rid)
    win._on_seek(1_000)
    model = win.region_view.model
    assert model.data(model.index(0, 5), Qt.DisplayRole) == "75"  # 50 + 25


# --- a decrypting payload scores on both temporal signals ------------------
def test_playback_seek_scores_an_unpacking_region(main_window):
    from PySide6.QtCore import Qt
    from memlapse.model.region import (
        MEM_COMMIT, MEM_PRIVATE, PAGE_EXECUTE_READ, Region,
    )
    win, db = main_window
    packed, code = bytes(range(256)), b"\x48\x8b\x05\x01" * 64
    region = Region(0x40000, 4096, MEM_COMMIT, PAGE_EXECUTE_READ, MEM_PRIVATE)
    conn = connect(db)
    dao = Dao(conn)
    rid = dao.create_recording(1000, "proc.exe", 1_000)
    for ts, head in ((1_000, packed), (2_000, code)):
        dao.add_sample(rid, ts, ProcState(ts, 1000, 100, 50, 3), [region],
                       {0x40000: head})
    dao.end_recording(rid, 3_000)
    conn.close()

    win._open_recording(rid)
    win._on_seek(2_000)
    model = win.region_view.model
    assert model.data(model.index(0, 5), Qt.DisplayRole) == "85"  # 50 + 15 + 20


# --- a replay says what the sample could and could not see ------------------
def _seed_state(db, *, can_read=None, created=None, ts=1_000):
    from memlapse.storage.dao import ProcState
    conn = connect(db)
    dao = Dao(conn)
    rid = dao.create_recording(1000, "proc.exe", 0)
    dao.add_sample(rid, ts, ProcState(ts, 1000, 100, 50, 3,
                                      can_read=can_read, created_ft=created), [])
    dao.end_recording(rid, ts + 1)
    conn.close()
    return rid


def test_playback_header_reports_a_target_that_denied_reads(main_window):
    """Live says this; a replay of the same watch has to say it too.

    Without it an empty head set reads as a clean look at the memory, when in
    truth nothing was ever read and every region is scored on structure alone.
    """
    win, db = main_window
    rid = _seed_state(db, can_read=False)
    win._open_recording(rid)
    win._on_seek(1_000)
    assert "(no read access, map only)" in win.region_view.header.text()


def test_playback_header_is_silent_when_reads_worked(main_window):
    win, db = main_window
    rid = _seed_state(db, can_read=True)
    win._open_recording(rid)
    win._on_seek(1_000)
    assert "no read access" not in win.region_view.header.text()


def test_playback_header_does_not_invent_a_denial_for_an_old_recording(main_window):
    """None means the column did not exist, which is not a denial.

    Saying "no read access" here would tell an analyst a recording was taken
    blind when nobody ever asked the question.
    """
    win, db = main_window
    rid = _seed_state(db)                     # neither column written
    win._open_recording(rid)
    win._on_seek(1_000)
    assert "no read access" not in win.region_view.header.text()


def test_playback_header_flags_a_pid_reused_mid_recording(main_window):
    """The sampler opens a fresh handle each sample, so this really can happen."""
    from memlapse.storage.dao import ProcState
    win, db = main_window
    conn = connect(db)
    dao = Dao(conn)
    rid = dao.create_recording(1000, "proc.exe", 0)
    for ts, created in ((1_000, 111), (2_000, 222)):
        dao.add_sample(rid, ts, ProcState(ts, 1000, 100, 50, 3, created_ft=created), [])
    dao.end_recording(rid, 3_000)
    conn.close()
    win._open_recording(rid)
    win._on_seek(1_000)
    assert "pid reused" not in win.region_view.header.text()   # before the change
    win._on_seek(2_000)
    assert "pid reused during this recording" in win.region_view.header.text()


# --- which allowlist scores a replay ---------------------------------------
# The recording's own, when it wrote one down. Everything below turns on the
# difference between "no list was recorded" and "a list was recorded and it
# was empty", which are the same zero rows and opposite instructions.


def _rwx_region():
    from memlapse.model.region import (
        MEM_COMMIT, MEM_PRIVATE, PAGE_EXECUTE_READWRITE, Region)
    # private + committed + executable fires private-exec (50) and rwx (25).
    return Region(0x40000, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE, MEM_PRIVATE)


def _excusing(*rules):
    from memlapse.analytics import Allowlist, AllowlistEntry
    return Allowlist([AllowlistEntry("proc.exe", r, "JIT host") for r in rules])


def _replay(win, db, *, recorded, current):
    win.allowlist = current
    win.region_view._allowlist = current
    rid = _seed(db, sample_regions=[_rwx_region()], allowlist=recorded)
    win._open_recording(rid)
    win._on_seek(2_000)
    return win.region_view.model._verdicts[0]


def test_a_replay_scores_with_the_recorded_allowlist_not_the_current_one(main_window):
    """The discriminating fixture: the two lists excuse opposite rules.

    Record under private-exec, replay on a machine configured for rwx. If the
    replay took the current list the excused rule would be rwx and the score
    50; the recording says private-exec and 25. Scoring the recording's way is
    what lets someone else open it and reach the finding this session reached.
    """
    from memlapse.analytics import RULE_PRIVATE_EXEC, RULE_RWX
    win, db = main_window
    verdict = _replay(win, db, recorded=_excusing(RULE_PRIVATE_EXEC),
                      current=_excusing(RULE_RWX))
    assert {r.rule for r in verdict.reasons if r.allowed} == {RULE_PRIVATE_EXEC}
    assert verdict.effective_score == 25
    assert verdict.score == 75  # the raw number is never suppressed


def test_a_recorded_empty_allowlist_beats_a_configured_one(main_window):
    """Falsy, and still the answer.

    Zero recorded entries with the flag set says this session excused
    nothing. Reading that for truth rather than for None hands the replay
    back to whatever this machine has configured, which would silently
    excuse a rule the recording never excused.
    """
    from memlapse.analytics import Allowlist, RULE_RWX
    win, db = main_window
    verdict = _replay(win, db, recorded=Allowlist(), current=_excusing(RULE_RWX))
    assert [r.rule for r in verdict.reasons if r.allowed] == []
    assert verdict.effective_score == 75


def test_a_recording_with_no_allowlist_falls_back_to_the_current_one(main_window):
    """No regression for every recording made before this was stored."""
    from memlapse.analytics import RULE_RWX
    win, db = main_window
    verdict = _replay(win, db, recorded=None, current=_excusing(RULE_RWX))
    assert {r.rule for r in verdict.reasons if r.allowed} == {RULE_RWX}
    assert verdict.effective_score == 50


def test_the_header_says_when_the_current_allowlist_did_the_scoring(main_window):
    """Because then the bands owe something to this machine, not the recording."""
    from memlapse.analytics import RULE_RWX
    win, db = main_window
    _replay(win, db, recorded=None, current=_excusing(RULE_RWX))
    assert "no allowlist recorded" in win.region_view.header.text()


def test_the_header_stays_quiet_when_the_fallback_changes_nothing(main_window):
    """An empty current list excuses nothing either way, so there is no news."""
    from memlapse.analytics import Allowlist
    win, db = main_window
    _replay(win, db, recorded=None, current=Allowlist())
    assert "no allowlist recorded" not in win.region_view.header.text()


def test_the_header_stays_quiet_when_the_entry_is_for_another_process(main_window):
    """Holding an entry is not the same as having excused something.

    The recording is of proc.exe and the only entry names something else, so
    the fallback happened and changed no band. Saying otherwise sends an
    analyst looking for an influence on these rows that is not there.
    """
    from memlapse.analytics import Allowlist, AllowlistEntry, RULE_RWX
    win, db = main_window
    other = Allowlist([AllowlistEntry("elsewhere.exe", RULE_RWX, "not this one")])
    verdict = _replay(win, db, recorded=None, current=other)
    assert [r.rule for r in verdict.reasons if r.allowed] == []
    assert "no allowlist recorded" not in win.region_view.header.text()


def test_the_header_stays_quiet_when_the_entry_names_a_rule_that_did_not_fire(
        main_window):
    """The region is RWX and private, so a pe-header entry excuses nothing."""
    from memlapse.analytics import Allowlist, AllowlistEntry, RULE_PE_HEADER
    win, db = main_window
    unfired = Allowlist([AllowlistEntry("proc.exe", RULE_PE_HEADER, "no MZ here")])
    verdict = _replay(win, db, recorded=None, current=unfired)
    assert [r.rule for r in verdict.reasons if r.allowed] == []
    assert "no allowlist recorded" not in win.region_view.header.text()


def test_the_header_stays_quiet_when_the_recording_brought_its_own(main_window):
    from memlapse.analytics import Allowlist, RULE_RWX
    win, db = main_window
    _replay(win, db, recorded=Allowlist(), current=_excusing(RULE_RWX))
    assert "no allowlist recorded" not in win.region_view.header.text()


def test_recording_is_started_with_the_windows_allowlist(main_window):
    """One list, two consumers: the live view scores with it and the
    recording writes it down. Two objects here would let a replay disagree
    with the watch that made it."""
    win, _ = main_window
    win._selected_pid, win._selected_name = 4242, "proc.exe"
    win._toggle_record()
    assert FakeSampler.instances[-1].allowlist is win.allowlist
    assert win.region_view._allowlist is win.allowlist
