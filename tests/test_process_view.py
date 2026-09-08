"""Tests for the process table model and view."""

import pytest
from PySide6.QtCore import Qt

from memlapse.ui.process_view import ProcessTableModel, ProcessView, _fmt_bytes


def test_fmt_bytes():
    assert _fmt_bytes(0) == "-"       # zero/unknown renders as a hyphen
    assert _fmt_bytes(-5) == "-"
    assert _fmt_bytes(512) == "512 B"
    assert _fmt_bytes(1536) == "1.5 KB"
    assert _fmt_bytes(5 * 1024 * 1024) == "5.0 MB"
    assert _fmt_bytes(3 * 1024**4) == "3.0 TB"
    assert _fmt_bytes(2 * 1024**5) == "2.0 PB"


@pytest.fixture
def model(qapp):
    return ProcessTableModel()


def test_model_dimensions_and_headers(model, make_process):
    model.set_processes([make_process()])
    assert model.rowCount() == 1
    assert model.columnCount() == 7
    assert model.headerData(0, Qt.Horizontal, Qt.DisplayRole) == "PID"
    # Vertical header / non-display roles return None.
    assert model.headerData(0, Qt.Vertical, Qt.DisplayRole) is None


def test_model_display_and_sort_roles(model, make_process):
    model.set_processes([make_process(pid=7, name="A.exe", wset_bytes=2048)])
    idx = model.index(0, 0)
    assert model.data(idx, Qt.DisplayRole) == 7
    assert model.data(model.index(0, 4), Qt.DisplayRole) == "2.0 KB"
    # UserRole is the raw value for numeric sorting.
    assert model.data(model.index(0, 4), Qt.UserRole) == 2048
    assert model.data(model.index(0, 1), Qt.UserRole) == "a.exe"
    # Numeric columns are right-aligned.
    align = model.data(model.index(0, 0), Qt.TextAlignmentRole)
    assert align == int(Qt.AlignRight | Qt.AlignVCenter)


def test_model_invalid_index(model, make_process):
    model.set_processes([make_process()])
    from PySide6.QtCore import QModelIndex
    assert model.data(QModelIndex()) is None
    assert model.process_at(99) is None
    assert model.process_at(0) is not None
    # rowCount under a valid parent is 0 (flat model).
    assert model.rowCount(model.index(0, 0)) == 0


@pytest.fixture
def view(qtbot):
    v = ProcessView()
    qtbot.addWidget(v)
    return v


def test_filter_by_name(view, make_process):
    view.update_processes([
        make_process(pid=1, name="chrome.exe"),
        make_process(pid=2, name="python.exe"),
    ])
    view.filter_box.setText("chrome")
    assert view.proxy.rowCount() == 1


def test_selection_emits_once_per_pid(view, make_process, qtbot):
    view.update_processes([
        make_process(pid=1, name="a.exe"),
        make_process(pid=2, name="b.exe"),
    ])
    emitted = []
    view.processSelected.connect(lambda pid, name: emitted.append((pid, name)))
    view.table.selectRow(0)
    first_pid = emitted[0][0]
    # Re-selecting the same row must not re-emit.
    view.table.selectRow(0)
    assert len(emitted) == 1
    # Selecting a different row emits again.
    view.table.selectRow(1)
    assert len(emitted) == 2
    assert emitted[1][0] != first_pid


def test_columns_autosized_once_from_first_snapshot(view, make_process, monkeypatch):
    calls = []
    monkeypatch.setattr(view.table, "resizeColumnsToContents",
                        lambda: calls.append(1))
    view.update_processes([])            # nothing to measure yet
    assert calls == []
    view.update_processes([make_process(pid=1)])
    assert len(calls) == 1
    view.update_processes([make_process(pid=1), make_process(pid=2)])
    assert len(calls) == 1               # later polls leave widths alone


def test_model_heat_background_only_on_working_set(model, make_process):
    from PySide6.QtGui import QBrush
    model.set_processes([make_process(pid=1, wset_bytes=100),
                         make_process(pid=2, wset_bytes=50)])
    assert isinstance(model.data(model.index(0, 4), Qt.BackgroundRole), QBrush)
    assert model.data(model.index(0, 1), Qt.BackgroundRole) is None
    model.set_processes([make_process(pid=3, wset_bytes=0)])
    assert model.data(model.index(0, 4), Qt.BackgroundRole) is None


def test_select_pid_programmatically(view, make_process):
    view.update_processes([make_process(pid=1, name="a.exe"),
                           make_process(pid=2, name="b.exe")])
    view.select_pid(2)
    assert view._selected_pid == 2


def test_current_changed_invalid_is_ignored(view, make_process):
    from PySide6.QtCore import QModelIndex
    emitted = []
    view.processSelected.connect(lambda pid, name: emitted.append(pid))
    view._on_current_changed(QModelIndex(), QModelIndex())  # invalid -> early return
    assert emitted == []


def test_reselect_pid_not_found_is_silent(view, make_process):
    view.update_processes([make_process(pid=1, name="a.exe")])
    view.table.selectRow(0)
    # Selected pid disappears on the next poll -> reselect loop finds nothing.
    view.update_processes([make_process(pid=2, name="b.exe")])
    assert view._selected_pid == 1  # remembered, even though not currently present


def test_selection_survives_refresh_without_reemit(view, make_process):
    view.update_processes([make_process(pid=1, name="a.exe"),
                           make_process(pid=2, name="b.exe")])
    emitted = []
    view.processSelected.connect(lambda pid, name: emitted.append(pid))
    view.table.selectRow(0)
    selected_pid = emitted[0]
    # A poll replaces all rows; selection should be restored by pid, silently.
    view.update_processes([make_process(pid=2, name="b.exe"),
                           make_process(pid=1, name="a.exe")])
    assert view._selected_pid == selected_pid
    assert len(emitted) == 1  # no re-emit for the same pid


# --- the Parent column -----------------------------------------------------
def test_parent_column_shows_and_sorts_by_creator(model, make_process):
    from PySide6.QtCore import Qt
    model.set_processes([
        make_process(pid=10, name="child.exe", parent_pid=600),
        make_process(pid=11, name="orphan.exe", parent_pid=0),
    ])
    assert model.headerData(6, Qt.Horizontal, Qt.DisplayRole) == "Parent"
    assert model.data(model.index(0, 6), Qt.DisplayRole) == 600
    assert model.data(model.index(1, 6), Qt.DisplayRole) == ""
    assert model.data(model.index(0, 6), Qt.UserRole) == 600
    assert model.data(model.index(1, 6), Qt.UserRole) == 0
    assert model.data(model.index(0, 6), Qt.TextAlignmentRole) is not None
