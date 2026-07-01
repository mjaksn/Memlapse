"""Process table: model + view.

``ProcessTableModel`` adapts a list of :class:`ProcessInfo` to Qt's model/view
framework. ``ProcessView`` wraps it with a live filter box and a sortable
table. Sorting/filtering go through a QSortFilterProxyModel so the underlying
data can be swapped wholesale on each poll without disturbing the user's view.
"""

from __future__ import annotations

from PySide6.QtCore import (
    QAbstractTableModel, QModelIndex, Qt, QSortFilterProxyModel, Signal,
)
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import QLineEdit, QTableView, QVBoxLayout, QWidget

from ..model import ProcessInfo
from .theme import heat_color


def _fmt_bytes(n: int) -> str:
    if n <= 0:
        return "—"
    value = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024.0:
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{value:.1f} PB"


class ProcessTableModel(QAbstractTableModel):
    COLUMNS = ("PID", "Name", "User", "Threads", "Working Set", "Private")

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._rows: list[ProcessInfo] = []
        self._max_ws: int = 0

    # --- required overrides ------------------------------------------------
    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent=QModelIndex()) -> int:
        return len(self.COLUMNS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self.COLUMNS[section]
        return None

    def data(self, index: QModelIndex, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        p = self._rows[index.row()]
        col = index.column()

        if role == Qt.DisplayRole:
            return (
                p.pid, p.name, p.username, p.num_threads,
                _fmt_bytes(p.wset_bytes), _fmt_bytes(p.private_bytes),
            )[col]

        # Sort numerically on the numeric columns instead of by display string.
        if role == Qt.UserRole:
            return (
                p.pid, p.name.lower(), p.username.lower(), p.num_threads,
                p.wset_bytes, p.private_bytes,
            )[col]

        if role == Qt.TextAlignmentRole and col in (0, 3, 4, 5):
            return int(Qt.AlignRight | Qt.AlignVCenter)

        # Heat the Working Set cell relative to the busiest process in view.
        if role == Qt.BackgroundRole and col == 4 and self._max_ws > 0:
            r, g, b = heat_color(p.wset_bytes / self._max_ws)
            return QBrush(QColor(r, g, b, 90))
        return None

    # --- data update -------------------------------------------------------
    def set_processes(self, rows: list[ProcessInfo]) -> None:
        self.beginResetModel()
        self._rows = rows
        self._max_ws = max((r.wset_bytes for r in rows), default=0)
        self.endResetModel()

    def process_at(self, row: int) -> ProcessInfo | None:
        return self._rows[row] if 0 <= row < len(self._rows) else None


class ProcessView(QWidget):
    #: Emitted (pid, name) when the user selects a different process.
    processSelected = Signal(int, str)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._selected_pid: int | None = None

        self.model = ProcessTableModel(self)
        self.proxy = QSortFilterProxyModel(self)
        self.proxy.setSourceModel(self.model)
        self.proxy.setSortRole(Qt.UserRole)
        self.proxy.setFilterRole(Qt.DisplayRole)
        self.proxy.setFilterCaseSensitivity(Qt.CaseInsensitive)
        self.proxy.setFilterKeyColumn(1)  # filter on Name

        self.filter_box = QLineEdit(self)
        self.filter_box.setPlaceholderText("Filter by process name…")
        self.filter_box.textChanged.connect(self.proxy.setFilterFixedString)

        self.table = QTableView(self)
        self.table.setModel(self.proxy)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(4, Qt.DescendingOrder)  # Working Set desc
        self.table.setSelectionBehavior(QTableView.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.selectionModel().currentRowChanged.connect(self._on_current_changed)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.addWidget(self.filter_box)
        layout.addWidget(self.table)

    def select_pid(self, pid: int) -> None:
        """Programmatically select a process by pid (used for drill-in)."""
        self._reselect_pid(pid)

    def update_processes(self, rows: list[ProcessInfo]) -> None:
        self.model.set_processes(rows)
        self.table.resizeColumnsToContents()
        # A full model reset clears the selection; restore it by pid so the
        # region view stays put (and, via the pid guard, doesn't re-enumerate).
        if self._selected_pid is not None:
            self._reselect_pid(self._selected_pid)

    def _reselect_pid(self, pid: int) -> None:
        for proxy_row in range(self.proxy.rowCount()):
            src = self.proxy.mapToSource(self.proxy.index(proxy_row, 0))
            proc = self.model.process_at(src.row())
            if proc and proc.pid == pid:
                self.table.selectRow(proxy_row)
                return

    def _on_current_changed(self, current: QModelIndex, _prev: QModelIndex) -> None:
        if not current.isValid():
            return
        src = self.proxy.mapToSource(current)
        proc = self.model.process_at(src.row())
        if proc is None or proc.pid == self._selected_pid:
            return  # same process (e.g. re-selection after a poll) — don't re-emit
        self._selected_pid = proc.pid
        self.processSelected.emit(proc.pid, proc.name)
