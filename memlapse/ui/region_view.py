"""Region map + hex inspector.

Displays the VirtualQueryEx region list for a process and, on selection, a hex
dump of the region's first bytes. Used in both live mode (reads memory on the
fly via ProcessMemory) and playback mode (region map from SQLite, no bytes ->
hex panel explains they weren't captured).
"""

from __future__ import annotations

from PySide6.QtCore import (
    QAbstractTableModel, QModelIndex, QObject, QRunnable, Qt, QThreadPool, Signal,
)
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QLabel, QPlainTextEdit, QSplitter, QTableView, QVBoxLayout, QWidget,
)

from ..analytics import RegionVerdict, score_region
from ..model.region import Region
from ..win32.memory import ProcessAccessError, ProcessMemory
from .hexdump import hexdump
from .theme import heat_color

#: How many bytes to read for the hex preview of a selected region.
HEX_PREVIEW_BYTES = 512


class _RegionLoadSignals(QObject):
    """Signals for :class:`_RegionLoadTask` (QRunnable can't carry its own)."""

    #: req_id, regions (list[Region]), readable
    loaded = Signal(int, object, bool)
    #: req_id, error message
    failed = Signal(int, str)


class _RegionLoadTask(QRunnable):
    """Enumerate one process's region map off the GUI thread.

    VirtualQueryEx walks the whole address space, which for a busy process is
    tens of thousands of syscalls, long enough to freeze the window if done on
    the GUI thread. Running it in the thread pool keeps the UI responsive; the
    result is handed back over a queued signal.
    """

    def __init__(self, req_id: int, pid: int) -> None:
        super().__init__()
        self._req_id = req_id
        self._pid = pid
        self.signals = _RegionLoadSignals()

    def run(self) -> None:  # executed on a pool thread
        try:
            with ProcessMemory(self._pid) as pm:
                regions = pm.regions()
                readable = pm.can_read
        except ProcessAccessError as exc:
            self.signals.failed.emit(self._req_id, str(exc))
        except Exception as exc:  # never let a pool thread die silently
            self.signals.failed.emit(self._req_id, str(exc))
        else:
            self.signals.loaded.emit(self._req_id, regions, readable)


def _fmt_size(n: int) -> str:
    value = float(n)
    for unit in ("B", "K", "M", "G", "T"):
        if value < 1024.0:
            return f"{value:.0f}{unit}" if unit == "B" else f"{value:.1f}{unit}"
        value /= 1024.0
    return f"{value:.1f}P"


class RegionTableModel(QAbstractTableModel):
    COLUMNS = ("Base Address", "Size", "State", "Protect", "Type", "Score")

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._rows: list[Region] = []
        self._verdicts: list[RegionVerdict] = []

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
        row, col = index.row(), index.column()
        r = self._rows[row]
        verdict = self._verdicts[row]
        if role == Qt.DisplayRole:
            return (
                f"0x{r.base_addr:012x}", _fmt_size(r.size),
                r.state_str, r.protect_str, r.type_str,
                str(verdict.score) if verdict.suspicious else "",
            )[col]
        if role == Qt.TextAlignmentRole and col in (1, 5):
            return int(Qt.AlignRight | Qt.AlignVCenter)
        # Suspicious rows get a heat-tinted background and a reason tooltip.
        if verdict.suspicious:
            if role == Qt.BackgroundRole:
                red, green, blue = heat_color(verdict.score / 100.0)
                return QColor(red, green, blue, 110)  # translucent over dark theme
            if role == Qt.ToolTipRole:
                return "; ".join(verdict.reasons)
        return None

    def set_regions(self, rows: list[Region],
                    heads: dict[int, bytes] | None = None) -> None:
        heads = heads or {}
        self.beginResetModel()
        self._rows = rows
        self._verdicts = [
            score_region(r, head=heads.get(r.base_addr, b"")) for r in rows
        ]
        self.endResetModel()

    def region_at(self, row: int) -> Region | None:
        return self._rows[row] if 0 <= row < len(self._rows) else None


class RegionView(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._pid: int | None = None
        self._live = True  # live -> can read bytes; playback -> cannot
        self._readable = False

        # Live region maps are enumerated off the GUI thread. Each request gets
        # a monotonic id; only the newest one's result is applied, so rapidly
        # clicking through processes (or switching to playback) can't be clobbered
        # by a slow enumeration that finished late.
        self._pool = QThreadPool.globalInstance()
        self._load_seq = 0
        self._pending: tuple[int, str] | None = None

        self.header = QLabel("Select a process to inspect its memory map.", self)
        self.header.setWordWrap(True)

        self.model = RegionTableModel(self)
        self.table = QTableView(self)
        self.table.setModel(self.model)
        self.table.setSelectionBehavior(QTableView.SelectRows)
        self.table.setSelectionMode(QTableView.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.selectionModel().currentRowChanged.connect(self._on_region_selected)
        # Clearing the region list should not leave a stale hex dump behind
        # (e.g. when switching back to Live mode).
        self.model.modelReset.connect(self._on_model_reset)

        self.hex = QPlainTextEdit(self)
        self.hex.setReadOnly(True)
        self.hex.setFont(QFont("Consolas", 9))
        self.hex.setLineWrapMode(QPlainTextEdit.NoWrap)

        split = QSplitter(Qt.Vertical, self)
        split.addWidget(self.table)
        split.addWidget(self.hex)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.addWidget(self.header)
        layout.addWidget(split)

    # --- live mode: enumerate + allow reads --------------------------------
    def show_live_process(self, pid: int, name: str) -> None:
        self._pid = pid
        self._live = True
        self.hex.clear()
        # Clear the previous map at once and enumerate the new one in the
        # background so the GUI thread never blocks on VirtualQueryEx.
        self.model.set_regions([])
        self._load_seq += 1
        self._pending = (pid, name)
        self.header.setText(f"{name} ({pid}): reading memory map…")
        task = _RegionLoadTask(self._load_seq, pid)
        task.signals.loaded.connect(self._on_regions_loaded)
        task.signals.failed.connect(self._on_regions_failed)
        self._pool.start(task)

    def _on_regions_loaded(self, req_id: int, regions: list[Region],
                           readable: bool) -> None:
        if req_id != self._load_seq or self._pending is None:
            return  # a newer selection (or a mode switch) superseded this load
        pid, name = self._pending
        self._readable = readable
        self.model.set_regions(regions)
        note = "" if readable else "  (no read access, map only)"
        self.header.setText(f"{name} ({pid}): {len(regions)} regions{note}")

    def _on_regions_failed(self, req_id: int, message: str) -> None:
        if req_id != self._load_seq or self._pending is None:
            return
        pid, name = self._pending
        self.model.set_regions([])
        self.header.setText(f"{name} ({pid}), cannot open: {message}")

    # --- playback mode: region map from storage, no live reads -------------
    def show_recorded_regions(self, regions: list[Region], header: str,
                              heads: dict[int, bytes] | None = None) -> None:
        self._pid = None
        self._live = False
        # Invalidate any in-flight live enumeration so it can't overwrite the
        # recorded map when it finishes.
        self._load_seq += 1
        self._pending = None
        self.model.set_regions(regions, heads)
        self.header.setText(header)
        self.hex.setPlainText("(memory contents not captured in this recording)")

    def _on_model_reset(self) -> None:
        if self.model.rowCount() == 0:
            self.hex.clear()

    def _on_region_selected(self, current: QModelIndex, _prev: QModelIndex) -> None:
        region = self.model.region_at(current.row()) if current.isValid() else None
        if region is None:
            self.hex.clear()
            return
        if not self._live or self._pid is None:
            return  # playback: leave the "not captured" note in place
        if not region.is_readable:
            self.hex.setPlainText(
                f"0x{region.base_addr:012x}  {region.state_str}/{region.protect_str}"
                f", not readable"
            )
            return
        try:
            with ProcessMemory(self._pid) as pm:
                data = pm.read(region.base_addr, min(HEX_PREVIEW_BYTES, region.size))
        except ProcessAccessError as exc:
            self.hex.setPlainText(f"read failed: {exc}")
            return
        self.hex.setPlainText(hexdump(data, region.base_addr))
