"""Region map + hex inspector.

Displays the VirtualQueryEx region list for a process and, on selection, a hex
dump of the region's first bytes. Used in both live mode (reads memory on the
fly via ProcessMemory) and playback mode (region map from SQLite, no bytes ->
hex panel explains they weren't captured).
"""

from __future__ import annotations

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QLabel, QPlainTextEdit, QSplitter, QTableView, QVBoxLayout, QWidget,
)

from ..model.region import Region
from ..win32.memory import ProcessAccessError, ProcessMemory
from .hexdump import hexdump

#: How many bytes to read for the hex preview of a selected region.
HEX_PREVIEW_BYTES = 512


def _fmt_size(n: int) -> str:
    value = float(n)
    for unit in ("B", "K", "M", "G", "T"):
        if value < 1024.0:
            return f"{value:.0f}{unit}" if unit == "B" else f"{value:.1f}{unit}"
        value /= 1024.0
    return f"{value:.1f}P"


class RegionTableModel(QAbstractTableModel):
    COLUMNS = ("Base Address", "Size", "State", "Protect", "Type")

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._rows: list[Region] = []

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
        r = self._rows[index.row()]
        if role == Qt.DisplayRole:
            return (
                f"0x{r.base_addr:012x}", _fmt_size(r.size),
                r.state_str, r.protect_str, r.type_str,
            )[index.column()]
        if role == Qt.TextAlignmentRole and index.column() in (1,):
            return int(Qt.AlignRight | Qt.AlignVCenter)
        return None

    def set_regions(self, rows: list[Region]) -> None:
        self.beginResetModel()
        self._rows = rows
        self.endResetModel()

    def region_at(self, row: int) -> Region | None:
        return self._rows[row] if 0 <= row < len(self._rows) else None


class RegionView(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._pid: int | None = None
        self._live = True  # live -> can read bytes; playback -> cannot

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
        try:
            with ProcessMemory(pid) as pm:
                regions = pm.regions()
                self._readable = pm.can_read
        except ProcessAccessError as exc:
            self.model.set_regions([])
            self.header.setText(f"{name} ({pid}) — cannot open: {exc}")
            return
        self.model.set_regions(regions)
        note = "" if self._readable else "  (no read access — map only)"
        self.header.setText(
            f"{name} ({pid}) — {len(regions)} regions{note}"
        )

    # --- playback mode: region map from storage, no live reads -------------
    def show_recorded_regions(self, regions: list[Region], header: str) -> None:
        self._pid = None
        self._live = False
        self.model.set_regions(regions)
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
                f" — not readable"
            )
            return
        try:
            with ProcessMemory(self._pid) as pm:
                data = pm.read(region.base_addr, min(HEX_PREVIEW_BYTES, region.size))
        except ProcessAccessError as exc:
            self.hex.setPlainText(f"read failed: {exc}")
            return
        self.hex.setPlainText(hexdump(data, region.base_addr))
