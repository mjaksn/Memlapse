"""Region map + hex inspector.

Displays the VirtualQueryEx region list for a process and, on selection, a hex
dump of the region's first bytes. Used in both live mode and playback mode.

Live mode enumerates the map and reads the head of each executable region on
a pool thread, then refreshes on a timer while the view is on screen; the
heads feed the content signals and, from the second refresh on, the regions
whose head changed while watching are flagged as rewritten, and those whose
entropy fell from packed to code-like as unpacked. Playback mode shows the
region map and the captured heads from SQLite, with the same two sets taken
between consecutive samples, and the hex panel shows a fixed note, since only
the first 256 bytes of executable regions are recorded.

Both modes also mark the regions a thread starts in: live from a per-thread
query on the pool thread, playback from what the recording stored.
"""

from __future__ import annotations

import os
import tempfile
from contextlib import suppress
from pathlib import Path
from typing import Collection

from PySide6.QtCore import (
    QAbstractTableModel, QModelIndex, QObject, QRunnable, Qt, QThreadPool, QTimer,
    Signal,
)
from PySide6.QtGui import QAction, QColor, QFont
from PySide6.QtWidgets import (
    QFileDialog, QLabel, QPlainTextEdit, QSplitter, QTableView, QVBoxLayout,
    QWidget,
)

from ..analytics import (
    ALLOWLISTED, Allowlist, LIKELY_SCORE, RULE_IMAGE_REWRITTEN, RULE_REWRITTEN,
    RegionVerdict, regions_with_thread_starts, rewritten_regions, score_region,
    unpacked_regions,
)
from ..collectors.region import read_heads
from ..model.region import Region
from ..win32.memory import ProcessAccessError, ProcessMemory
from ..win32.threads import start_addresses
from .hexdump import hexdump
from .theme import heat_color

#: How many bytes to read for the hex preview of a selected region.
HEX_PREVIEW_BYTES = 512

#: Most bytes one "save region bytes" writes. A region can be gigabytes, and
#: the point of the action is to hand a payload to a disassembler or a YARA
#: rule, not to mirror an address space. A truncated save says so.
REGION_DUMP_MAX = 16 * 1024 * 1024

#: How often the live map is re-enumerated while the view is on screen. Matches
#: the recorder's default one second cadence, so what the live detector shows
#: is what a recording of the same process would replay.
LIVE_REFRESH_MS = 1000


class _RegionLoadSignals(QObject):
    """Signals for :class:`_RegionLoadTask` (QRunnable can't carry its own)."""

    #: req_id, regions (list[Region]), heads (dict[int, bytes]),
    #: thread-start region bases, the target's creation time (with the pid,
    #: which instance this map came from), readable
    loaded = Signal(int, object, object, object, "qlonglong", bool)
    #: req_id, error message
    failed = Signal(int, str)


class _RegionLoadTask(QRunnable):
    """Enumerate one process's region map off the GUI thread.

    VirtualQueryEx walks the whole address space, which for a busy process is
    tens of thousands of syscalls, long enough to freeze the window if done on
    the GUI thread. Running it in the thread pool keeps the UI responsive; the
    result, with the head bytes of each executable region for the content and
    change signals, is handed back over a queued signal.
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
                heads = read_heads(pm, regions)
                readable = pm.can_read
                # Which instance this map describes. Every later read compares
                # against it, since the pid alone can come to mean another
                # process entirely.
                created = pm.creation_time()
                # Inside the handle, which is what pins the pid: released
                # here, a target that exited could have its number reused and
                # the replacement's threads mapped onto this region list.
                # Also off the GUI thread: one handle per thread, query only.
                started = regions_with_thread_starts(
                    regions, start_addresses(self._pid).values())
        except ProcessAccessError as exc:
            self.signals.failed.emit(self._req_id, str(exc))
        except Exception as exc:  # never let a pool thread die silently
            self.signals.failed.emit(self._req_id, str(exc))
        else:
            self.signals.loaded.emit(self._req_id, regions, heads, started,
                                     created, readable)


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
        #: Base addresses whose head bytes were available when the rows were
        #: scored. A region missing from this set was never read, live or in
        #: the recording, so its content rules could not fire rather than
        #: having fired and found nothing. The held-back tooltip needs the
        #: difference; nothing else does.
        self._read: set[int] = set()

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
                if verdict.band == ALLOWLISTED:
                    # Deliberately not a heat colour. The row stays, and the
                    # score with it, but nothing here is asking to be read.
                    return QColor(128, 128, 128, 60)
                red, green, blue = heat_color(verdict.effective_score / 100.0)
                return QColor(red, green, blue, 110)  # translucent over dark theme
            if role == Qt.ToolTipRole:
                # Band first: the number alone does not say what to do with it.
                tip = (f"{verdict.band}: " + "; ".join(
                    f"{r.text} (allowlisted)" if r.allowed else r.text
                    for r in verdict.reasons))
                # A row can now show a top-band number in the review band,
                # which looks like a bug unless the row says why. Say which
                # of the two reasons it is: nothing was found in the bytes,
                # or there were no bytes to look at.
                if (verdict.map_shape_only
                        and verdict.effective_score >= LIKELY_SCORE):
                    if r.base_addr in self._read:
                        tip += ("; held at review: nothing here but the shape "
                                "of the map, which is what a JIT compiler "
                                "leaves too")
                    else:
                        tip += ("; held at review: no bytes could be read "
                                "here, so only the map had anything to say")
                return tip
        return None

    def set_regions(self, rows: list[Region],
                    heads: dict[int, bytes] | None = None,
                    rewritten: set[int] | None = None,
                    thread_starts: set[int] | None = None,
                    unpacked: set[int] | None = None,
                    allowed: Collection[str] = ()) -> None:
        """Replace the rows and score each one.

        ``heads`` carries the head bytes by base address (read live, or
        captured in the recording) and ``rewritten`` the base addresses whose
        head changed: since the previous sample in playback, while watching in
        live mode. Without heads only the structural signals apply.
        ``thread_starts`` carries the base addresses a thread starts in and
        ``unpacked`` those whose entropy fell to code-like values; both modes
        can know either. ``allowed`` is the rule ids exempted for the process
        these regions belong to, which the caller looks up; the model is
        handed the ids rather than the allowlist so it stays ignorant of what
        an entry is keyed on.
        """
        heads = heads or {}
        rewritten = rewritten or set()
        thread_starts = thread_starts or set()
        unpacked = unpacked or set()
        self.beginResetModel()
        self._rows = rows
        self._read = set(heads)
        self._verdicts = [
            score_region(r, head=heads.get(r.base_addr, b""),
                         rewritten=r.base_addr in rewritten,
                         thread_start=r.base_addr in thread_starts,
                         unpacked=r.base_addr in unpacked,
                         allowed=allowed)
            for r in rows
        ]
        self.endResetModel()

    def rewritten_count(self) -> int:
        """Regions whose rewrite still counts, allowlisted ones excluded.

        The header reports this rather than the size of the change set, so
        it cannot announce findings the bands have already excused.
        """
        return sum(
            1 for v in self._verdicts
            if any(r.rule in (RULE_REWRITTEN, RULE_IMAGE_REWRITTEN)
                   and not r.allowed for r in v.reasons)
        )

    def region_at(self, row: int) -> Region | None:
        return self._rows[row] if 0 <= row < len(self._rows) else None


class RegionView(QWidget):
    def __init__(self, parent=None, allowlist: Allowlist | None = None) -> None:
        super().__init__(parent)
        #: Rules excused per process. Empty until entries are stored and
        #: loaded (ARCHITECTURE.md, "Planned: the rest of the allowlist");
        #: an empty one scores exactly as the view did before it existed.
        self._allowlist = allowlist or Allowlist()
        self._pid: int | None = None
        self._live = True  # live -> can read bytes; playback -> cannot
        #: Creation time of the instance the current map came from. With the
        #: pid it identifies one process, which is what every later read is
        #: checked against.
        self._created = 0

        # Live region maps are enumerated off the GUI thread. Each request gets
        # a monotonic id; only the newest one's result is applied, so rapidly
        # clicking through processes (or switching to playback) can't be clobbered
        # by a slow enumeration that finished late.
        self._pool = QThreadPool.globalInstance()
        self._load_seq = 0
        self._pending: tuple[int, str] | None = None
        self._in_flight = False

        # Live mode re-enumerates on a timer. The previous refresh's regions
        # and head bytes feed the change and entropy detectors, and a region
        # seen rewritten or unpacked stays flagged while it is still there,
        # since a change that showed for one tick and vanished would be a
        # detector nobody sees. Keeping the bytes rather than their hashes
        # costs 256 bytes a region, under 200 KiB for the largest process on
        # this machine, and is what lets the entropy rule run live at all.
        self._refresh = QTimer(self)
        self._refresh.setInterval(LIVE_REFRESH_MS)
        self._refresh.timeout.connect(self._on_refresh_tick)
        self._prev_regions: list[Region] = []
        self._prev_heads: dict[int, bytes] = {}
        self._live_rewritten: set[int] = set()
        self._live_unpacked: set[int] = set()

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
        # Right-click a row to keep its bytes. Live only: a recording holds
        # the first 256 bytes of executable regions, which is not a dump.
        self.save_action = QAction("Save region bytes\u2026", self)
        self.save_action.triggered.connect(self.save_selected_region)
        self.table.setContextMenuPolicy(Qt.ActionsContextMenu)
        self.table.addAction(self.save_action)
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
        # background so the GUI thread never blocks on VirtualQueryEx. A new
        # selection starts the change history afresh, even for the same pid.
        self.model.set_regions([])
        self._created = 0
        self._prev_regions = []
        self._prev_heads = {}
        self._live_rewritten = set()
        self._live_unpacked = set()
        self._pending = (pid, name)
        self.header.setText(f"{name} ({pid}): reading memory map…")
        self._start_load(pid)
        self._refresh.start()

    def _start_load(self, pid: int) -> None:
        self._load_seq += 1
        self._in_flight = True
        task = _RegionLoadTask(self._load_seq, pid)
        task.signals.loaded.connect(self._on_regions_loaded)
        task.signals.failed.connect(self._on_regions_failed)
        self._pool.start(task)

    def _on_refresh_tick(self) -> None:
        """Re-enumerate the watched process, latest-only and only when seen.

        A tick is skipped while the previous load is still running (the same
        no-backlog rule the collectors follow) and while the view is hidden,
        so the Dashboard tab does not pay for a VirtualQueryEx walk a second.
        """
        if not self._live or self._pid is None:
            self._refresh.stop()
            return
        if self._in_flight or not self.isVisible():
            return
        self._start_load(self._pid)

    def _on_regions_loaded(self, req_id: int, regions: list[Region],
                           heads: dict[int, bytes], thread_starts: set[int],
                           created: int, readable: bool) -> None:
        if req_id != self._load_seq or self._pending is None:
            return  # a newer selection (or a mode switch) superseded this load
        self._in_flight = False
        pid, name = self._pending
        if self._created and created != self._created:
            # A later refresh reached a different process under the same
            # number. Adopting it would compare a stranger's memory against
            # the heads of the process being watched and report every
            # difference as code rewritten in place, which is the loudest
            # thing this view can say. The last map read from the real
            # target stays on screen, since it is the final observation of
            # it; every read from it is already refused by the same check.
            self._refresh.stop()
            self.header.setText(self._STALE.format(pid=pid))
            return
        self._created = created
        # The heads are compared directly, which is the same equality test the
        # stored hashes give playback and saves hashing every head a second.
        changed = rewritten_regions(self._prev_regions, self._prev_heads,
                                    regions, heads)
        # Only what changed on this refresh: the sticky set below would compare
        # a head with itself and never fall.
        fell = unpacked_regions(self._prev_heads, heads, changed)
        present = {r.base_addr for r in regions}
        self._live_rewritten = (self._live_rewritten & present) | changed
        self._live_unpacked = (self._live_unpacked & present) | fell
        self._prev_regions, self._prev_heads = regions, heads
        self._replace_rows(regions, heads, self._live_rewritten, thread_starts,
                           self._live_unpacked,
                           self._allowlist.rules_for(name))
        note = "" if readable else "  (no read access, map only)"
        # From the verdicts, not the change set: a rewrite this process is
        # excused for is not a finding, so the header must not count it.
        flagged = self.model.rewritten_count()
        change = f", {flagged} rewritten while watching" if flagged else ""
        self.header.setText(
            f"{name} ({pid}): {len(regions)} regions{change}{note}"
        )

    def _replace_rows(self, regions: list[Region], heads: dict[int, bytes],
                      rewritten: set[int], thread_starts: set[int],
                      unpacked: set[int], allowed: Collection[str] = ()) -> None:
        """Reset the model without losing the analyst's place.

        A model reset drops the current row silently, which would blank the
        hex panel and scroll to the top on every refresh. Reselecting the same
        base address re-reads its preview (the refresh the analyst wants) and
        the scroll position is restored last, since selecting a row scrolls.
        """
        current = self.model.region_at(self.table.currentIndex().row())
        scroll = self.table.verticalScrollBar().value()
        self.model.set_regions(regions, heads, rewritten, thread_starts,
                               unpacked, allowed)
        if current is not None:
            for row, r in enumerate(regions):
                if r.base_addr == current.base_addr:
                    self.table.selectRow(row)
                    break
            else:
                self.hex.clear()
        self.table.verticalScrollBar().setValue(scroll)

    def _on_regions_failed(self, req_id: int, message: str) -> None:
        if req_id != self._load_seq or self._pending is None:
            return
        self._in_flight = False
        self._refresh.stop()  # the target is gone or closed to us
        pid, name = self._pending
        self.model.set_regions([])
        self.header.setText(f"{name} ({pid}), cannot open: {message}")

    # --- playback mode: region map from storage, no live reads -------------
    def show_recorded_regions(self, regions: list[Region], header: str,
                              heads: dict[int, bytes] | None = None,
                              rewritten: set[int] | None = None,
                              thread_starts: set[int] | None = None,
                              unpacked: set[int] | None = None,
                              image_name: str = "") -> None:
        """Show a map from storage. ``image_name`` is the recorded process,
        looked up in the allowlist exactly as live mode looks up the process
        it is watching: an entry has to mean the same thing in both modes or
        a replay contradicts the watch it came from.
        """
        self._pid = None
        self._live = False
        # Invalidate any in-flight live enumeration so it can't overwrite the
        # recorded map when it finishes, and stop refreshing.
        self._refresh.stop()
        self._load_seq += 1
        self._pending = None
        self._in_flight = False
        self.model.set_regions(regions, heads, rewritten, thread_starts,
                               unpacked,
                               self._allowlist.rules_for(image_name))
        self.header.setText(header)
        self.hex.setPlainText(
            "(hex preview is live only; a recording keeps the first 256 bytes of "
            "executable regions for scoring, not for display)"
        )

    def _on_model_reset(self) -> None:
        if self.model.rowCount() == 0:
            self.hex.clear()

    def _same_instance(self, pm: ProcessMemory) -> bool:
        """Is the handle on the process the region map was read from?

        Windows reuses pids. A target that exits between the map being read
        and an analyst asking for bytes can be replaced by something unrelated
        under the same number, and those bytes would then be filed under the
        old selection. The handle is already open here, which is what pins the
        pid, so comparing creation times closes the window rather than
        narrowing it.
        """
        return pm.creation_time() == self._created

    #: Shown when the pid no longer names the process the map came from.
    _STALE = "process {pid} has exited; the pid now belongs to another process"

    def _on_region_selected(self, current: QModelIndex, _prev: QModelIndex) -> None:
        region = self.model.region_at(current.row()) if current.isValid() else None
        if region is None:
            self.hex.clear()
            return
        if not self._live or self._pid is None:
            return  # playback: leave the live-only note in place
        if not region.is_readable:
            self.hex.setPlainText(
                f"0x{region.base_addr:012x}  {region.state_str}/{region.protect_str}"
                f", not readable"
            )
            return
        try:
            with ProcessMemory(self._pid) as pm:
                if not self._same_instance(pm):
                    self.hex.setPlainText(self._STALE.format(pid=self._pid))
                    return
                data = pm.read(region.base_addr, min(HEX_PREVIEW_BYTES, region.size))
        except ProcessAccessError as exc:
            self.hex.setPlainText(f"read failed: {exc}")
            return
        self.hex.setPlainText(hexdump(data, region.base_addr))

    # --- evidence: keep a region's bytes -----------------------------------
    def save_selected_region(self) -> None:
        """Write the selected region's bytes to a file the analyst chooses.

        The header carries the outcome, since this view has no status bar of
        its own and the analyst just asked for the thing being reported. Live
        mode only: playback stores the first 256 bytes of executable regions
        for scoring, which would make a misleading dump.
        """
        region = self.model.region_at(self.table.currentIndex().row())
        if region is None:
            self.header.setText("Select a region first, then save its bytes.")
            return
        if not self._live or self._pid is None:
            self.header.setText(
                "Saving bytes is live only; a recording keeps 256 bytes a region."
            )
            return
        path, _filter = QFileDialog.getSaveFileName(
            self, "Save region bytes",
            f"{self._pid}-{region.base_addr:012x}.bin", "Raw bytes (*.bin)",
        )
        if not path:
            return  # cancelled
        wanted = min(region.size, REGION_DUMP_MAX)
        try:
            with ProcessMemory(self._pid) as pm:
                if not self._same_instance(pm):
                    # Refusing is the only honest answer: bytes from a
                    # replacement process filed under this selection would be
                    # evidence of nothing.
                    self.header.setText(
                        "save refused: " + self._STALE.format(pid=self._pid)
                    )
                    return
                data = pm.read(region.base_addr, wanted)
        except ProcessAccessError as exc:
            self.header.setText(f"save failed: {exc}")
            return
        if not data:
            self.header.setText(
                f"0x{region.base_addr:012x}: nothing readable to save"
            )
            return
        # Write beside the target and rename onto it once the bytes are all
        # there. A read failure already reports through the header and a write
        # failure has to as well, but it must not cost the analyst a file that
        # was already on disk: writing in place would truncate the chosen file
        # first, so a failure part way through would destroy it. Only the
        # temporary file ever holds a partial region.
        target = Path(path)
        try:
            handle, temp_name = tempfile.mkstemp(
                dir=target.parent, prefix=f"{target.name}.", suffix=".part"
            )
            try:
                with os.fdopen(handle, "wb") as out:
                    out.write(data)
                os.replace(temp_name, target)
            except OSError:
                with suppress(OSError):
                    os.unlink(temp_name)
                raise
        except OSError as exc:
            self.header.setText(f"save failed: {exc}")
            return
        # A short save has two different causes and the analyst needs to know
        # which: the cap is our decision, a short read is the target's. They
        # can happen to the same save, so each is reported on its own; folding
        # them together would let our cap hide the target's short read.
        notes = []
        if region.size > REGION_DUMP_MAX:
            notes.append(f"capped at {_fmt_size(REGION_DUMP_MAX)} of "
                         f"{_fmt_size(region.size)}")
        if len(data) < wanted:
            notes.append(f"short read of {_fmt_size(wanted)}")
        note = "".join(f", {n}" for n in notes)
        self.header.setText(
            f"saved {_fmt_size(len(data))} from 0x{region.base_addr:012x}{note}"
        )
