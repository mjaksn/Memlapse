"""Vivid near-live memory dashboard.

An additive view over the same collector streams that drive the forensic
monitor:

* system-wide **gauges** (RAM %, swap %) with a live used/total readout,
* a scrolling **RAM timeline** (pyqtgraph) over the last ~10 minutes,
* a heat-ranked **top-process** bar list, and
* an **interpret** strip (leak rate / anomaly / biggest mover).

Clicking a process emits :data:`processActivated` so the main window can drill
into it in the forensic monitor. **Export** writes the current window to
CSV/JSON. All aggregation happens on the GUI thread from queued signals; the
heavy lifting stays in the collectors.
"""

from __future__ import annotations

import csv
import json

import pyqtgraph as pg
from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QColor, QPainter
from PySide6.QtWidgets import (
    QFileDialog, QFrame, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget,
)

from ..analytics import (
    SeriesBuffer, leak_rate_bytes_per_sec, top_movers, zscore,
)
from ..model import ProcessInfo, SystemSample
from . import theme
from .gauges import AnimatedGauge

HISTORY = 600          # samples retained (~10 min at 1 Hz)
TOP_N = 8              # process bars shown
LEAK_WARN_PER_MIN = 5 * 1024 * 1024   # 5 MB/min triggers a climbing/falling note
ANOMALY_Z = 3.0


def _fmt_bytes(n: float) -> str:
    value = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024.0:
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{value:.1f} PB"


def _panel(title: str) -> tuple[QFrame, QVBoxLayout]:
    frame = QFrame()
    frame.setObjectName("Panel")
    lay = QVBoxLayout(frame)
    lay.setContentsMargins(12, 10, 12, 12)
    if title:
        lbl = QLabel(title.upper())
        lbl.setObjectName("PanelTitle")
        lay.addWidget(lbl)
    return frame, lay


class ProcessBar(QWidget):
    """A labelled heat bar for one top process (click to drill in)."""

    clicked = Signal(int, str)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._pid = -1
        self._name = ""
        self._width_frac = 0.0
        self._color_frac = 0.0
        self._text = ""
        self.setMinimumHeight(22)
        self.setCursor(Qt.PointingHandCursor)

    def set_value(
        self, pid: int, name: str, width_frac: float, color_frac: float, text: str
    ) -> None:
        self._pid, self._name, self._text = pid, name, text
        self._width_frac = max(0.0, min(1.0, width_frac))
        self._color_frac = max(0.0, min(1.0, color_frac))
        self.update()

    def mousePressEvent(self, _event) -> None:
        if self._pid >= 0:
            self.clicked.emit(self._pid, self._name)

    def paintEvent(self, _event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)
        w, h = self.width(), self.height()
        p.setPen(Qt.NoPen)
        p.setBrush(QColor(theme.GRID))
        p.drawRoundedRect(0, 4, w, h - 8, 5, 5)
        if self._width_frac > 0.0:
            r, g, b = theme.heat_color(self._color_frac)
            p.setBrush(QColor(r, g, b))
            p.drawRoundedRect(0, 4, int(w * self._width_frac), h - 8, 5, 5)
        p.setPen(QColor(theme.TEXT))
        p.drawText(8, 0, w - 16, h, Qt.AlignVCenter | Qt.AlignLeft, self._name)
        p.setPen(QColor(theme.MUTED))
        p.drawText(8, 0, w - 16, h, Qt.AlignVCenter | Qt.AlignRight, self._text)
        p.end()


class DashboardView(QWidget):
    #: Emitted (pid, name) when a process bar is clicked.
    processActivated = Signal(int, str)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("Dashboard")
        theme.configure_pyqtgraph()
        self.setStyleSheet(theme.DASHBOARD_QSS)

        self._used = SeriesBuffer(HISTORY)
        self._percent = SeriesBuffer(HISTORY)
        self._prev_ws: dict[int, tuple[str, int]] = {}
        self._mover_text = ""
        self._latest_system: SystemSample | None = None

        self._build_ui()

        # render timer eases the gauges independently of the ~1 Hz data feed
        self._render = QTimer(self)
        self._render.setInterval(33)  # ~30 fps
        self._render.timeout.connect(self._on_render)
        self._render.start()

    # --- construction -----------------------------------------------------
    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(14, 14, 14, 14)
        root.setSpacing(12)

        # top row: gauges + timeline
        top = QHBoxLayout()
        top.setSpacing(12)

        gauges_frame, gauges_lay = _panel("System Memory")
        grow = QHBoxLayout()
        self.ram_gauge = AnimatedGauge("RAM")
        self.swap_gauge = AnimatedGauge("SWAP")
        grow.addWidget(self.ram_gauge)
        grow.addWidget(self.swap_gauge)
        gauges_lay.addLayout(grow)
        self.readout = QLabel("—")
        self.readout.setObjectName("Insight")
        self.readout.setAlignment(Qt.AlignCenter)
        gauges_lay.addWidget(self.readout)
        gauges_frame.setFixedWidth(320)
        top.addWidget(gauges_frame)

        chart_frame, chart_lay = _panel("RAM Usage — last 10 min")
        self.plot = pg.PlotWidget()
        self.plot.setBackground(theme.BG)
        self.plot.showGrid(x=True, y=True, alpha=0.15)
        self.plot.setYRange(0, 100)
        self.plot.setMouseEnabled(x=False, y=False)
        self.plot.setMenuEnabled(False)
        self.plot.getPlotItem().hideButtons()
        self.plot.setLabel("left", "%")
        self.plot.setLabel("bottom", "seconds ago")
        self.curve = self.plot.plot(
            pen=pg.mkPen(theme.ACCENT, width=2),
            fillLevel=0,
            brush=pg.mkBrush(0, 229, 255, 45),
        )
        chart_lay.addWidget(self.plot)
        top.addWidget(chart_frame, 1)
        root.addLayout(top, 1)

        # middle: top processes
        proc_frame, proc_lay = _panel(f"Top {TOP_N} Processes — working set")
        self._bars: list[ProcessBar] = []
        for _ in range(TOP_N):
            bar = ProcessBar()
            bar.clicked.connect(self.processActivated)
            self._bars.append(bar)
            proc_lay.addWidget(bar)
        root.addWidget(proc_frame)

        # bottom: interpret strip + export
        bottom = QHBoxLayout()
        self.insight = QLabel("Collecting telemetry…")
        self.insight.setObjectName("Insight")
        bottom.addWidget(self.insight, 1)
        self.export_btn = QPushButton("Export window")
        self.export_btn.setObjectName("Export")
        self.export_btn.clicked.connect(self._export)
        bottom.addWidget(self.export_btn)
        root.addLayout(bottom)

    # --- data feeds (called on the GUI thread via queued signals) ---------
    def update_system(self, s: SystemSample) -> None:
        self._latest_system = s
        self._used.append(s.ts_us, float(s.used))
        self._percent.append(s.ts_us, s.percent)
        self.ram_gauge.set_target(s.percent, _fmt_bytes(s.used))
        self.swap_gauge.set_target(s.swap_percent, _fmt_bytes(s.swap_used))
        self.readout.setText(
            f"{_fmt_bytes(s.used)} / {_fmt_bytes(s.total)}   ·   "
            f"{_fmt_bytes(s.available)} free"
        )
        self._refresh_chart()
        self._refresh_insight()

    def update_processes(self, rows: list[ProcessInfo]) -> None:
        total = self._latest_system.total if self._latest_system else 0
        top = sorted(rows, key=lambda p: p.wset_bytes, reverse=True)[:TOP_N]
        max_ws = top[0].wset_bytes if top else 0
        for i, bar in enumerate(self._bars):
            if i < len(top):
                p = top[i]
                width = (p.wset_bytes / max_ws) if max_ws else 0.0
                color = (p.wset_bytes / total) if total else width
                bar.set_value(p.pid, p.name, width, color, _fmt_bytes(p.wset_bytes))
                bar.show()
            else:
                bar.hide()

        curr = {p.pid: (p.name, p.wset_bytes) for p in rows}
        if self._prev_ws:
            movers = top_movers(self._prev_ws, curr, 1)
            if movers:
                m = movers[0]
                arrow = "▲" if m.delta_bytes > 0 else "▼"
                self._mover_text = f"{arrow} {m.name} {_fmt_bytes(abs(m.delta_bytes))}"
            else:
                self._mover_text = ""
        self._prev_ws = curr

    # --- rendering / interpretation ---------------------------------------
    def _refresh_chart(self) -> None:
        times = self._percent.times()
        vals = self._percent.values()
        if not times:
            return
        now = times[-1]
        xs = [(t - now) / 1_000_000 for t in times]  # seconds ago (<= 0)
        self.curve.setData(xs, vals)

    def _refresh_insight(self) -> None:
        times = self._used.times()
        used = self._used.values()
        per_min = leak_rate_bytes_per_sec(times[-60:], used[-60:]) * 60
        z = zscore(self._percent.values()[-120:])

        parts: list[str] = []
        if per_min > LEAK_WARN_PER_MIN:
            parts.append(f"▲ RAM climbing {_fmt_bytes(per_min)}/min")
        elif per_min < -LEAK_WARN_PER_MIN:
            parts.append(f"▼ RAM falling {_fmt_bytes(-per_min)}/min")
        else:
            parts.append("● RAM steady")
        if abs(z) >= ANOMALY_Z:
            parts.append(f"⚠ anomaly z={z:.1f}")
        if self._mover_text:
            parts.append(f"mover: {self._mover_text}")
        self.insight.setText("      ".join(parts))

    def _on_render(self) -> None:
        self.ram_gauge.animate_step()
        self.swap_gauge.animate_step()

    # --- export -----------------------------------------------------------
    def _export(self) -> None:
        path, _filter = QFileDialog.getSaveFileName(
            self, "Export memory window", "memdo-window",
            "CSV (*.csv);;JSON (*.json)",
        )
        if not path:
            return
        rows = [
            {"ts_us": t, "percent": pc, "used_bytes": int(u)}
            for t, pc, u in zip(
                self._percent.times(), self._percent.values(), self._used.values()
            )
        ]
        if path.lower().endswith(".json"):
            with open(path, "w", encoding="utf-8") as f:
                json.dump(rows, f, indent=2)
        else:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=["ts_us", "percent", "used_bytes"])
                writer.writeheader()
                writer.writerows(rows)
