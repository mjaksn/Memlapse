"""Main application window.

Two modes:

* **Live**, the ProcessCollector streams the process list; selecting a process
  shows its live memory map, refreshed every second while on screen and scored
  with the content signals, the regions rewritten while watching and the ones
  that unpacked themselves there.
* **Playback**, a recording is opened; the timeline scrubber drives the region
  view from stored samples (no live reads), including the regions rewritten
  since the previous sample, the ones that unpacked between samples and the
  regions a thread started in.

Recording is available in live mode: pick a process, hit Record, and a
RegionSampler writes samples to SQLite until you stop.
"""

from __future__ import annotations

import time

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDockWidget, QLabel, QMainWindow, QMenu, QMessageBox, QSplitter, QTabWidget,
    QToolBar, QToolButton,
)

from ..collectors import ProcessCollector, SystemCollector
from ..model import ProcessInfo
from ..services import PlaybackEngine, RecordingManager
from ..win32 import privileges
from .dashboard import DashboardView
from .process_view import ProcessView
from .region_view import RegionView
from .timeline import TimelineWidget


def _fmt_bytes(n: int) -> str:
    value = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024.0:
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{value:.1f} PB"


class MainWindow(QMainWindow):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Memlapse: Memory Monitor")
        self.resize(1100, 700)

        self._mode = "live"          # "live" | "playback"
        self._selected_pid: int | None = None
        self._selected_name: str = ""
        # Owned by the GUI thread; each collector hands its total over.
        self._process_count = 0
        self._dropped = {"process": 0, "system": 0}

        # --- central layout ------------------------------------------------
        self.process_view = ProcessView(self)
        self.region_view = RegionView(self)
        splitter = QSplitter(Qt.Horizontal, self)
        splitter.addWidget(self.process_view)
        splitter.addWidget(self.region_view)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)

        # A vivid, near-live dashboard sits alongside the forensic monitor.
        self.dashboard = DashboardView(self)
        self.dashboard.processActivated.connect(self._on_dashboard_activate)

        self._monitor_tab = splitter
        self.tabs = QTabWidget(self)
        self.tabs.addTab(self.dashboard, "Dashboard")
        self.tabs.addTab(splitter, "Forensic Monitor")
        self.setCentralWidget(self.tabs)

        self.process_view.processSelected.connect(self._on_process_selected)

        # --- timeline dock (playback only) ---------------------------------
        self.timeline = TimelineWidget(self)
        self.timeline.seek.connect(self._on_seek)
        self._timeline_dock = QDockWidget("Timeline", self)
        self._timeline_dock.setWidget(self.timeline)
        self._timeline_dock.setFeatures(QDockWidget.NoDockWidgetFeatures)
        self.addDockWidget(Qt.BottomDockWidgetArea, self._timeline_dock)
        self._timeline_dock.hide()

        # --- services ------------------------------------------------------
        self.recorder = RecordingManager(parent=self)
        self.recorder.started.connect(self._on_recording_started)
        self.recorder.sampled.connect(self._on_sampled)
        self.recorder.stopped.connect(self._on_recording_stopped)
        self.playback: PlaybackEngine | None = None

        self._build_toolbar()

        # --- status bar ----------------------------------------------------
        self._status_label = QLabel("", self)
        self.statusBar().addPermanentWidget(self._status_label)
        self.statusBar().showMessage(self._privilege_summary())

        # --- live process stream -------------------------------------------
        self.collector = ProcessCollector(interval=1.0, parent=self)
        self.collector.updated.connect(self._on_processes)
        self.collector.updated.connect(self.dashboard.update_processes)
        self.collector.dropped.connect(
            lambda total: self._on_dropped("process", total)
        )
        self.collector.start()

        # --- system-wide memory stream (drives the dashboard) --------------
        self.system_collector = SystemCollector(interval=1.0, parent=self)
        self.system_collector.updated.connect(self.dashboard.update_system)
        self.system_collector.dropped.connect(
            lambda total: self._on_dropped("system", total)
        )
        self.system_collector.start()

    # --- toolbar ----------------------------------------------------------
    def _build_toolbar(self) -> None:
        tb = QToolBar("Main", self)
        tb.setMovable(False)
        self.addToolBar(tb)

        self.record_action = tb.addAction("● Record")
        self.record_action.setEnabled(False)
        self.record_action.triggered.connect(self._toggle_record)

        self.open_btn = QToolButton(self)
        self.open_btn.setText("Open Recording ▾")
        self.open_btn.setPopupMode(QToolButton.InstantPopup)
        self._recordings_menu = QMenu(self.open_btn)
        self._recordings_menu.aboutToShow.connect(self._populate_recordings)
        self.open_btn.setMenu(self._recordings_menu)
        tb.addWidget(self.open_btn)

        self.live_action = tb.addAction("Live")
        self.live_action.setEnabled(False)
        self.live_action.triggered.connect(self._enter_live_mode)

    def _privilege_summary(self) -> str:
        admin = "yes" if privileges.is_elevated() else "no"
        debug = "enabled" if privileges.enable_se_debug_privilege() else "unavailable"
        return f"Administrator: {admin}   |   SeDebugPrivilege: {debug}"

    # --- live mode --------------------------------------------------------
    def _on_processes(self, rows: list[ProcessInfo]) -> None:
        if self._mode == "live":
            self.process_view.update_processes(rows)
            self._process_count = len(rows)
            self._refresh_status()

    def _on_dropped(self, which: str, total: int) -> None:
        """Record a collector's dropped-poll total, handed over by signal.

        Latest-only delivery drops a poll when the GUI is still busy with the
        last one, and counting them is only honest if it shows. Both streams
        drop independently, so each is named: the system poll feeds the
        dashboard, and its drops would otherwise be invisible.
        """
        self._dropped[which] = total
        # The collectors keep running during playback, where the status line
        # belongs to the recording and the live count behind it is stale. The
        # total is kept either way and shown again on the return to live.
        if self._mode == "live":
            self._refresh_status()

    def _refresh_status(self) -> None:
        note = "".join(
            f", {self._dropped[which]} {which} polls dropped"
            for which in ("process", "system") if self._dropped[which]
        )
        self._status_label.setText(f"{self._process_count} processes{note}")

    def _on_process_selected(self, pid: int, name: str) -> None:
        self._selected_pid = pid
        self._selected_name = name
        if not self.recorder.is_recording:
            self.record_action.setEnabled(True)
        if self._mode == "live":
            self.region_view.show_live_process(pid, name)

    def _on_dashboard_activate(self, pid: int, name: str) -> None:
        """Drill from the dashboard into the forensic monitor for a process."""
        self.tabs.setCurrentWidget(self._monitor_tab)
        self.process_view.select_pid(pid)

    def _enter_live_mode(self) -> None:
        if self.recorder.is_recording:
            return
        self._mode = "live"
        self._timeline_dock.hide()
        self.live_action.setEnabled(False)
        if self.playback is not None:
            self.playback.close()
            self.playback = None
        self._refresh_status()   # the live counts, including any drops, return
        # Coming back from playback must land where live mode left off. The
        # selection never changed, so clearing the map and leaving Record
        # disabled strands the analyst: re-picking the same row emits nothing,
        # since the process view still holds it as the current selection.
        self.record_action.setEnabled(self._selected_pid is not None)
        if self._selected_pid is not None:
            self.region_view.show_live_process(self._selected_pid,
                                               self._selected_name)
        else:
            self.region_view.header.setText(
                "Select a process to inspect its memory map.")
            self.region_view.model.set_regions([])
        self.statusBar().showMessage("Live mode", 3000)

    # --- recording --------------------------------------------------------
    def _toggle_record(self) -> None:
        if self.recorder.is_recording:
            self.recorder.stop()
            return
        if self._selected_pid is None:
            return
        self.recorder.start(self._selected_pid, self._selected_name)

    def _on_recording_started(self, recording_id: int) -> None:
        self.record_action.setText("■ Stop")
        self.statusBar().showMessage(
            f"Recording {self._selected_name} ({self._selected_pid}) "
            f"→ recording #{recording_id}"
        )

    def _on_sampled(self, ts_us: int, region_count: int) -> None:
        self._status_label.setText(f"recording, {region_count} regions @ last sample")

    def _on_recording_stopped(self, reason: str) -> None:
        self.record_action.setText("● Record")
        self.record_action.setEnabled(self._selected_pid is not None)
        self.statusBar().showMessage(f"Recording stopped: {reason}", 5000)

    # --- playback ---------------------------------------------------------
    def _populate_recordings(self) -> None:
        self._recordings_menu.clear()
        engine = PlaybackEngine()
        try:
            recordings = engine.list_recordings()
        finally:
            engine.close()
        if not recordings:
            self._recordings_menu.addAction("(no recordings yet)").setEnabled(False)
            return
        for rec in recordings:
            started = time.strftime("%Y-%m-%d %H:%M:%S",
                                    time.localtime(rec.started_utc / 1_000_000))
            label = f"#{rec.id}  {rec.target_name} ({rec.target_pid}),  {started}"
            self._recordings_menu.addAction(label).triggered.connect(
                lambda _=False, rid=rec.id: self._open_recording(rid)
            )

    def _open_recording(self, recording_id: int) -> None:
        if self.recorder.is_recording:
            QMessageBox.information(self, "Memlapse", "Stop the current recording first.")
            return
        if self.playback is not None:
            self.playback.close()
        self.playback = PlaybackEngine()
        times = self.playback.open(recording_id)
        self._mode = "playback"
        self.live_action.setEnabled(True)
        self.record_action.setEnabled(False)
        self._timeline_dock.show()
        self.timeline.set_sample_times(times)
        if not times:
            self.region_view.show_recorded_regions([], "Recording has no samples.")
        self.statusBar().showMessage(
            f"Playback: recording #{recording_id}, {len(times)} samples"
        )

    def _on_seek(self, ts_us: int) -> None:
        if self._mode != "playback" or self.playback is None:
            return
        state, regions = self.playback.seek(ts_us)
        heads = self.playback.heads(ts_us)
        rewritten = self.playback.rewritten(ts_us)
        thread_starts = self.playback.thread_start_regions(ts_us)
        unpacked = self.playback.unpacked(ts_us, rewritten)
        if state is not None:
            header = (
                f"Recording #{self.playback.recording_id}, PID {state.pid}, "
                f"{len(regions)} regions | WS {_fmt_bytes(state.wset_bytes)} | "
                f"Priv {_fmt_bytes(state.priv_bytes)} | {state.thread_count} threads"
            )
            self._status_label.setText(
                f"WS {_fmt_bytes(state.wset_bytes)}  |  {state.thread_count} threads"
            )
        else:
            header = f"Recording #{self.playback.recording_id}, no data at this time"
        self.region_view.show_recorded_regions(regions, header, heads, rewritten,
                                               thread_starts, unpacked,
                                               self.playback.target_name)

    # --- shutdown ---------------------------------------------------------
    def closeEvent(self, event) -> None:
        self.recorder.stop()
        self.collector.stop()
        self.collector.wait(2000)
        self.system_collector.stop()
        self.system_collector.wait(2000)
        if self.playback is not None:
            self.playback.close()
        super().closeEvent(event)
