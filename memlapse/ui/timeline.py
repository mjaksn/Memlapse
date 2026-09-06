"""Timeline scrubber for playback.

A slider indexed over a recording's discrete sample timestamps, plus a
play/pause button that steps through them on a timer. Emits ``seek(ts_us)``
whenever the position changes so the main window can rebuild state at that
time.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QHBoxLayout, QLabel, QPushButton, QSlider, QWidget,
)

#: Playback step interval in ms (advance one sample per tick).
PLAY_STEP_MS = 250


def _fmt_elapsed(us: int) -> str:
    seconds = us / 1_000_000
    minutes, secs = divmod(seconds, 60)
    return f"{int(minutes):02d}:{secs:06.3f}"


class TimelineWidget(QWidget):
    seek = Signal("qlonglong")  # ts_us (64-bit epoch microseconds)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._times: list[int] = []

        self.play_btn = QPushButton("▶", self)
        self.play_btn.setFixedWidth(36)
        self.play_btn.setEnabled(False)
        self.play_btn.clicked.connect(self._toggle_play)

        self.slider = QSlider(Qt.Horizontal, self)
        self.slider.setEnabled(False)
        self.slider.valueChanged.connect(self._on_slider)

        self.time_label = QLabel("--:--.---", self)
        self.time_label.setMinimumWidth(140)
        self.time_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self._timer = QTimer(self)
        self._timer.setInterval(PLAY_STEP_MS)
        self._timer.timeout.connect(self._advance)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(6, 3, 6, 3)
        layout.addWidget(self.play_btn)
        layout.addWidget(self.slider, 1)
        layout.addWidget(self.time_label)

    def set_sample_times(self, times: list[int]) -> None:
        self._stop_timer()
        self._times = times
        has = len(times) > 0
        self.slider.setEnabled(has)
        self.play_btn.setEnabled(has)
        if has:
            self.slider.setRange(0, len(times) - 1)
            self.slider.setValue(0)
            self._on_slider(0)  # emit initial state
        else:
            self.time_label.setText("--:--.---")

    # --- slider / playback -------------------------------------------------
    def _on_slider(self, index: int) -> None:
        if not self._times:
            return
        index = max(0, min(index, len(self._times) - 1))
        ts = self._times[index]
        self.time_label.setText(
            f"{_fmt_elapsed(ts - self._times[0])}   [{index + 1}/{len(self._times)}]"
        )
        self.seek.emit(ts)

    def _toggle_play(self) -> None:
        if self._timer.isActive():
            self._stop_timer()
        elif self._times:
            if self.slider.value() >= len(self._times) - 1:
                self.slider.setValue(0)  # restart from the beginning
            self._timer.start()
            self.play_btn.setText("⏸")

    def _advance(self) -> None:
        nxt = self.slider.value() + 1
        if nxt >= len(self._times):
            self._stop_timer()
            return
        self.slider.setValue(nxt)

    def _stop_timer(self) -> None:
        self._timer.stop()
        self.play_btn.setText("▶")
