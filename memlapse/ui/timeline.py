"""Timeline scrubber for playback.

A slider indexed over a recording's discrete sample timestamps, plus a
play/pause button that steps through them on a timer. Emits ``seek(ts_us)``
whenever the position changes so the main window can rebuild state at that
time.

The slider also carries marks: the samples where something the analyst would
want to see happened, which today is where a region was rewritten. Without
them a recording is a bar with no landmarks and finding the interesting minute
means dragging across the whole of it.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import (
    QHBoxLayout, QLabel, QPushButton, QSlider, QStyle, QStyleOptionSlider,
    QWidget,
)

from .theme import ACCENT_2

#: Playback step interval in ms (advance one sample per tick).
PLAY_STEP_MS = 250

#: A mark's tick: height in pixels and how wide the stroke is. Two pixels
#: wide because one disappears against the groove on a high DPI screen.
MARK_HEIGHT = 10
MARK_WIDTH = 2


def _fmt_elapsed(us: int) -> str:
    seconds = us / 1_000_000
    minutes, secs = divmod(seconds, 60)
    return f"{int(minutes):02d}:{secs:06.3f}"


class MarkedSlider(QSlider):
    """A horizontal slider that draws a tick at each marked position.

    The marks are slider values, which is to say sample indices, so a tick
    lands exactly where the handle lands when it is on that sample. Working
    that out means asking the style where the groove and the handle are:
    the travel a value maps onto is the groove less one handle's width,
    because the handle's own width is the part of the groove it cannot reach
    with its centre.
    """

    def __init__(self, parent=None) -> None:
        super().__init__(Qt.Horizontal, parent)
        self._marks: list[int] = []

    def set_marks(self, values) -> None:
        self._marks = sorted(set(values))
        self.update()

    def paintEvent(self, event) -> None:
        super().paintEvent(event)
        if not self._marks:
            return
        option = QStyleOptionSlider()
        self.initStyleOption(option)
        style = self.style()
        groove = style.subControlRect(
            QStyle.CC_Slider, option, QStyle.SC_SliderGroove, self)
        handle = style.subControlRect(
            QStyle.CC_Slider, option, QStyle.SC_SliderHandle, self)
        span = groove.width() - handle.width()
        middle = groove.center().y()
        painter = QPainter(self)
        painter.setPen(QPen(QColor(ACCENT_2), MARK_WIDTH))
        for value in self._marks:
            offset = style.sliderPositionFromValue(
                self.minimum(), self.maximum(), value, span,
                option.upsideDown)
            x = groove.x() + offset + handle.width() // 2
            painter.drawLine(x, middle - MARK_HEIGHT // 2,
                             x, middle + MARK_HEIGHT // 2)
        painter.end()


class TimelineWidget(QWidget):
    seek = Signal("qlonglong")  # ts_us (64-bit epoch microseconds)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._times: list[int] = []

        self.play_btn = QPushButton("▶", self)
        self.play_btn.setFixedWidth(36)
        self.play_btn.setEnabled(False)
        self.play_btn.clicked.connect(self._toggle_play)

        self.slider = MarkedSlider(self)
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
        # A mark is an index into these, so the last recording's are now
        # nonsense. Cleared here rather than left for the caller, because a
        # recording with nothing to mark would otherwise inherit the marks of
        # the one before it.
        self.slider.set_marks([])
        has = len(times) > 0
        self.slider.setEnabled(has)
        self.play_btn.setEnabled(has)
        if has:
            self.slider.setRange(0, len(times) - 1)
            self.slider.setValue(0)
            self._on_slider(0)  # emit initial state
        else:
            self.time_label.setText("--:--.---")

    def set_marks(self, times: list[int]) -> None:
        """Mark the samples at these times, in ts_us as everything else is.

        Call after :meth:`set_sample_times`, which clears the marks along with
        the times they index. A time that is not a sample of this recording is
        dropped rather than rounded to a neighbour: a tick that does not sit
        on a sample points at a place the slider cannot stop.
        """
        index_of = {ts: i for i, ts in enumerate(self._times)}
        self.slider.set_marks([index_of[ts] for ts in times if ts in index_of])

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
