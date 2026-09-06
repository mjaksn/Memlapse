"""Animated circular gauge widget.

A 270° arc (opening at the bottom) that eases toward its target each render
tick, with a value-driven colour (green→amber→red) and a big centre readout.
Drive :meth:`animate_step` from a render timer for smooth motion decoupled
from the ~1 Hz data cadence.
"""

from __future__ import annotations

import math

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import QWidget

from .theme import DANGER, GRID, MUTED, TEXT, heat_color

_START_ANGLE = 225   # degrees (lower-left); Qt angles are CCW from 3 o'clock
_SPAN = -270         # clockwise sweep, leaving a gap at the bottom


class AnimatedGauge(QWidget):
    def __init__(self, title: str = "", parent=None) -> None:
        super().__init__(parent)
        self._title = title
        self._target = 0.0
        self._value = 0.0
        self._subtitle = ""
        self._alert = False
        self._pulse = 0.0
        self.setMinimumSize(130, 130)

    def set_target(self, percent: float, subtitle: str = "") -> None:
        self._target = max(0.0, min(100.0, float(percent)))
        self._subtitle = subtitle

    def set_alert(self, on: bool) -> None:
        """Toggle the pulsing danger glow (high pressure / anomaly)."""
        self._alert = bool(on)

    def animate_step(self) -> None:
        """Ease the displayed value toward the target; call from a timer."""
        changed = False
        diff = self._target - self._value
        if abs(diff) < 0.1:
            if self._value != self._target:
                self._value = self._target
                changed = True
        else:
            self._value += diff * 0.25
            changed = True
        if self._alert:  # keep repainting so the glow breathes
            self._pulse = (self._pulse + 0.18) % (2 * math.pi)
            changed = True
        if changed:
            self.update()

    def paintEvent(self, _event) -> None:
        side = min(self.width(), self.height())
        margin = 14
        rect = QRectF(
            (self.width() - side) / 2 + margin,
            (self.height() - side) / 2 + margin,
            side - 2 * margin,
            side - 2 * margin,
        )
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)

        pen = QPen(QColor(GRID))
        pen.setWidth(12)
        pen.setCapStyle(Qt.RoundCap)
        p.setPen(pen)
        p.drawArc(rect, _START_ANGLE * 16, _SPAN * 16)

        frac = self._value / 100.0

        # pulsing danger glow behind the value arc when in alert
        if self._alert:
            glow = QColor(DANGER)
            glow.setAlpha(int(55 + 70 * (0.5 + 0.5 * math.sin(self._pulse))))
            gpen = QPen(glow)
            gpen.setWidth(22)
            gpen.setCapStyle(Qt.RoundCap)
            p.setPen(gpen)
            p.drawArc(rect, _START_ANGLE * 16, int(_SPAN * frac) * 16)

        r, g, b = heat_color(frac)
        pen.setColor(QColor(r, g, b))
        p.setPen(pen)
        p.drawArc(rect, _START_ANGLE * 16, int(_SPAN * frac) * 16)

        # centre readout
        p.setPen(QColor(TEXT))
        big = QFont()
        big.setPointSize(max(13, int(side * 0.15)))
        big.setBold(True)
        p.setFont(big)
        p.drawText(rect, Qt.AlignCenter, f"{self._value:.0f}%")

        # title + subtitle in the bottom gap
        small = QFont()
        small.setPointSize(9)
        p.setFont(small)
        p.setPen(QColor(MUTED))
        label = self._title if not self._subtitle else f"{self._title} · {self._subtitle}"
        p.drawText(
            QRectF(rect.left(), rect.bottom() - 6, rect.width(), 22),
            Qt.AlignHCenter | Qt.AlignTop,
            label,
        )
        p.end()
