"""Vivid dark theme for the dashboard surface.

Scoped to the dashboard widgets (via an object-name'd stylesheet) so the
forensic monitor keeps its native look. Exposes a neon palette, a green→red
heat ramp, and pyqtgraph defaults.
"""

from __future__ import annotations

import pyqtgraph as pg

# --- neon-on-charcoal palette --------------------------------------------
BG = "#0d1117"
PANEL = "#141b26"
GRID = "#223047"
TEXT = "#e6edf3"
MUTED = "#8b97a7"
ACCENT = "#00e5ff"      # cyan
ACCENT_2 = "#ff3fb4"    # magenta
WARN = "#ffb020"        # amber
DANGER = "#ff4d4d"      # red
OK = "#3ddc84"          # green


def heat_color(fraction: float) -> tuple[int, int, int]:
    """Green → amber → red ramp for a 0..1 fraction, as an (r, g, b) tuple."""
    f = 0.0 if fraction < 0.0 else 1.0 if fraction > 1.0 else fraction
    if f < 0.5:  # green → amber
        t = f / 0.5
        r = int(0x3d + (0xff - 0x3d) * t)
        g = int(0xdc + (0xb0 - 0xdc) * t)
        b = int(0x84 + (0x20 - 0x84) * t)
    else:        # amber → red
        t = (f - 0.5) / 0.5
        r = 0xff
        g = int(0xb0 + (0x4d - 0xb0) * t)
        b = int(0x20 + (0x4d - 0x20) * t)
    return r, g, b


def configure_pyqtgraph() -> None:
    pg.setConfigOptions(antialias=True, background=BG, foreground=MUTED)


DASHBOARD_QSS = f"""
QWidget#Dashboard {{
    background: {BG};
    color: {TEXT};
}}
QFrame#Panel {{
    background: {PANEL};
    border: 1px solid {GRID};
    border-radius: 10px;
}}
QLabel#PanelTitle {{
    color: {MUTED};
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 1px;
}}
QLabel#Insight {{
    color: {TEXT};
    font-size: 12px;
}}
QPushButton#Export {{
    background: {ACCENT};
    color: #06222a;
    border: none;
    border-radius: 6px;
    padding: 6px 14px;
    font-weight: 600;
}}
QPushButton#Export:hover {{ background: #55f0ff; }}
"""
