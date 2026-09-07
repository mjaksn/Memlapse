"""Dark theme.

``DASHBOARD_QSS`` is scoped to the dashboard widgets through object names;
``APP_QSS`` is applied to the whole application in app.py, so the forensic
monitor is styled too. Exposes the neon palette, a green to red heat ramp,
both stylesheets and pyqtgraph defaults.
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
QPushButton#Select {{
    background: transparent;
    color: {ACCENT_2};
    border: 1px solid {ACCENT_2};
    border-radius: 6px;
    padding: 6px 14px;
    font-weight: 600;
}}
QPushButton#Select:checked {{ background: {ACCENT_2}; color: #2a0a1e; }}
QLabel#Selection {{ color: {ACCENT_2}; font-size: 11px; }}
"""


# Applied app-wide so the whole shell (tabs, toolbar, tables, status bar)
# reads as one vivid surface, not just the dashboard tab.
APP_QSS = f"""
QMainWindow, QDialog {{ background: {BG}; }}
QLabel {{ color: {TEXT}; }}
QStatusBar {{ background: {PANEL}; color: {MUTED}; }}
QStatusBar QLabel {{ color: {MUTED}; }}
QToolBar {{ background: {PANEL}; border: none; spacing: 6px; padding: 4px; }}
QToolButton {{
    background: {GRID}; color: {TEXT};
    border: 1px solid {GRID}; border-radius: 6px; padding: 5px 12px;
}}
QToolButton:hover {{ border: 1px solid {ACCENT}; color: {ACCENT}; }}
QToolButton:disabled {{ color: {MUTED}; }}
QTabWidget::pane {{ border: 1px solid {GRID}; background: {BG}; }}
QTabBar::tab {{
    background: {PANEL}; color: {MUTED};
    padding: 8px 18px; margin-right: 2px;
    border-top-left-radius: 8px; border-top-right-radius: 8px;
}}
QTabBar::tab:selected {{
    background: {BG}; color: {ACCENT}; border-bottom: 2px solid {ACCENT};
}}
QTableView {{
    background: {PANEL}; alternate-background-color: #101722;
    color: {TEXT}; gridline-color: {GRID};
    selection-background-color: {ACCENT}; selection-color: #06222a;
    border: 1px solid {GRID};
}}
QHeaderView::section {{
    background: {GRID}; color: {TEXT}; border: none; padding: 5px;
}}
QLineEdit {{
    background: {PANEL}; color: {TEXT};
    border: 1px solid {GRID}; border-radius: 6px; padding: 5px 8px;
    selection-background-color: {ACCENT}; selection-color: #06222a;
}}
QMenu {{ background: {PANEL}; color: {TEXT}; border: 1px solid {GRID}; }}
QMenu::item:selected {{ background: {ACCENT}; color: #06222a; }}
QScrollBar:vertical {{ background: {BG}; width: 12px; margin: 0; }}
QScrollBar::handle:vertical {{
    background: {GRID}; border-radius: 6px; min-height: 24px;
}}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; }}
"""
