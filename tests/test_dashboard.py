"""Tests for the near-live dashboard view."""

import json

import pytest

import memlapse.ui.dashboard as dash_mod
from memlapse.ui.dashboard import DashboardView, ProcessBar, _fmt_bytes, _panel
from memlapse.model.system import SystemSample


def _sys(ts, used, total=16 * 1024**3, percent=None, swap_used=0,
         swap_total=4 * 1024**3, swap_percent=0.0, available=None):
    if percent is None:
        percent = 100.0 * used / total
    if available is None:
        available = total - used
    return SystemSample(ts_us=ts, total=total, available=available, used=used,
                        percent=percent, swap_total=swap_total,
                        swap_used=swap_used, swap_percent=swap_percent)


# --- helpers ---------------------------------------------------------------
def test_fmt_bytes_scales_to_pb():
    assert _fmt_bytes(0) == "0 B"
    assert _fmt_bytes(1536) == "1.5 KB"
    assert _fmt_bytes(3 * 1024**5) == "3.0 PB"


def test_panel_with_and_without_title(qapp):
    frame, lay = _panel("Title")
    assert lay.count() == 1  # title label added
    frame2, lay2 = _panel("")
    assert lay2.count() == 0  # no title -> no label


# --- ProcessBar ------------------------------------------------------------
@pytest.fixture
def bar(qtbot):
    b = ProcessBar()
    qtbot.addWidget(b)
    b.resize(200, 24)
    return b


def test_process_bar_click_emits(bar):
    seen = []
    bar.clicked.connect(lambda pid, name: seen.append((pid, name)))
    bar.set_value(42, "p.exe", 0.5, 0.5, "50 MB")
    bar.mousePressEvent(None)
    assert seen == [(42, "p.exe")]


def test_process_bar_click_ignored_when_unset(bar):
    seen = []
    bar.clicked.connect(lambda pid, name: seen.append(pid))
    bar.mousePressEvent(None)  # pid still -1 -> no emit
    assert seen == []


def test_process_bar_paints_filled_and_empty(bar):
    bar.set_value(1, "p", 0.7, 0.7, "x")
    assert not bar.grab().isNull()      # width_frac > 0 branch
    bar.set_value(2, "q", 0.0, 0.0, "y")
    assert not bar.grab().isNull()      # width_frac == 0 branch


# --- DashboardView ---------------------------------------------------------
@pytest.fixture
def dash(qtbot):
    d = DashboardView()
    qtbot.addWidget(d)
    d._render.stop()  # stop the ~30fps timer for deterministic tests
    return d


def test_update_system_updates_gauges_and_readout(dash):
    dash.update_system(_sys(1_000_000, 8 * 1024**3))
    assert dash.ram_gauge._target == pytest.approx(50.0)
    assert "/" in dash.readout.text()
    assert len(dash._percent) == 1


def test_update_processes_populates_and_hides_bars(dash, make_process):
    rows = [make_process(pid=i, name=f"p{i}", wset_bytes=(i + 1) * 1000)
            for i in range(3)]
    dash.update_system(_sys(1_000_000, 8 * 1024**3))
    dash.update_processes(rows)
    visible = [b for b in dash._bars if b.isVisibleTo(dash)]
    assert len(visible) == 3  # only 3 of TOP_N bars shown


def test_top_mover_arrows(dash, make_process):
    dash.update_processes([make_process(pid=1, name="a", wset_bytes=100)])
    # Growth -> up arrow.
    dash.update_processes([make_process(pid=1, name="a", wset_bytes=1_000_000)])
    assert "▲" in dash._mover_text
    # Shrink -> down arrow.
    dash.update_processes([make_process(pid=1, name="a", wset_bytes=100)])
    assert "▼" in dash._mover_text
    # No change -> mover text cleared.
    dash.update_processes([make_process(pid=1, name="a", wset_bytes=100)])
    assert dash._mover_text == ""


def test_refresh_chart_empty_is_noop(dash):
    dash._refresh_chart()  # no samples yet -> early return, must not raise


def test_insight_climbing(dash):
    for i in range(60):
        dash._used.append(i * 1_000_000, float(i * 1024 * 1024))  # +1MB/s
        dash._percent.append(i * 1_000_000, 50.0)
    dash._refresh_insight()
    assert "climbing" in dash.insight.text()


def test_insight_falling(dash):
    for i in range(60):
        dash._used.append(i * 1_000_000, float((60 - i) * 1024 * 1024))
        dash._percent.append(i * 1_000_000, 50.0)
    dash._refresh_insight()
    assert "falling" in dash.insight.text()


def test_insight_anomaly_and_mover(dash):
    for i in range(30):
        dash._used.append(i * 1_000_000, 1000.0)
        dash._percent.append(i * 1_000_000, 50.0)
    dash._percent.append(30_000_000, 95.0)   # spike -> high z-score
    dash._used.append(30_000_000, 1000.0)
    dash._mover_text = "▲ x 1.0 MB"
    dash._refresh_insight()
    text = dash.insight.text()
    assert "anomaly" in text and "mover:" in text


def test_insight_steady(dash):
    for i in range(60):
        dash._used.append(i * 1_000_000, 1000.0)
        dash._percent.append(i * 1_000_000, 50.0)
    dash._refresh_insight()
    assert "steady" in dash.insight.text()


def test_on_render_steps_gauges(dash):
    dash.ram_gauge.set_target(100.0)
    dash._on_render()
    assert dash.ram_gauge._value > 0.0


# --- export ----------------------------------------------------------------
def _seed_export(dash):
    for i in range(3):
        dash._percent.append(i, float(i * 10))
        dash._used.append(i, float(i * 1000))


def test_export_csv(dash, tmp_path, monkeypatch):
    out = tmp_path / "w.csv"
    monkeypatch.setattr(dash_mod.QFileDialog, "getSaveFileName",
                        lambda *a, **k: (str(out), "CSV (*.csv)"))
    _seed_export(dash)
    dash._export()
    assert out.exists()
    assert "ts_us,percent,used_bytes" in out.read_text()


def test_export_json(dash, tmp_path, monkeypatch):
    out = tmp_path / "w.json"
    monkeypatch.setattr(dash_mod.QFileDialog, "getSaveFileName",
                        lambda *a, **k: (str(out), "JSON (*.json)"))
    _seed_export(dash)
    dash._export()
    data = json.loads(out.read_text())
    assert len(data) == 3 and "used_bytes" in data[0]


def test_export_cancelled(dash, tmp_path, monkeypatch):
    monkeypatch.setattr(dash_mod.QFileDialog, "getSaveFileName",
                        lambda *a, **k: ("", ""))
    _seed_export(dash)
    dash._export()  # cancelled -> no file written, no raise


# --- time-window selection -------------------------------------------------
def _seed_window(dash):
    base = 100_000_000
    for k, pc in [(0, 50.0), (30, 60.0), (60, 70.0)]:  # seconds -> µs
        dash._percent.append(base + k * 1_000_000, pc)
        dash._used.append(base + k * 1_000_000, pc * 1000)


def test_select_toggle_reports_stats(dash):
    dash.select_btn.setChecked(True)  # -> _toggle_select(True)
    assert dash.region.isVisible()
    assert "no samples" in dash.selection_label.text()  # nothing buffered yet

    _seed_window(dash)
    dash.region.setRegion((-60.0, 0.0))
    dash._on_region()
    text = dash.selection_label.text()
    assert "avg 60.0%" in text and "peak 70.0%" in text

    dash.select_btn.setChecked(False)  # -> _toggle_select(False)
    assert not dash.region.isVisible()
    assert dash.selection_label.text() == ""


def test_on_region_ignored_when_hidden(dash):
    dash._on_region()  # region hidden -> early return
    assert dash.selection_label.text() == ""


def test_selected_points_empty_without_samples(dash):
    dash.region.show()
    assert dash._selected_points() == []


def test_export_rows_filters_to_selection(dash):
    _seed_window(dash)
    assert len(dash._export_rows()) == 3  # no selection -> everything
    dash.region.show()
    dash.region.setRegion((-5.0, 0.0))  # only the newest (0s ago) sample
    rows = dash._export_rows()
    assert len(rows) == 1 and rows[0]["percent"] == 70.0


# --- the interpret strip refuses to report from too little data ------------
def test_insight_waits_for_a_baseline(dash):
    from memlapse.ui.dashboard import MIN_INSIGHT_SAMPLES
    for i in range(5):
        dash._used.append(i * 1_000_000, float(i * 1024 * 1024))
        dash._percent.append(i * 1_000_000, 50.0)
    dash._refresh_insight()
    text = dash.insight.text()
    assert "collecting baseline" in text
    assert f"5 of {MIN_INSIGHT_SAMPLES}" in text
    assert "climbing" not in text  # a slope through five points is not a finding
    assert dash.ram_gauge._alert is False


def test_insight_reports_once_the_baseline_is_full(dash):
    from memlapse.ui.dashboard import MIN_INSIGHT_SAMPLES
    for i in range(MIN_INSIGHT_SAMPLES):
        dash._used.append(i * 1_000_000, 1000.0)
        dash._percent.append(i * 1_000_000, 50.0)
    dash._refresh_insight()
    assert "collecting baseline" not in dash.insight.text()
    assert "steady" in dash.insight.text()
