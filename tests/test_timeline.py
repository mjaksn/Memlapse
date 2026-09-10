"""Tests for the timeline scrubber widget."""

import pytest

from memlapse.ui.timeline import TimelineWidget, _fmt_elapsed


def test_fmt_elapsed():
    assert _fmt_elapsed(0) == "00:00.000"
    assert _fmt_elapsed(1_500_000) == "00:01.500"
    assert _fmt_elapsed(65_000_000) == "01:05.000"


@pytest.fixture
def timeline(qtbot):
    w = TimelineWidget()
    qtbot.addWidget(w)
    return w


def test_empty_disables_controls(timeline):
    timeline.set_sample_times([])
    assert not timeline.slider.isEnabled()
    assert not timeline.play_btn.isEnabled()
    assert timeline.time_label.text() == "--:--.---"


def test_set_times_emits_initial_seek(timeline, qtbot):
    times = [1_000, 2_000, 3_000]
    with qtbot.waitSignal(timeline.seek, timeout=500) as sig:
        timeline.set_sample_times(times)
    assert sig.args == [1_000]
    assert timeline.slider.isEnabled()
    assert timeline.slider.maximum() == 2


def test_slider_move_emits_seek(timeline):
    timeline.set_sample_times([1_000, 2_000, 3_000])
    seen = []
    timeline.seek.connect(seen.append)
    timeline.slider.setValue(2)
    assert seen[-1] == 3_000
    assert "[3/3]" in timeline.time_label.text()


def test_play_pause_toggle(timeline):
    timeline.set_sample_times([1_000, 2_000])
    timeline._toggle_play()
    assert timeline._timer.isActive()
    assert timeline.play_btn.text() == "⏸"
    timeline._toggle_play()
    assert not timeline._timer.isActive()
    assert timeline.play_btn.text() == "▶"


def test_advance_steps_and_stops_at_end(timeline):
    timeline.set_sample_times([1_000, 2_000, 3_000])
    timeline._toggle_play()
    timeline._advance()
    assert timeline.slider.value() == 1
    timeline._advance()  # now at last index
    assert timeline.slider.value() == 2
    timeline._advance()  # past end -> stops
    assert not timeline._timer.isActive()


def test_on_slider_with_no_times_is_noop(timeline):
    # Guard path: sliding with an empty timeline must not raise or emit.
    seen = []
    timeline.seek.connect(seen.append)
    timeline._on_slider(0)
    assert seen == []


def test_toggle_play_with_no_times(timeline):
    timeline.set_sample_times([])
    timeline._toggle_play()  # elif self._times is False -> no timer
    assert not timeline._timer.isActive()


def test_play_from_end_restarts(timeline):
    timeline.set_sample_times([1_000, 2_000])
    timeline.slider.setValue(1)  # at end
    timeline._toggle_play()
    assert timeline.slider.value() == 0  # restarted
    assert timeline._timer.isActive()


# --- marks: where the recording says something happened ---------------------
TIMES = [1_000, 2_000, 3_000, 4_000, 5_000]


def _marked_columns(slider):
    """The x of every pixel painted in the mark colour."""
    from PySide6.QtGui import QColor
    from memlapse.ui.timeline import ACCENT_2

    image = slider.grab().toImage()
    want = QColor(ACCENT_2).rgb()
    return {x for x in range(image.width()) for y in range(image.height())
            if image.pixel(x, y) == want}


def test_marks_are_the_sample_times_as_indices(timeline):
    timeline.set_sample_times(TIMES)
    timeline.set_marks([2_000, 5_000])
    assert timeline.slider._marks == [1, 4]


def test_a_time_that_is_not_a_sample_is_dropped(timeline):
    """A tick off a sample would point where the slider cannot stop."""
    timeline.set_sample_times(TIMES)
    timeline.set_marks([2_500, 3_000])
    assert timeline.slider._marks == [2]


def test_new_sample_times_clear_the_old_marks(timeline):
    """Indices into the last recording mean nothing in this one."""
    timeline.set_sample_times(TIMES)
    timeline.set_marks([2_000])
    timeline.set_sample_times([9_000, 9_500])
    assert timeline.slider._marks == []


def test_a_mark_is_painted_where_the_handle_would_sit(timeline):
    """The tick has to land on the sample it means.

    A tick a few pixels off is worse than no tick: the analyst drags to it,
    lands on a neighbouring sample and sees nothing. So the painted column is
    compared with where the style itself puts the handle for that value,
    which is where the slider stops when the tick is followed.
    """
    from PySide6.QtWidgets import QStyle, QStyleOptionSlider

    slider = timeline.slider
    slider.setFixedSize(220, 24)
    timeline.set_sample_times(TIMES)
    timeline.set_marks([3_000])                  # index 2 of 0..4

    columns = _marked_columns(slider)
    assert columns, "no tick was painted"

    slider.setValue(2)
    option = QStyleOptionSlider()
    slider.initStyleOption(option)
    handle = slider.style().subControlRect(
        QStyle.CC_Slider, option, QStyle.SC_SliderHandle, slider)
    painted = sum(columns) / len(columns)
    assert abs(painted - handle.center().x()) <= 2


def test_nothing_is_painted_without_marks(timeline):
    slider = timeline.slider
    slider.setFixedSize(220, 24)
    timeline.set_sample_times(TIMES)
    assert _marked_columns(slider) == set()


def test_the_marks_are_announced_and_not_only_painted(qtbot):
    """Painted pixels tell a screen reader nothing.

    A slider exposes its value and its range, so without this the samples
    worth scrubbing to exist only for someone who can see them.
    """
    from memlapse.ui.timeline import MarkedSlider
    slider = MarkedSlider()
    qtbot.addWidget(slider)
    assert slider.accessibleDescription() == ""

    slider.set_marks([0, 3])
    said = slider.accessibleDescription()
    assert "2 samples marked as rewritten" in said
    assert said.endswith("1, 4")        # counted from one, as the label is

    slider.set_marks([2])
    assert "1 sample marked as rewritten" in slider.accessibleDescription()

    slider.set_marks([])
    assert slider.accessibleDescription() == ""
