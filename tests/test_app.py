"""Tests for the application entry point."""

import runpy

import pytest

import memlapse.app as app_mod
from memlapse.app import main, should_relaunch_elevated


def test_should_relaunch_when_flagged_and_not_elevated(monkeypatch):
    monkeypatch.setattr(app_mod.privileges, "is_elevated", lambda: False)
    assert should_relaunch_elevated(["memlapse", "--elevate"]) is True


def test_no_relaunch_without_flag(monkeypatch):
    monkeypatch.setattr(app_mod.privileges, "is_elevated", lambda: False)
    assert should_relaunch_elevated(["memlapse"]) is False


def test_no_relaunch_when_already_elevated(monkeypatch):
    monkeypatch.setattr(app_mod.privileges, "is_elevated", lambda: True)
    assert should_relaunch_elevated(["memlapse", "--elevate"]) is False


class FakeApp:
    last = None

    def __init__(self, argv):
        self.argv = argv
        FakeApp.last = self

    def setApplicationName(self, name):
        self.name = name

    def setStyleSheet(self, qss):
        self.qss = qss

    def exec(self):
        return 0


class FakeWindow:
    def __init__(self):
        self.shown = False

    def show(self):
        self.shown = True


def _patch_gui(monkeypatch):
    monkeypatch.setattr(app_mod.privileges, "enable_se_debug_privilege", lambda: True)
    monkeypatch.setattr(app_mod, "QApplication", FakeApp)
    monkeypatch.setattr(app_mod, "MainWindow", FakeWindow)


def test_main_relaunches_and_exits(monkeypatch):
    _patch_gui(monkeypatch)
    monkeypatch.setattr(app_mod, "should_relaunch_elevated", lambda argv: True)
    monkeypatch.setattr(app_mod.privileges, "relaunch_as_admin", lambda: True)
    assert main(["memlapse", "--elevate"]) == 0
    assert FakeApp.last is None  # never constructed the GUI


def test_main_runs_gui(monkeypatch):
    _patch_gui(monkeypatch)
    FakeApp.last = None
    monkeypatch.setattr(app_mod, "should_relaunch_elevated", lambda argv: False)
    assert main(["memlapse"]) == 0
    assert FakeApp.last is not None
    assert FakeApp.last.name == "memlapse"


def test_main_runs_gui_when_relaunch_fails(monkeypatch):
    _patch_gui(monkeypatch)
    FakeApp.last = None
    monkeypatch.setattr(app_mod, "should_relaunch_elevated", lambda argv: True)
    monkeypatch.setattr(app_mod.privileges, "relaunch_as_admin", lambda: False)
    assert main(["memlapse", "--elevate"]) == 0
    assert FakeApp.last is not None  # fell through to launching the GUI


def test_python_dash_m_runs_main_and_exits_with_its_code(monkeypatch):
    monkeypatch.setattr(app_mod, "main", lambda: 7)
    with pytest.raises(SystemExit) as exited:
        runpy.run_module("memlapse", run_name="__main__")
    assert exited.value.code == 7
