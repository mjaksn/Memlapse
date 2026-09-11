"""Tests for elevation / privilege helpers.

The Win32 calls are exercised through fake shell32, advapi32 and kernel32
shims so every branch is reachable without actually being elevated.
"""

import ctypes

import memlapse.win32.privileges as privileges
from memlapse.win32.privileges import (
    enable_se_debug_privilege, is_elevated, relaunch_as_admin,
)


class FakeShell:
    def __init__(self, admin=1, exec_rc=42, raise_on=None):
        self._admin = admin
        self._exec_rc = exec_rc
        self._raise_on = raise_on

    def IsUserAnAdmin(self):
        if self._raise_on == "admin":
            raise OSError("boom")
        return self._admin

    def ShellExecuteW(self, hwnd, verb, exe, params, cwd, show):
        if self._raise_on == "exec":
            raise OSError("boom")
        self.executed = (verb, exe, params)
        return self._exec_rc


class FakeAdvapi:
    def __init__(self, opentoken=1, lookup=1, adjust=1):
        self._opentoken = opentoken
        self._lookup = lookup
        self._adjust = adjust

    def OpenProcessToken(self, proc, access, token_ptr):
        return self._opentoken

    def LookupPrivilegeValueW(self, system, name, luid_ptr):
        return self._lookup

    def AdjustTokenPrivileges(self, *args):
        return self._adjust


class FakeKernel:
    def GetCurrentProcess(self):
        return -1  # the pseudo-handle the real call returns

    def CloseHandle(self, handle):
        return 1


def _set_shell(monkeypatch, shell):
    monkeypatch.setattr(privileges.ctypes.windll, "shell32", shell, raising=False)


def _set_advapi(monkeypatch, advapi):
    monkeypatch.setattr(privileges, "_advapi32", advapi)
    monkeypatch.setattr(privileges, "_kernel32", FakeKernel())


# --- is_elevated -----------------------------------------------------------
def test_is_elevated_true(monkeypatch):
    _set_shell(monkeypatch, FakeShell(admin=1))
    assert is_elevated() is True


def test_is_elevated_false(monkeypatch):
    _set_shell(monkeypatch, FakeShell(admin=0))
    assert is_elevated() is False


def test_is_elevated_swallows_errors(monkeypatch):
    _set_shell(monkeypatch, FakeShell(raise_on="admin"))
    assert is_elevated() is False


# --- enable_se_debug_privilege --------------------------------------------
def test_enable_open_token_fails(monkeypatch):
    _set_advapi(monkeypatch, FakeAdvapi(opentoken=0))
    assert enable_se_debug_privilege() is False


def test_enable_lookup_fails(monkeypatch):
    _set_advapi(monkeypatch, FakeAdvapi(lookup=0))
    assert enable_se_debug_privilege() is False


def test_enable_adjust_fails(monkeypatch):
    _set_advapi(monkeypatch, FakeAdvapi(adjust=0))
    assert enable_se_debug_privilege() is False


def test_enable_success(monkeypatch):
    _set_advapi(monkeypatch, FakeAdvapi())
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 0)
    assert enable_se_debug_privilege() is True


def test_enable_not_all_assigned(monkeypatch):
    _set_advapi(monkeypatch, FakeAdvapi())
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 1300)  # ERROR_NOT_ALL_ASSIGNED
    assert enable_se_debug_privilege() is False


# --- relaunch_as_admin -----------------------------------------------------
def test_relaunch_success(monkeypatch):
    _set_shell(monkeypatch, FakeShell(exec_rc=42))
    assert relaunch_as_admin() is True


def test_relaunch_reruns_the_interpreter_command_line(monkeypatch):
    # What the pip launcher leaves behind: orig_argv names memlapse.exe, which
    # the interpreter can run, while sys.argv[0] has lost its extension.
    shell = FakeShell(exec_rc=42)
    _set_shell(monkeypatch, shell)
    scripts = "C:\\my venv\\Scripts\\"
    monkeypatch.setattr(privileges.sys, "executable", scripts + "pythonw.exe")
    monkeypatch.setattr(privileges.sys, "argv", [scripts + "memlapse", "--elevate"])
    monkeypatch.setattr(privileges.sys, "orig_argv", [
        scripts + "pythonw.exe", scripts + "memlapse.exe", "--elevate",
    ])
    assert relaunch_as_admin() is True
    assert shell.executed == (
        "runas", scripts + "pythonw.exe", f'"{scripts}memlapse.exe" --elevate',
    )


def test_relaunch_failure_low_rc(monkeypatch):
    _set_shell(monkeypatch, FakeShell(exec_rc=5))  # <= 32 means failure
    assert relaunch_as_admin() is False


def test_relaunch_swallows_errors(monkeypatch):
    _set_shell(monkeypatch, FakeShell(raise_on="exec"))
    assert relaunch_as_admin() is False
