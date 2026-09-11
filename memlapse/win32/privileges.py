"""Elevation and privilege management.

Most useful forensic targets (services, other users' processes) can only be
opened when the current process holds SeDebugPrivilege, which in turn requires
running as administrator. This module reports the current state and, on
request, can relaunch the app elevated via UAC.
"""

from __future__ import annotations

import ctypes
import subprocess
import sys
from ctypes import wintypes
from pathlib import Path

# --- constants -------------------------------------------------------------
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY = 0x0008
SE_PRIVILEGE_ENABLED = 0x00000002
SE_DEBUG_NAME = "SeDebugPrivilege"
ERROR_NOT_ALL_ASSIGNED = 1300


class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", wintypes.DWORD),
                ("Privileges", LUID_AND_ATTRIBUTES * 1)]


# Loaded with use_last_error=True so ctypes.get_last_error() reflects these
# calls; the shared ctypes.windll handles do not capture GetLastError.
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

# GetCurrentProcess returns the pseudo-handle -1. Without a HANDLE restype it
# comes back as a 32-bit int, which OpenProcessToken rejects on 64-bit Windows.
_kernel32.GetCurrentProcess.restype = wintypes.HANDLE
_kernel32.GetCurrentProcess.argtypes = []
_kernel32.CloseHandle.restype = wintypes.BOOL
_kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
_advapi32.OpenProcessToken.restype = wintypes.BOOL
_advapi32.OpenProcessToken.argtypes = [
    wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE),
]
_advapi32.LookupPrivilegeValueW.restype = wintypes.BOOL
_advapi32.LookupPrivilegeValueW.argtypes = [
    wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(LUID),
]
_advapi32.AdjustTokenPrivileges.restype = wintypes.BOOL
_advapi32.AdjustTokenPrivileges.argtypes = [
    wintypes.HANDLE, wintypes.BOOL, ctypes.c_void_p, wintypes.DWORD,
    ctypes.c_void_p, ctypes.c_void_p,
]


def is_elevated() -> bool:
    """True if the current process is running with administrator rights."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def enable_se_debug_privilege() -> bool:
    """Enable SeDebugPrivilege on the current process token.

    Returns True on success. Fails (returns False) when not elevated.
    """
    h_token = wintypes.HANDLE()
    if not _advapi32.OpenProcessToken(
        _kernel32.GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        ctypes.byref(h_token),
    ):
        return False

    try:
        luid = LUID()
        if not _advapi32.LookupPrivilegeValueW(None, SE_DEBUG_NAME, ctypes.byref(luid)):
            return False

        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

        if not _advapi32.AdjustTokenPrivileges(
            h_token, False, ctypes.byref(tp), 0, None, None
        ):
            return False

        # AdjustTokenPrivileges can "succeed" but not apply all privileges;
        # GetLastError() == ERROR_NOT_ALL_ASSIGNED (1300) means it didn't stick.
        return ctypes.get_last_error() != ERROR_NOT_ALL_ASSIGNED
    finally:
        _kernel32.CloseHandle(h_token)


def _relaunch_params() -> str:
    """The command line to hand the interpreter for an elevated copy of this run."""
    script = Path(sys.argv[0])
    if script.suffix.lower() == ".py" and script.name != "__main__.py":
        # Started as a script, `python main.py` in a checkout, and sys.argv is
        # what to repeat. It has to be: under a debugger the interpreter was
        # started on the debugger's own bootstrap, which sys.argv leaves out
        # and the elevated copy has no business running.
        return subprocess.list2cmdline(sys.argv)
    # Started any other way, sys.argv cannot be run again. Through the
    # memlapse.exe launcher that pip writes, sys.argv[0] has had its ".exe"
    # stripped and names a file that does not exist; under `python -m
    # memlapse` it is the package's __main__.py, which cannot run outside the
    # package. The interpreter's own command line still holds what it was
    # given, the launcher's path or `-m memlapse`, and can be repeated.
    return subprocess.list2cmdline(sys.orig_argv[1:])


def relaunch_as_admin() -> bool:
    """Relaunch this program elevated via UAC. Returns True if a new elevated
    process was started (caller should then exit)."""
    try:
        params = _relaunch_params()
        # ShellExecuteW returns > 32 on success.
        rc = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, params, None, 1
        )
        return rc > 32
    except Exception:
        return False
