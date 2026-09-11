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


def relaunch_as_admin() -> bool:
    """Relaunch this program elevated via UAC. Returns True if a new elevated
    process was started (caller should then exit)."""
    try:
        # The interpreter's own command line, not sys.argv. Started through
        # the memlapse.exe launcher that pip writes, sys.argv[0] has had its
        # ".exe" stripped and names a file that does not exist, while
        # orig_argv still holds the launcher's path, which the interpreter can
        # run again. It also carries `-m memlapse` and any -X options through.
        params = subprocess.list2cmdline(sys.orig_argv[1:])
        # ShellExecuteW returns > 32 on success.
        rc = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, params, None, 1
        )
        return rc > 32
    except Exception:
        return False
