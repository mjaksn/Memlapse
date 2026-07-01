"""Elevation and privilege management.

Most useful forensic targets (services, other users' processes) can only be
opened when the current process holds SeDebugPrivilege, which in turn requires
running as administrator. This module reports the current state and, on
request, can relaunch the app elevated via UAC.
"""

from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes

# --- constants -------------------------------------------------------------
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY = 0x0008
SE_PRIVILEGE_ENABLED = 0x00000002
SE_DEBUG_NAME = "SeDebugPrivilege"


class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", wintypes.DWORD),
                ("Privileges", LUID_AND_ATTRIBUTES * 1)]


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
    advapi32 = ctypes.windll.advapi32
    kernel32 = ctypes.windll.kernel32

    h_token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        ctypes.byref(h_token),
    ):
        return False

    try:
        luid = LUID()
        if not advapi32.LookupPrivilegeValueW(None, SE_DEBUG_NAME, ctypes.byref(luid)):
            return False

        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

        if not advapi32.AdjustTokenPrivileges(
            h_token, False, ctypes.byref(tp), 0, None, None
        ):
            return False

        # AdjustTokenPrivileges can "succeed" but not apply all privileges;
        # GetLastError() == ERROR_NOT_ALL_ASSIGNED (1300) means it didn't stick.
        return ctypes.get_last_error() == 0
    finally:
        kernel32.CloseHandle(h_token)


def relaunch_as_admin() -> bool:
    """Relaunch this program elevated via UAC. Returns True if a new elevated
    process was started (caller should then exit)."""
    try:
        params = " ".join(f'"{a}"' for a in sys.argv)
        # ShellExecuteW returns > 32 on success.
        rc = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, params, None, 1
        )
        return rc > 32
    except Exception:
        return False
