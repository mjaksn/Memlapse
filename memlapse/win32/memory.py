"""ctypes wrappers for reading another process's virtual memory.

``ProcessMemory`` opens a handle once and exposes region enumeration
(VirtualQueryEx) and reads (ReadProcessMemory). It is a context manager so the
handle is always released. Assumes a 64-bit host (the MEMORY_BASIC_INFORMATION
layout below is the x64 one).
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes

from ..model.region import MEM_FREE, Region

# --- access rights ---------------------------------------------------------
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_VM_READ = 0x0010

# Upper bound of user-mode address space on x64 (leave the last page out).
_MAX_ADDRESS = 0x00007FFFFFFEFFFF

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    # x64 layout, including the alignment padding the compiler inserts.
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("__alignment1", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("__alignment2", wintypes.DWORD),
    ]


_kernel32.OpenProcess.restype = wintypes.HANDLE
_kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]

_kernel32.CloseHandle.restype = wintypes.BOOL
_kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

_kernel32.VirtualQueryEx.restype = ctypes.c_size_t
_kernel32.VirtualQueryEx.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p,
    ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t,
]

_kernel32.ReadProcessMemory.restype = wintypes.BOOL
_kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
    ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
]


class ProcessAccessError(OSError):
    """Raised when a process cannot be opened (usually needs elevation)."""


class ProcessMemory:
    """Handle to another process's address space. Use as a context manager."""

    def __init__(self, pid: int, *, want_read: bool = True) -> None:
        self.pid = pid
        self.can_read = want_read
        access = PROCESS_QUERY_INFORMATION | (PROCESS_VM_READ if want_read else 0)
        handle = _kernel32.OpenProcess(access, False, pid)
        if not handle and want_read:
            # Retry without VM_READ: we can still map regions, just not read them.
            handle = _kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            self.can_read = False
        if not handle:
            err = ctypes.get_last_error()
            raise ProcessAccessError(
                f"OpenProcess({pid}) failed (WinError {err}); try running elevated"
            )
        self._handle = handle

    # --- lifecycle ---------------------------------------------------------
    def close(self) -> None:
        if self._handle:
            _kernel32.CloseHandle(self._handle)
            self._handle = None

    def __enter__(self) -> "ProcessMemory":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # --- operations --------------------------------------------------------
    def regions(self, *, include_free: bool = False) -> list[Region]:
        """Walk the whole address space via VirtualQueryEx."""
        out: list[Region] = []
        mbi = MEMORY_BASIC_INFORMATION()
        size = ctypes.sizeof(mbi)
        address = 0
        while address < _MAX_ADDRESS:
            written = _kernel32.VirtualQueryEx(self._handle, address, ctypes.byref(mbi), size)
            if not written:
                break
            region_size = mbi.RegionSize
            if region_size == 0:  # pragma: no cover - defensive; VQE never returns 0-size
                break
            if include_free or mbi.State != MEM_FREE:
                out.append(Region(
                    base_addr=mbi.BaseAddress or address,
                    size=region_size,
                    state=mbi.State,
                    protect=mbi.Protect,
                    type=mbi.Type,
                ))
            address = (mbi.BaseAddress or address) + region_size
        return out

    def read(self, address: int, size: int) -> bytes:
        """Best-effort read; returns however many bytes were actually read."""
        if not self.can_read:
            return b""
        buf = ctypes.create_string_buffer(size)
        read = ctypes.c_size_t(0)
        ok = _kernel32.ReadProcessMemory(
            self._handle, address, buf, size, ctypes.byref(read)
        )
        if not ok and read.value == 0:
            return b""
        return buf.raw[: read.value]


def enumerate_regions(pid: int, *, include_free: bool = False) -> list[Region]:
    """Convenience one-shot region map for a pid."""
    with ProcessMemory(pid, want_read=False) as pm:
        return pm.regions(include_free=include_free)
