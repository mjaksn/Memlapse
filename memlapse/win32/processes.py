"""Bulk process enumeration via NtQuerySystemInformation.

One ``SystemProcessInformation`` query returns pid, image name, thread count
and memory counters for every process on the system in a single syscall,
without opening a handle to any of them. That makes it far cheaper than
asking each process individually (which costs a handle open or a full
system scan per pid), and because ctypes releases the GIL for the duration
of the call, the GUI thread is not starved while the collector polls.

Assumes a 64-bit host: the structure layout below is the x64 one.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass

SystemProcessInformation = 5
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004

#: Initial query buffer; grown on demand when the process table is larger.
_INITIAL_BUFFER = 512 * 1024
#: Headroom added to the reported size so processes appearing between the
#: sizing call and the real one do not force another round trip.
_SLACK = 64 * 1024
#: How many times to grow the buffer before giving up.
_MAX_ATTEMPTS = 8

_ntdll = ctypes.WinDLL("ntdll", use_last_error=True)


class UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.USHORT),
        ("MaximumLength", wintypes.USHORT),
        ("Buffer", ctypes.c_void_p),
    ]


class SYSTEM_PROCESS_INFORMATION(ctypes.Structure):
    """x64 layout of one entry (thread array omitted; walked by offset)."""

    _fields_ = [
        ("NextEntryOffset", wintypes.ULONG),
        ("NumberOfThreads", wintypes.ULONG),
        ("WorkingSetPrivateSize", ctypes.c_longlong),
        ("HardFaultCount", wintypes.ULONG),
        ("NumberOfThreadsHighWatermark", wintypes.ULONG),
        ("CycleTime", ctypes.c_ulonglong),
        ("CreateTime", ctypes.c_longlong),
        ("UserTime", ctypes.c_longlong),
        ("KernelTime", ctypes.c_longlong),
        ("ImageName", UNICODE_STRING),
        ("BasePriority", ctypes.c_long),
        ("UniqueProcessId", ctypes.c_void_p),
        ("InheritedFromUniqueProcessId", ctypes.c_void_p),
        ("HandleCount", wintypes.ULONG),
        ("SessionId", wintypes.ULONG),
        ("UniqueProcessKey", ctypes.c_size_t),
        ("PeakVirtualSize", ctypes.c_size_t),
        ("VirtualSize", ctypes.c_size_t),
        ("PageFaultCount", wintypes.ULONG),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
        ("PrivatePageCount", ctypes.c_size_t),
        ("ReadOperationCount", ctypes.c_longlong),
        ("WriteOperationCount", ctypes.c_longlong),
        ("OtherOperationCount", ctypes.c_longlong),
        ("ReadTransferCount", ctypes.c_longlong),
        ("WriteTransferCount", ctypes.c_longlong),
        ("OtherTransferCount", ctypes.c_longlong),
    ]


_ntdll.NtQuerySystemInformation.restype = wintypes.ULONG  # NTSTATUS, unsigned
_ntdll.NtQuerySystemInformation.argtypes = [
    wintypes.ULONG, ctypes.c_void_p, wintypes.ULONG, ctypes.POINTER(wintypes.ULONG),
]


@dataclass(frozen=True, slots=True)
class SystemProcess:
    """One row of the system process table."""

    pid: int
    name: str
    num_threads: int
    wset_bytes: int       # WorkingSetSize
    private_bytes: int    # PagefileUsage, the process's commit charge
    create_time: int      # FILETIME ticks; with pid, identifies a process instance
    parent_pid: int       # creator's pid at creation; may be dead or reused since


def _query_buffer() -> ctypes.Array:
    """Return a buffer holding the raw SystemProcessInformation table."""
    size = _INITIAL_BUFFER
    needed = wintypes.ULONG(0)
    for _ in range(_MAX_ATTEMPTS):
        buf = ctypes.create_string_buffer(size)
        status = _ntdll.NtQuerySystemInformation(
            SystemProcessInformation, buf, size, needed
        )
        if status == 0:
            return buf
        if status != STATUS_INFO_LENGTH_MISMATCH:
            raise OSError(f"NtQuerySystemInformation failed (NTSTATUS 0x{status:08x})")
        size = needed.value + _SLACK if needed.value else size * 2
    raise OSError("NtQuerySystemInformation: process table kept growing")


def list_processes() -> list[SystemProcess]:
    """Snapshot every process on the system in one syscall."""
    buf = _query_buffer()
    out: list[SystemProcess] = []
    offset = 0
    while True:
        entry = SYSTEM_PROCESS_INFORMATION.from_buffer(buf, offset)
        pid = entry.UniqueProcessId or 0
        name_len = entry.ImageName.Length // 2
        if entry.ImageName.Buffer and name_len:
            name = ctypes.wstring_at(entry.ImageName.Buffer, name_len)
        else:
            name = "System Idle Process" if pid == 0 else ""
        out.append(SystemProcess(
            pid=pid,
            name=name,
            num_threads=entry.NumberOfThreads,
            wset_bytes=entry.WorkingSetSize,
            private_bytes=entry.PagefileUsage,
            create_time=entry.CreateTime,
            parent_pid=entry.InheritedFromUniqueProcessId or 0,
        ))
        if not entry.NextEntryOffset:
            return out
        offset += entry.NextEntryOffset
