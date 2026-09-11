"""Win32 start address of each thread in a process.

The bulk process table (:mod:`memlapse.win32.processes`) carries a thread array
after every process entry, but its ``StartAddress`` is the kernel start routine
rather than the thread's own code, and Windows zeroes the field entirely for an
unelevated caller. Neither form answers "where does this thread's code begin?",
so the address has to be asked for per thread, with
``NtQueryInformationThread`` and the ``ThreadQuerySetWin32StartAddress`` class.

That class is refused with ``THREAD_QUERY_LIMITED_INFORMATION``, so the handle
is opened with ``THREAD_QUERY_INFORMATION``. This is the second kind of handle
memlapse opens, after the process handle in :mod:`memlapse.win32.memory`, and
it stays on the same side of the read-only boundary: query access only, never
``THREAD_SET_*``, never suspend or resume. A thread whose handle will not open,
or whose address the kernel refuses, is left out of the result rather than
recorded as zero. Unelevated, that is every thread of another user's process.

Assumes a 64-bit host, like the rest of ``win32``.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes

# Both modules read the same system table, so the buffer helper is shared.
from .processes import SYSTEM_PROCESS_INFORMATION, _query_buffer

#: Access right the start-address query needs.
THREAD_QUERY_INFORMATION = 0x0040
#: THREADINFOCLASS value for the Win32 start address; not in the public headers.
ThreadQuerySetWin32StartAddress = 9

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_ntdll = ctypes.WinDLL("ntdll", use_last_error=True)


class CLIENT_ID(ctypes.Structure):
    _fields_ = [
        ("UniqueProcess", ctypes.c_void_p),
        ("UniqueThread", ctypes.c_void_p),
    ]


class SYSTEM_THREAD_INFORMATION(ctypes.Structure):
    """x64 layout of one entry in a process's trailing thread array."""

    _fields_ = [
        ("KernelTime", ctypes.c_longlong),
        ("UserTime", ctypes.c_longlong),
        ("CreateTime", ctypes.c_longlong),
        ("WaitTime", wintypes.ULONG),
        ("StartAddress", ctypes.c_void_p),   # kernel start, not the Win32 one
        ("ClientId", CLIENT_ID),
        ("Priority", ctypes.c_long),
        ("BasePriority", ctypes.c_long),
        ("ContextSwitches", wintypes.ULONG),
        ("ThreadState", wintypes.ULONG),
        ("WaitReason", wintypes.ULONG),
    ]


_kernel32.OpenThread.restype = wintypes.HANDLE
_kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]

_kernel32.CloseHandle.restype = wintypes.BOOL
_kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

_kernel32.GetProcessIdOfThread.restype = wintypes.DWORD
_kernel32.GetProcessIdOfThread.argtypes = [wintypes.HANDLE]

_ntdll.NtQueryInformationThread.restype = wintypes.ULONG  # NTSTATUS, unsigned
_ntdll.NtQueryInformationThread.argtypes = [
    wintypes.HANDLE, wintypes.ULONG, ctypes.c_void_p, wintypes.ULONG,
    ctypes.POINTER(wintypes.ULONG),
]


def thread_ids(pid: int) -> list[int]:
    """Thread ids of one process, read from the bulk system table.

    Empty when the process is not in the table, which means it exited between
    the query and the walk.
    """
    buf = _query_buffer()
    entry_size = ctypes.sizeof(SYSTEM_PROCESS_INFORMATION)
    thread_size = ctypes.sizeof(SYSTEM_THREAD_INFORMATION)
    offset = 0
    while True:
        entry = SYSTEM_PROCESS_INFORMATION.from_buffer(buf, offset)
        if (entry.UniqueProcessId or 0) == pid:
            first = offset + entry_size
            return [
                int(SYSTEM_THREAD_INFORMATION.from_buffer(
                    buf, first + i * thread_size).ClientId.UniqueThread or 0)
                for i in range(entry.NumberOfThreads)
            ]
        if not entry.NextEntryOffset:
            return []
        offset += entry.NextEntryOffset


def start_addresses(pid: int) -> dict[int, int]:
    """Win32 start address of each of ``pid``'s threads, keyed by thread id.

    A thread is omitted when its handle will not open, when the handle turns
    out to belong to another process, or when the kernel refuses the address:
    unknown, which is not the same as zero. The caller sees a partial map
    rather than a wrong one.

    Callers should hold an open handle to ``pid`` across this call. That is
    what keeps the pid itself from being recycled while the threads are
    walked; the owner check below only covers the thread ids.

    A failed system table query is the same answer at a larger scale, so it
    yields an empty map rather than an exception: no thread id is known, and
    the thread-start rule stays silent. Raising here would let a transient
    query failure fail a region map that read perfectly well, and would end a
    recording that has no other reason to stop.
    """
    try:
        tids = thread_ids(pid)
    except OSError:
        return {}
    found: dict[int, int] = {}
    for tid in tids:
        handle = _kernel32.OpenThread(THREAD_QUERY_INFORMATION, False, tid)
        if not handle:
            continue  # another user's thread, or it exited
        try:
            # Thread ids are recycled like pids are. Between the table read
            # and this open, the thread can have exited and its id been taken
            # by a thread somewhere else entirely, whose start address would
            # then be filed against this process. Ask the handle who owns it.
            if _kernel32.GetProcessIdOfThread(handle) != pid:
                continue
            address = ctypes.c_size_t(0)
            status = _ntdll.NtQueryInformationThread(
                handle, ThreadQuerySetWin32StartAddress, ctypes.byref(address),
                ctypes.sizeof(address), None,
            )
            if status == 0 and address.value:
                found[tid] = address.value
        finally:
            _kernel32.CloseHandle(handle)
    return found
