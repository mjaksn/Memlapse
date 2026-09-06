"""Live process collector.

Runs the shared polling loop (:class:`PollingCollector`) on its own QThread
and emits a fresh snapshot of every process on each tick. The process table
comes from one bulk ``NtQuerySystemInformation`` call (see
:mod:`memlapse.win32.processes`), which is a single GIL-free syscall rather
than a handle open per process; psutil is only consulted for the owning user
name, once per process instance, since that is not in the bulk table.
"""

from __future__ import annotations

import psutil

from ..model import ProcessInfo
from ..win32.processes import list_processes
from .base import PollingCollector


class ProcessCollector(PollingCollector):
    """Polls the process list every ``interval`` seconds until stopped."""

    def __init__(self, interval: float = 1.0, parent=None) -> None:
        super().__init__(interval, parent)
        # (pid, create_time) -> username. Keyed on the creation time as well
        # so a reused pid is looked up afresh rather than served a stale name.
        self._usernames: dict[tuple[int, int], str] = {}

    def _poll(self) -> list[ProcessInfo]:
        procs = list_processes()
        live: dict[tuple[int, int], str] = {}
        results: list[ProcessInfo] = []
        for p in procs:
            key = (p.pid, p.create_time)
            username = self._usernames.get(key)
            if username is None:
                username = self._lookup_username(p.pid)
            live[key] = username
            results.append(ProcessInfo(
                pid=p.pid,
                name=p.name or "?",
                username=username,
                num_threads=p.num_threads,
                wset_bytes=p.wset_bytes,
                private_bytes=p.private_bytes,
            ))
        self._usernames = live  # drop entries for processes that have exited
        return results

    @staticmethod
    def _lookup_username(pid: int) -> str:
        """Owning user without the domain prefix; empty when not readable."""
        try:
            return psutil.Process(pid).username().split("\\")[-1]
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return ""
