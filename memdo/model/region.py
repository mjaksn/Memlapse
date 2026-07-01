"""Virtual memory region model and Win32 constant decoding.

A Region is one entry from VirtualQueryEx — a run of pages sharing the same
state, protection, and type. Constants are decoded to short human labels for
display and stored as raw integers in SQLite.
"""

from __future__ import annotations

from dataclasses import dataclass

# --- state -----------------------------------------------------------------
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_FREE = 0x10000

_STATE = {MEM_COMMIT: "Commit", MEM_RESERVE: "Reserve", MEM_FREE: "Free"}

# --- type ------------------------------------------------------------------
MEM_PRIVATE = 0x20000
MEM_MAPPED = 0x40000
MEM_IMAGE = 0x1000000

_TYPE = {MEM_PRIVATE: "Private", MEM_MAPPED: "Mapped", MEM_IMAGE: "Image"}

# --- protection ------------------------------------------------------------
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD = 0x100
PAGE_NOCACHE = 0x200
PAGE_WRITECOMBINE = 0x400

_PROTECT_BASE = {
    PAGE_NOACCESS: "---",
    PAGE_READONLY: "R--",
    PAGE_READWRITE: "RW-",
    PAGE_WRITECOPY: "RC-",
    PAGE_EXECUTE: "--X",
    PAGE_EXECUTE_READ: "R-X",
    PAGE_EXECUTE_READWRITE: "RWX",
    PAGE_EXECUTE_WRITECOPY: "RCX",
}


def protect_str(protect: int) -> str:
    """Short protection label, e.g. 'RW-' or 'R-X +G' for guarded pages."""
    if protect == 0:
        return "—"
    base = _PROTECT_BASE.get(protect & 0xFF, f"0x{protect & 0xFF:02x}")
    flags = ""
    if protect & PAGE_GUARD:
        flags += " +G"
    if protect & PAGE_NOCACHE:
        flags += " +NC"
    if protect & PAGE_WRITECOMBINE:
        flags += " +WC"
    return base + flags


@dataclass(frozen=True, slots=True)
class Region:
    base_addr: int
    size: int
    state: int
    protect: int
    type: int

    @property
    def end_addr(self) -> int:
        return self.base_addr + self.size

    @property
    def state_str(self) -> str:
        return _STATE.get(self.state, hex(self.state))

    @property
    def type_str(self) -> str:
        return _TYPE.get(self.type, "" if self.type == 0 else hex(self.type))

    @property
    def protect_str(self) -> str:
        return protect_str(self.protect)

    @property
    def is_readable(self) -> bool:
        """True if the region can be read with ReadProcessMemory as-is."""
        if self.state != MEM_COMMIT:
            return False
        if self.protect & (PAGE_NOACCESS | PAGE_GUARD):
            return False
        return True
