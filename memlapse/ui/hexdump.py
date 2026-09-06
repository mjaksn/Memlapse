"""Classic hex + ASCII dump formatting."""

from __future__ import annotations


def hexdump(data: bytes, base_addr: int = 0, width: int = 16) -> str:
    if not data:
        return "(no data)"
    lines = []
    for offset in range(0, len(data), width):
        chunk = data[offset:offset + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        hex_part = hex_part.ljust(width * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{base_addr + offset:012x}  {hex_part}  {ascii_part}")
    return "\n".join(lines)
