"""Tests for the hex-dump formatter."""

from memdo.ui.hexdump import hexdump


def test_empty():
    assert hexdump(b"") == "(no data)"


def test_single_line_addr_and_ascii():
    line = hexdump(b"AB\x00\xff", base_addr=0x1000)
    # Address prefix, hex bytes, and ASCII gutter (non-printables -> '.').
    assert line.startswith("000000001000  ")
    assert "41 42 00 ff" in line
    assert line.endswith("AB..")


def test_multi_line_wrapping():
    data = bytes(range(20))  # 16 + 4 -> two lines
    out = hexdump(data, base_addr=0, width=16).splitlines()
    assert len(out) == 2
    # Second line's address advanced by the width.
    assert out[1].startswith("000000000010")


def test_short_line_is_padded():
    # A partial final row keeps the ascii column aligned via hex padding.
    out = hexdump(b"\x01\x02", width=16)
    assert "01 02" in out
    assert out.rstrip().endswith("..")
