"""Obstack/Snake chunkfun callback parameter plans."""
from dataclasses import dataclass

@dataclass(frozen=True)
class ObstackPlan:
    object_base: int
    next_free: int
    chunk_limit: int
    chunkfun: int
    extra_arg: int
    use_extra_arg: int = 1

def build_obstack_plan(*, object_base: int, next_free: int,
                       chunkfun_addr: int, extra_arg: int,
                       chunk_limit: int | None = None) -> ObstackPlan:
    """生成旧 Obstack 和新 Snake 共用的 obstack 字段计划。

    object_base: 当前 obstack chunk 起点；next_free: 当前写指针。
    chunk_limit: 当前 chunk 末尾，省略时使用 next_free 让扩容立即发生。
    chunkfun_addr: `_obstack_newchunk` 间接调用的分配回调。
    extra_arg: callback 第一个参数；use_extra_arg 固定为 1。
    """
    if chunk_limit is None: chunk_limit = next_free
    values = (object_base, next_free, chunk_limit, chunkfun_addr, extra_arg)
    if any(not isinstance(v, int) or v < 0 or v >= 1 << 64 for v in values):
        raise ValueError("obstack addresses must fit uint64")
    return ObstackPlan(object_base, next_free, chunk_limit, chunkfun_addr, extra_arg)
