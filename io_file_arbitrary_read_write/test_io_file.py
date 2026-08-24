import pytest

from io_file import (
    _IO_EOF_SEEN,
    _IO_NO_READS,
    apply_patches,
    build_stdin_arbitrary_write,
    build_stdout_arbitrary_read,
    patches_by_field,
)


def test_stdin_patch_preserves_flags_and_uses_exact_fd_width():
    patches = build_stdin_arbitrary_write(
        0x404000,
        0x21,
        fd=7,
        current_flags=0x1234 | _IO_NO_READS | _IO_EOF_SEEN,
    )
    fields = patches_by_field(patches)

    assert int.from_bytes(fields["_flags"], "little") == (
        (0x1234 | _IO_NO_READS | _IO_EOF_SEEN) & ~(_IO_NO_READS | _IO_EOF_SEEN)
    )
    assert len(fields["_flags"]) == 4
    assert fields["_IO_read_base"] == (0x404000).to_bytes(8, "little")
    assert fields["_IO_read_ptr"] == fields["_IO_read_end"]
    assert fields["_IO_buf_end"] == (0x404021).to_bytes(8, "little")
    assert fields["_fileno"] == (7).to_bytes(4, "little")


def test_stdout_patch_describes_read_region_and_serializes():
    patches = build_stdout_arbitrary_read(0x7FFFF000, 0x100, fd=1)
    image = apply_patches(patches)

    assert len(image) == 0xD8
    assert image[0x20:0x28] == (0x7FFFF000).to_bytes(8, "little")
    assert image[0x28:0x30] == (0x7FFFF100).to_bytes(8, "little")
    assert image[0x70:0x74] == (1).to_bytes(4, "little")


def test_base_image_allows_partial_field_plan():
    base = bytes([0xAA]) * 0xD8
    image = apply_patches(build_stdout_arbitrary_read(0x1000, 1), base=base)

    assert image[0] == 0xAA
    assert image[0x38:0x40] == (0x1000).to_bytes(8, "little")


@pytest.mark.parametrize(
    "target,length",
    [(0, 0), (-1, 1), (0xFFFFFFFFFFFFFFFF, 1)],
)
def test_invalid_region_is_rejected(target, length):
    with pytest.raises(ValueError):
        build_stdout_arbitrary_read(target, length)


def test_invalid_fd_is_rejected():
    with pytest.raises(ValueError):
        build_stdin_arbitrary_write(0x1000, 1, fd=0x1_0000_0000)
