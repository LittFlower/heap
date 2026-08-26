import pytest

from apple2 import build_house_of_apple2


COMMON = dict(
    file_addr=0x100000,
    fake_wide_data_addr=0x200000,
    fake_wide_vtable_addr=0x201000,
    callback_addr=0x401234,
    wfile_jumps_addr=0x7FFFF000,
    narrow_buffer_addr=0x300000,
)


def find_write(writes, address):
    for write in writes:
        if write.address == address:
            return write
    raise AssertionError(f"write at {address:#x} was not returned")


@pytest.mark.parametrize(
    "version,wide_offset",
    [
        ("2.24", 0x130),
        ("2.29", 0x130),
        ("2.30", 0xF0),
        ("2.31", 0xE0),
        ("2.43", 0xE0),
    ],
)
def test_version_specific_wide_vtable_offset(version, wide_offset):
    writes = build_house_of_apple2(version, **COMMON)
    wide = find_write(writes, COMMON["fake_wide_data_addr"])

    actual = int.from_bytes(
        wide.data[wide_offset:wide_offset + 8],
        "little",
    )
    assert actual == COMMON["fake_wide_vtable_addr"]

    transition_value = int.from_bytes(wide.data[0xF0:0xF8], "little")
    expected = 0
    if wide_offset == 0xF0:
        expected = COMMON["fake_wide_vtable_addr"]
    assert transition_value == expected


def test_file_fields_and_callback_slot_follow_poc():
    writes = build_house_of_apple2("2.31", current_flags=0xFFFF, **COMMON)
    file_write = find_write(writes, COMMON["file_addr"])
    vtable_write = find_write(writes, COMMON["fake_wide_vtable_addr"])

    assert int.from_bytes(file_write.data[0xA0:0xA8], "little") == COMMON[
        "fake_wide_data_addr"
    ]
    assert int.from_bytes(file_write.data[0xD8:0xE0], "little") == COMMON[
        "wfile_jumps_addr"
    ]
    assert int.from_bytes(file_write.data[0xC0:0xC4], "little") == 1
    assert int.from_bytes(file_write.data[0:4], "little") == (
        0xFFFF & ~(0x8 | 0x2 | 0x800)
    )
    assert int.from_bytes(vtable_write.data[0x68:0x70], "little") == COMMON[
        "callback_addr"
    ]


def test_unknown_version_is_rejected():
    with pytest.raises(ValueError):
        build_house_of_apple2("2.23", **COMMON)
