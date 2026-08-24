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


@pytest.mark.parametrize(
    "version,wide_offset",
    [("2.24", 0x130), ("2.29", 0x130), ("2.30", 0xF0), ("2.31", 0xE0), ("2.43", 0xE0)],
)
def test_version_specific_wide_vtable_offset(version, wide_offset):
    writes = build_house_of_apple2(version, **COMMON)
    by_label = {write.label: write for write in writes}

    wide = by_label[f"fake wide_data ({version})"]
    assert wide.address == COMMON["fake_wide_data_addr"]
    assert int.from_bytes(wide.data[wide_offset : wide_offset + 8], "little") == COMMON["fake_wide_vtable_addr"]
    assert int.from_bytes(wide.data[0xF0 : 0xF8], "little") == (0 if wide_offset != 0xF0 else COMMON["fake_wide_vtable_addr"])


def test_file_fields_and_callback_slot_follow_poc():
    writes = build_house_of_apple2("2.31", current_flags=0xFFFF, **COMMON)
    by_label = {write.label: write for write in writes}

    assert by_label["FILE._wide_data"].address == COMMON["file_addr"] + 0xA0
    assert by_label["FILE.vtable"].data == COMMON["wfile_jumps_addr"].to_bytes(8, "little")
    assert int.from_bytes(by_label["FILE._mode"].data, "little") == 1
    assert int.from_bytes(by_label["FILE._flags"].data, "little") == (0xFFFF & ~(0x8 | 0x2 | 0x800))

    vtable = by_label["fake wide_vtable.__doallocate"]
    assert vtable.address == COMMON["fake_wide_vtable_addr"]
    assert int.from_bytes(vtable.data[0x68:0x70], "little") == COMMON["callback_addr"]


def test_unknown_version_is_rejected():
    with pytest.raises(ValueError):
        build_house_of_apple2("2.23", **COMMON)