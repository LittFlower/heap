import pytest

from cat import build_house_of_cat


COMMON = dict(
    file_addr=0x100000,
    fake_wide_data_addr=0x200000,
    fake_wide_vtable_addr=0x201000,
    callback_addr=0x401234,
    wfile_jumps_addr=0x7FFFF000,
)


@pytest.mark.parametrize(
    "version,wide_offset",
    [("2.24", 0x130), ("2.29", 0x130), ("2.30", 0xF0), ("2.31", 0xE0), ("2.43", 0xE0)],
)
def test_cat_version_layout(version, wide_offset):
    writes = build_house_of_cat(version, **COMMON)
    by_label = {item.label: item for item in writes}
    assert by_label[f"FILE ({version})"].data[0xD8:0xE0] == (COMMON["wfile_jumps_addr"] + 0x30).to_bytes(8, "little")
    wide = by_label[f"fake wide_data ({version})"]
    assert int.from_bytes(wide.data[wide_offset:wide_offset + 8], "little") == COMMON["fake_wide_vtable_addr"]
    vtable = by_label["fake wide_vtable.__overflow"]
    assert int.from_bytes(vtable.data[0x18:0x20], "little") == COMMON["callback_addr"]


def test_invalid_version_is_rejected():
    with pytest.raises(ValueError):
        build_house_of_cat("2.23", **COMMON)
