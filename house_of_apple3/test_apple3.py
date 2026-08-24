import pytest

from apple3 import build_house_of_apple3


COMMON = dict(
    file_addr=0x100000,
    fake_codecvt_addr=0x200000,
    fake_step_addr=0x201000,
    callback_addr=0x401234,
    wide_data_addr=0x202000,
    wide_output_addr=0x203000,
    external_input_addr=0x204000,
)


@pytest.mark.parametrize(
    "version,codecvt_offset",
    [("2.23", 0x18), ("2.29", 0x18), ("2.30", 0x28), ("2.31", 0x28), ("2.43", 0x28)],
)
def test_codecvt_version_layout(version, codecvt_offset):
    writes = build_house_of_apple3(version, **COMMON)
    by_label = {item.label: item for item in writes}
    codecvt = by_label[f"fake codecvt ({version})"]
    if version in {"2.23", "2.29"}:
        assert int.from_bytes(codecvt.data[codecvt_offset:codecvt_offset + 8], "little") == COMMON["callback_addr"]
    elif version == "2.30":
        assert int.from_bytes(codecvt.data[8:16], "little") == COMMON["fake_step_addr"]
        step = by_label["fake __gconv_step"]
        assert int.from_bytes(step.data[0x28:0x30], "little") == COMMON["callback_addr"]
    else:
        assert int.from_bytes(codecvt.data[0:8], "little") == COMMON["fake_step_addr"]
        step = by_label["fake __gconv_step"]
        assert int.from_bytes(step.data[0x28:0x30], "little") == COMMON["callback_addr"]


def test_file_and_wide_buffers_follow_poc():
    writes = build_house_of_apple3("2.31", current_flags=0xFFFF, **COMMON)
    by_label = {item.label: item for item in writes}
    assert by_label["FILE._codecvt"].address == COMMON["file_addr"] + 0x98
    assert int.from_bytes(by_label["FILE._mode"].data, "little") == 1
    assert int.from_bytes(by_label["FILE._flags"].data, "little") == (0xFFFF & ~(0x10 | 0x4))
    wide = by_label["wide_data buffers"]
    assert int.from_bytes(wide.data[0x30:0x38], "little") == COMMON["wide_output_addr"]
    assert int.from_bytes(wide.data[0x38:0x40], "little") == COMMON["wide_output_addr"] + 0x20


def test_unsupported_version_is_rejected():
    with pytest.raises(ValueError):
        build_house_of_apple3("2.22", **COMMON)