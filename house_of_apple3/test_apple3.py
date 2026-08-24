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


def find_write(writes, address):
    for write in writes:
        if write.address == address:
            return write
    raise AssertionError(f"write at {address:#x} was not returned")


@pytest.mark.parametrize(
    "version,codecvt_offset",
    [
        ("2.23", 0x18),
        ("2.29", 0x18),
        ("2.30", 0x28),
        ("2.31", 0x28),
        ("2.43", 0x28),
    ],
)
def test_codecvt_version_layout(version, codecvt_offset):
    writes = build_house_of_apple3(version, **COMMON)
    codecvt = find_write(writes, COMMON["fake_codecvt_addr"])

    if version in {"2.23", "2.29"}:
        value = int.from_bytes(
            codecvt.data[codecvt_offset:codecvt_offset + 8],
            "little",
        )
        assert value == COMMON["callback_addr"]
    elif version == "2.30":
        assert int.from_bytes(codecvt.data[8:16], "little") == COMMON[
            "fake_step_addr"
        ]
        step = find_write(writes, COMMON["fake_step_addr"])
        assert int.from_bytes(step.data[0x28:0x30], "little") == COMMON[
            "callback_addr"
        ]
    else:
        assert int.from_bytes(codecvt.data[0:8], "little") == COMMON[
            "fake_step_addr"
        ]
        step = find_write(writes, COMMON["fake_step_addr"])
        assert int.from_bytes(step.data[0x28:0x30], "little") == COMMON[
            "callback_addr"
        ]


def test_file_and_wide_buffers_follow_poc():
    writes = build_house_of_apple3("2.31", current_flags=0xFFFF, **COMMON)
    file_write = find_write(writes, COMMON["file_addr"])
    wide = find_write(writes, COMMON["wide_data_addr"])

    assert int.from_bytes(file_write.data[0x98:0xA0], "little") == COMMON[
        "fake_codecvt_addr"
    ]
    assert int.from_bytes(file_write.data[0xC0:0xC4], "little") == 1
    assert int.from_bytes(file_write.data[0:4], "little") == (
        0xFFFF & ~(0x10 | 0x4)
    )
    assert int.from_bytes(wide.data[0x30:0x38], "little") == COMMON[
        "wide_output_addr"
    ]
    assert int.from_bytes(wide.data[0x38:0x40], "little") == (
        COMMON["wide_output_addr"] + 0x20
    )


def test_unsupported_version_is_rejected():
    with pytest.raises(ValueError):
        build_house_of_apple3("2.22", **COMMON)
