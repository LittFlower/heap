import pytest

from kiwi import build_house_of_kiwi, build_house_of_kiwi_payload


def test_kiwi_boundary():
    assert build_house_of_kiwi(version="2.35").wide_vtable_offset == 0xE0

    with pytest.raises(ValueError):
        build_house_of_kiwi(version="2.36")


def test_kiwi_payload_writes_top_size():
    writes = build_house_of_kiwi_payload(
        version="2.30",
        top_size_addr=0x404040,
        top_size=0x31,
    )

    assert writes[0].address == 0x404040
    assert writes[0].data == (0x31).to_bytes(8, "little")
    assert writes[0].label == "top chunk size"


def test_kiwi_rejects_unaligned_top_size():
    with pytest.raises(ValueError):
        build_house_of_kiwi_payload(
            version="2.35",
            top_size_addr=0x404040,
            top_size=0x30,
        )
