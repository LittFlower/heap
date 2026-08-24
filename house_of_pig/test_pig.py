import pytest

from pig import build_house_of_pig, build_house_of_pig_payload


def qword(data):
    return int.from_bytes(data, "little")


def test_pig_legacy_plan_slots():
    plan = build_house_of_pig(
        version="2.27",
        old_buffer_addr=0x300000,
        old_length=0x40,
        stream_addr=0x200000,
    )

    assert plan.new_size == 0xE4
    assert plan.allocate_slot_addr == 0x2000E0
    assert plan.free_slot_addr == 0x2000E8


def test_pig_modern_plan_has_no_legacy_slots():
    plan = build_house_of_pig(
        version="2.28",
        old_buffer_addr=0x300000,
        old_length=0x40,
    )

    assert plan.new_size == 0xE4
    assert plan.allocate_slot_addr is None
    assert plan.free_slot_addr is None


def test_pig_legacy_payload_writes_callback_slots():
    payload = build_house_of_pig_payload(
        version="2.27",
        stream_addr=0x200000,
        old_buffer_addr=0x300000,
        old_length=0x40,
        allocate_callback_addr=0x401000,
        free_callback_addr=0x402000,
    )

    labels = [write.label for write in payload.writes]
    assert labels == ["_IO_strfile._allocate_buffer", "_IO_strfile._free_buffer"]
    assert payload.writes[0].address == 0x2000E0
    assert payload.writes[0].data == (0x401000).to_bytes(8, "little")
    assert payload.writes[1].address == 0x2000E8
    assert payload.writes[1].data == (0x402000).to_bytes(8, "little")


def test_pig_modern_payload_forces_expansion_branch():
    payload = build_house_of_pig_payload(
        version="2.35",
        stream_addr=0x200000,
        old_buffer_addr=0x300000,
        old_length=0x40,
    )

    assert payload.plan.new_size == 0xE4
    assert len(payload.writes) == 1
    write = payload.writes[0]
    image = write.data
    assert write.address == 0x200000
    assert write.label == "_IO_str_overflow expansion fields"
    assert qword(image[0x08:0x10]) == 0x300000
    assert qword(image[0x10:0x18]) == 0x300000
    assert qword(image[0x18:0x20]) == 0x300000
    assert qword(image[0x20:0x28]) == 0x300000
    assert qword(image[0x28:0x30]) == 0x300040
    assert qword(image[0x30:0x38]) == 0x300040
    assert qword(image[0x38:0x40]) == 0x300000
    assert qword(image[0x40:0x48]) == 0x300040


def test_pig_rejects_missing_legacy_callbacks():
    with pytest.raises(ValueError):
        build_house_of_pig_payload(
            version="2.27",
            stream_addr=0x200000,
            old_buffer_addr=0x300000,
            old_length=0x40,
        )
