import pytest

from lemon import build_house_of_lemon, build_house_of_lemon_payload


def test_lemon_validated_size():
    plan = build_house_of_lemon(
        stdout_addr=0x3C4620,
        main_arena_addr=0x3C3B20,
        fake_chunk_header_addr=0x500000,
    )

    assert plan.request_size == 0x17B0
    assert plan.chunk_size == 0x17C0
    assert plan.stdout_vtable_addr == 0x3C46F8
    assert plan.fake_vtable_addr == 0x500000


def test_lemon_payload_writes_global_max_fast_and_stdout_vtable():
    writes = build_house_of_lemon_payload(
        stdout_addr=0x3C4620,
        main_arena_addr=0x3C3B20,
        fake_chunk_header_addr=0x500000,
        global_max_fast_addr=0x3C67F8,
    )

    assert writes[0].address == 0x3C67F8
    assert writes[0].data == (0x2000).to_bytes(8, "little")
    assert writes[0].label == "global_max_fast"

    assert writes[1].address == 0x3C46F8
    assert writes[1].data == (0x500000).to_bytes(8, "little")
    assert writes[1].label == "stdout vtable slot"


def test_lemon_rejects_wrong_layout():
    with pytest.raises(ValueError):
        build_house_of_lemon(
            stdout_addr=0x3C5620,
            main_arena_addr=0x3C3B20,
            fake_chunk_header_addr=0x500000,
        )
