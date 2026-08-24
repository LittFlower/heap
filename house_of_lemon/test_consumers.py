import pytest
from lemon import build_house_of_lemon

def test_lemon_validated_size():
    plan = build_house_of_lemon(stdout_addr=0x3c4620, main_arena_addr=0x3c3b20, fake_chunk_header_addr=0x500000)
    assert plan.chunk_size == 0x17C0
