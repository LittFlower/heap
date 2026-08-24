import pytest
from pig import build_house_of_pig

def test_pig_branches():
    assert build_house_of_pig(version='2.27', old_buffer_addr=1, old_length=0x20, stream_addr=0x1000).allocate_slot_addr == 0x10e0
    assert build_house_of_pig(version='2.28', old_buffer_addr=1, old_length=0x20).new_size == 164
