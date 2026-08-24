import pytest
from kiwi import build_house_of_kiwi

def test_kiwi_boundary():
    assert build_house_of_kiwi(version='2.35').wide_vtable_offset == 0xE0
    with pytest.raises(ValueError): build_house_of_kiwi(version='2.36')
