import pytest
from lys import build_house_of_lys

def test_lys_version_delta():
    assert build_house_of_lys(version='2.23', wfile_jumps_addr=0x700000, obstack_addr=1, chunkfun_addr=2, extra_arg=3).primary_vtable_addr == 0x700000 - 0x1100
    with pytest.raises(ValueError): build_house_of_lys(version='2.37', wfile_jumps_addr=1, obstack_addr=1, chunkfun_addr=1, extra_arg=1)
