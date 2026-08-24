import pytest
from some import build_house_of_some

COMMON = dict(file_addr=0x100000, wide_addr=0x200000, file_jumps_addr=0x7FFFF000,
              wfile_jumps_addr=0x7FFFF100, target_addr=0x300000, target_length=0x20,
              fd=3, lock_addr=0x400000, list_all_addr=0x7FFFF200)

@pytest.mark.parametrize("version,offset", [("2.23",0x130),("2.30",0xF0),("2.31",0xE0),("2.43",0xE0)])
def test_some_version_layout(version, offset):
    writes = build_house_of_some(version, prevchain_addr=COMMON["list_all_addr"], **COMMON)
    by = {w.label:w for w in writes}
    file = by[f"FILE ({version})"].data
    wide = by[f"wide_data ({version})"].data
    assert file[0xd8:0xe0] == COMMON["wfile_jumps_addr"].to_bytes(8,"little")
    assert int.from_bytes(wide[offset:offset+8],"little") == COMMON["file_jumps_addr"] - 0x48
    if version >= "2.40":
        assert file[0xb8:0xc0] == COMMON["list_all_addr"].to_bytes(8,"little")

def test_some_requires_prevchain_for_new_glibc():
    with pytest.raises(ValueError):
        build_house_of_some("2.40", **COMMON)
