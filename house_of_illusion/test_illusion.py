import pytest
from illusion import build_illusion_shifted_write, build_illusion_normal_read

COMMON = dict(file_addr=0x100000, file_jumps_addr=0x7FFFF000, lock_addr=0x400000,
              fd=3, target_addr=0x300000, length=0x20)

def test_shifted_write_legacy():
    w = build_illusion_shifted_write("2.39", **COMMON)[0].data
    assert w[0xd8:0xe0] == (COMMON["file_jumps_addr"] - 8).to_bytes(8,"little")
    assert w[0x20:0x28] == COMMON["target_addr"].to_bytes(8,"little")
    assert w[0x28:0x30] == (COMMON["target_addr"] + COMMON["length"]).to_bytes(8,"little")

def test_shifted_write_240_prevchain():
    w = build_illusion_shifted_write("2.40", io_list_all_addr=0x7FFF2000, **COMMON)[0].data
    assert w[0xb8:0xc0] == (0x7FFF2000).to_bytes(8,"little")

def test_normal_read_uses_real_vtable():
    args = {key: value for key, value in COMMON.items() if key != "fd"}
    w = build_illusion_normal_read("2.43", io_list_all_addr=0x7FFF2000, output_fd=5, **args)[0].data
    assert w[0xd8:0xe0] == COMMON["file_jumps_addr"].to_bytes(8,"little")
    assert int.from_bytes(w[0x70:0x74],"little") == 5

def test_new_version_requires_prevchain():
    with pytest.raises(ValueError):
        build_illusion_shifted_write("2.40", **COMMON)
