from apple1 import build_house_of_apple1

def test_apple1_known_writes():
    writes = build_house_of_apple1(fake_file_addr=0x100000, wide_data_addr=0x200000, wstrn_jumps_addr=0x7FFFF000)
    file, wide = writes[0].data, writes[1].data
    known = 0x100000 + 0xF0
    assert file[0xA0:0xA8] == (0x200000).to_bytes(8,'little')
    assert file[0xD8:0xE0] == (0x7FFFF000).to_bytes(8,'little')
    for off in (0, 0x10, 0x18, 0x20, 0x28, 0x30): assert wide[off:off+8] == known.to_bytes(8,'little')
    for off in (8, 0x38): assert wide[off:off+8] == (known+0x100).to_bytes(8,'little')
