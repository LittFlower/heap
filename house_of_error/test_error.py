import pytest
from error import build_house_of_error
from emma import build_house_of_emma, encode_cookie_callback, recover_pointer_guard

def test_error_mem_sync_fields():
    w = build_house_of_error(file_addr=0x100000, mem_jumps_addr=0x700000,
        bufloc_addr=0x200000, sizeloc_addr=0x200008,
        write_base_addr=0x300000, write_length=0x123)[0].data
    assert w[0x20:0x28] == (0x300000).to_bytes(8,'little')
    assert w[0x28:0x30] == (0x300123).to_bytes(8,'little')
    assert w[0xd8:0xe0] == (0x700038).to_bytes(8,'little')
    assert w[0xf0:0xf8] == (0x200000).to_bytes(8,'little')

def test_emma_plain_and_mangled_callbacks():
    assert encode_cookie_callback(0x1234, 0x9999, mangled=False) == 0x1234
    encoded = encode_cookie_callback(0x1234, 0x9999, mangled=True)
    assert recover_pointer_guard(0x1234, encoded) == 0x9999
    plain = build_house_of_emma(version='2.23', file_addr=0x100000, cookie_addr=0x200000, callback_addr=0x1234)[0].data
    assert plain[0xf0:0xf8] == (0x1234).to_bytes(8,'little')
    with pytest.raises(ValueError):
        build_house_of_emma(version='2.24', file_addr=0x100000, cookie_addr=0x200000, callback_addr=0x1234)

def test_emma_24_mangles_write():
    w = build_house_of_emma(version='2.24', file_addr=0x100000, cookie_addr=0x200000,
        callback_addr=0x1234, pointer_guard=0x9999)[0].data
    assert int.from_bytes(w[0xf0:0xf8], 'little') == encode_cookie_callback(0x1234, 0x9999, mangled=True)
