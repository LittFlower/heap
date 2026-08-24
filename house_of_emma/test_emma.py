from emma import build_house_of_emma, encode_cookie_callback, recover_pointer_guard

def test_emma_plain_and_mangled_callbacks():
    assert encode_cookie_callback(0x1234, 0x9999, mangled=False) == 0x1234
    encoded = encode_cookie_callback(0x1234, 0x9999, mangled=True)
    assert recover_pointer_guard(0x1234, encoded) == 0x9999
    plain = build_house_of_emma(version='2.23', file_addr=0x100000, cookie_addr=0x200000, callback_addr=0x1234)[0].data
    assert plain[0xf0:0xf8] == (0x1234).to_bytes(8,'little')
    try:
        build_house_of_emma(version='2.24', file_addr=0x100000, cookie_addr=0x200000, callback_addr=0x1234)
    except ValueError:
        pass
    else:
        raise AssertionError('pointer guard omission accepted')

def test_emma_24_mangles_write():
    w = build_house_of_emma(version='2.24', file_addr=0x100000, cookie_addr=0x200000,
        callback_addr=0x1234, pointer_guard=0x9999)[0].data
    assert int.from_bytes(w[0xf0:0xf8], 'little') == encode_cookie_callback(0x1234, 0x9999, mangled=True)
