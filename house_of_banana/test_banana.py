from banana import build_house_of_banana

def test_banana_dynamic_items():
    writes = build_house_of_banana(fini_dyn_addr=0x1000, fini_size_dyn_addr=0x1010,
        fini_array_addr=0x3000, callback_addr=0x4000, link_map_base=0x1000, array_count=1)
    assert int.from_bytes(writes[0].data[0:8], 'little') == 26
    assert int.from_bytes(writes[0].data[8:16], 'little') == 0x2000
    assert int.from_bytes(writes[1].data[0:8], 'little') == 28
    assert int.from_bytes(writes[1].data[8:16], 'little') == 8
    assert writes[2].data == (0x4000).to_bytes(8, 'little')
