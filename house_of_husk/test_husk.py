from husk import build_house_of_husk

def test_husk_uses_two_tables():
    writes = build_house_of_husk(
        printf_function_table_addr=0x1000,
        printf_arginfo_table_addr=0x2000,
        function_table_data_addr=0x3000,
        arginfo_table_data_addr=0x4000,
        format_char=ord('X'),
        handler_addr=0x5000,
    )
    assert writes[0].data == (0x3000).to_bytes(8, 'little')
    assert writes[1].data == (0x4000).to_bytes(8, 'little')
    assert writes[2].address == 0x4000 + (ord('X') - 2) * 8
    assert writes[2].data == (0x5000).to_bytes(8, 'little')
