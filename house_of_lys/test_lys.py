import pytest

from lys import build_house_of_lys, build_house_of_lys_payload


def qword(data):
    return int.from_bytes(data, "little")


def test_lys_version_delta():
    plan = build_house_of_lys(
        version="2.23",
        wfile_jumps_addr=0x700000,
        obstack_addr=1,
        chunkfun_addr=2,
        extra_arg=3,
    )

    assert plan.primary_vtable_addr == 0x700000 - 0x1100

    with pytest.raises(ValueError):
        build_house_of_lys(
            version="2.37",
            wfile_jumps_addr=1,
            obstack_addr=1,
            chunkfun_addr=1,
            extra_arg=1,
        )


def test_lys_payload_builds_file_and_obstack_images():
    writes = build_house_of_lys_payload(
        version="2.24",
        file_addr=0x100000,
        wfile_jumps_addr=0x700000,
        obstack_addr=0x200000,
        chunkfun_addr=0x401000,
        extra_arg=0x500000,
        object_base=0x300000,
        next_free=0x300100,
        chunk_limit=0x300100,
    )

    file_write, obstack_write = writes
    assert file_write.address == 0x100000
    assert qword(file_write.data[0xD8:0xE0]) == 0x700000 + 0x320
    assert qword(file_write.data[0xE0:0xE8]) == 0x200000

    image = obstack_write.data
    assert obstack_write.address == 0x200000
    assert qword(image[0x38:0x40]) == 0x401000
    assert qword(image[0x40:0x48]) == 0x500000
    assert int.from_bytes(image[0x50:0x54], "little") == 1
    assert qword(image[0x58:0x60]) == 0x300000
    assert qword(image[0x60:0x68]) == 0x300100
    assert qword(image[0x68:0x70]) == 0x300100
