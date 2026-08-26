from snake import build_house_of_snake, build_house_of_snake_payload


def qword(data):
    return int.from_bytes(data, "little")


def test_snake_plan_keeps_printf_buffer_boundary_explicit():
    plan = build_house_of_snake(
        printf_buffer_addr=0x1000,
        obstack_addr=0x2000,
        object_base=0x3000,
        next_free=0x3100,
        chunkfun_addr=0x4000,
        extra_arg=0x5000,
    )

    assert plan.chunk_limit == 0x3100
    assert plan.obstack_addr == 0x2000


def test_snake_payload_builds_pointer_and_obstack_object():
    writes = build_house_of_snake_payload(
        printf_buffer_addr=0x1000,
        obstack_pointer_addr=0x1088,
        obstack_addr=0x2000,
        object_base=0x3000,
        next_free=0x3100,
        chunkfun_addr=0x4000,
        extra_arg=0x5000,
    )

    pointer_write, object_write = writes
    assert pointer_write.address == 0x1088
    assert pointer_write.data == (0x2000).to_bytes(8, "little")
    assert pointer_write.label == "printf_buffer.obstack pointer"

    image = object_write.data
    assert object_write.address == 0x2000
    assert qword(image[0x38:0x40]) == 0x4000
    assert qword(image[0x40:0x48]) == 0x5000
    assert int.from_bytes(image[0x50:0x54], "little") == 1
    assert qword(image[0x58:0x60]) == 0x3000
    assert qword(image[0x60:0x68]) == 0x3100
    assert qword(image[0x68:0x70]) == 0x3100
