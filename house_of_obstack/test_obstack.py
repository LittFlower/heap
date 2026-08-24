from obstack import build_obstack_payload, build_obstack_plan


def qword(data):
    return int.from_bytes(data, "little")


def test_obstack_plan_forces_growth():
    plan = build_obstack_plan(
        object_base=0x1000,
        next_free=0x1100,
        chunkfun_addr=0x4000,
        extra_arg=0x5000,
    )

    assert plan.chunk_limit == 0x1100
    assert plan.use_extra_arg == 1
    assert plan.chunkfun == 0x4000


def test_obstack_payload_builds_fake_object():
    writes = build_obstack_payload(
        obstack_addr=0x2000,
        object_base=0x1000,
        next_free=0x1100,
        chunkfun_addr=0x4000,
        extra_arg=0x5000,
    )

    write = writes[0]
    image = write.data
    assert write.address == 0x2000
    assert write.label == "fake obstack object"
    assert qword(image[0x38:0x40]) == 0x4000
    assert qword(image[0x40:0x48]) == 0x5000
    assert int.from_bytes(image[0x50:0x54], "little") == 1
    assert qword(image[0x58:0x60]) == 0x1000
    assert qword(image[0x60:0x68]) == 0x1100
    assert qword(image[0x68:0x70]) == 0x1100
