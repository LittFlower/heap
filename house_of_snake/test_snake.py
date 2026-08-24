from snake import build_house_of_snake

def test_snake_plan_keeps_printf_buffer_boundary_explicit():
    plan = build_house_of_snake(printf_buffer_addr=0x1000, obstack_addr=0x2000,
        object_base=0x3000, next_free=0x3100, chunkfun_addr=0x4000, extra_arg=0x5000)
    assert plan.chunk_limit == 0x3100
    assert plan.obstack_addr == 0x2000
