from obstack import build_obstack_plan

def test_obstack_plan_forces_growth():
    plan = build_obstack_plan(object_base=0x1000, next_free=0x1100, chunkfun_addr=0x4000, extra_arg=0x5000)
    assert plan.chunk_limit == 0x1100
    assert plan.use_extra_arg == 1
    assert plan.chunkfun == 0x4000
