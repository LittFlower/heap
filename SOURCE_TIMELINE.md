# glibc 2.23～2.43 Heap 源码时间线

本页记录“为什么在这个版本分段”，便于拿到附件 libc 后按提交反查。判断顺序是：Build ID → 发行版源码包 → 上游 tag/commit；不要只信 `ldd --version` 的两位版本号。

## 关键提交

| 进入版本 | 提交/源码变化 | 对利用的影响 |
|---|---|---|
| 2.24 | [db3476a：libio vtable validation](https://sourceware.org/git/?p=glibc.git;a=commit;h=db3476aff19b75c4fdefbe65fcd5f0a90588ba51) | heap 上任意 fake 窄 vtable 失败；需指向 `__libc_IO_vtables` 内合法表。 |
| 2.24 | [983fd5c：fopencookie 回调 pointer mangling](https://sourceware.org/git/?p=glibc.git;a=commit;h=983fd5c41ab7e5a5c33922259ca1ac99b3b413f8) | House of Emma 在 2.23 可写明文回调；2.24 起必须掌握/恢复 pointer_guard 并写入 mangled 指针。 |
| 2.26 | [d5c3faf：tcache 引入](https://sourceware.org/git/?p=glibc.git;a=commit;h=d5c3fafc4307c9b7a4c7d5cb381fcdbfad340bcc) | free/malloc 默认先走 tcache，所有 fastbin/smallbin PoC 需重新排布；Roman 原 fastbin 第 1 段不能原样延长，本项目改为 count=3 的 tcache 链。 |
| 2.26 | [91e7cf9：malloc_printerr 行为变化](https://sourceware.org/git/?p=glibc.git;a=commit;h=91e7cf982d0104f0e71770f5ae8e3faf352dea9f) | 经典 Orange 的错误→flush→fake FILE 触发链终止。 |
| 2.26 | [17f487b：unlink size/prev_size](https://sourceware.org/git/?p=glibc.git;a=commit;h=17f487b7afa7cd6c316040f3e6c86dc96b2eec30) | Poison Null Byte/Einherjar 必须让 fake chunk size 与其下一边界的 `prev_size` 一致。 |
| 2.27 | [e956075：`malloc_state` 新增 `have_fastchunks`](https://sourceware.org/git/?p=glibc.git;a=commit;h=e956075a5a2044d05ce48b905b10270ed4a63e87) | fastbinsY 整体后移；更关键的是 House of Gods 原链把 `main_arena+8` 当 fake size 的重叠从 fastbin 指针变成 0/1 标志，原版单-UAF binmap 链不能靠改偏移满足 unsorted size 下界。 |
| 2.27 | [3f6bb8a：malloc/calloc 单线程快路径](https://sourceware.org/git/?p=glibc.git;a=commit;h=3f6bb8a32e5f5efd78ac08c41e623651cc242a89) | 单线程 `malloc` 直接使用 `main_arena`，不读取 `thread_arena`；即使另有能力写坏 thread_arena，也要有真实多线程状态或改走其他消费路径。 |
| 2.28 | [4e8a634：`strops.c` 改用直接 malloc/free](https://sourceware.org/git/?p=glibc.git;a=commit;h=4e8a6346cd3da2d88bbad745a1769260d36f2783) | `_IO_strfile` 的 `_allocate_buffer/_free_buffer` 不再作为可控回调，旧合法-vtable 回调 FSOP 终止；与此同时，现代 House of Pig 使用的直接 `malloc→memcpy→free` 扩容最终触发点从此版本开始。 |
| 2.28 | [bdc3009：harden unsorted removal](https://sourceware.org/git/?p=glibc.git;a=commit;h=bdc3009b8ff0effdbbfb05eb6b10966753cbf9b8) | 摘链前检查 `bck->fd == victim`；target 初值任意的经典 Unsorted Bin Attack、单 fake-node Into Stack、Roman hook 投递与 Storm 交叉链均止于 2.27。Storm 在第二次 fake-victim 摘链时也无法满足该检查。2.29 的 `b90ddd0` 是进一步加固，不是第一道检查。 |
| 2.29 | [30a17d8：检查 top <= system_mem](https://sourceware.org/git/?p=glibc.git;a=commit;h=30a17d8c95fbfb15c52d1115803b63aaa73a285c) | House of Force 的 top=-1 环绕失效。 |
| 2.29 | [b90ddd0：进一步 unsorted 完整性检查](https://sourceware.org/git/?p=glibc.git;a=commit;h=b90ddd08f6dd688e651df9ee89ca3a69ff88cd0c) | 在 2.28 `bck->fd` 检查之上再验证 victim/next size、`next->prev_size`、`prev_inuse(next)` 等；旧 freed-size overlap 在此出现额外硬边界，Roman/Storm 则已先在 2.28 失效。 |
| 2.29 | [bcdaad2：tcache double-free key](https://sourceware.org/git/?p=glibc.git;a=commit;h=bcdaad21d4635931d1bd3b54a7894276925d081d) | 直接 tcache dup 终止；Botcake/Kauri 等转向绕 key。 |
| 2.29 | [d6db68e：向后合并前再查 size/prev_size](https://sourceware.org/git/?p=glibc.git;a=commit;h=d6db68e66dff25d12c3bc5641b60cbd7fb6ab44f) | 旧 Poison Null Byte stale-`prev_size` 链终止；现代链改用一致 fake chunk + largebin 残留指针。 |
| 2.30 | [`__libc_malloc` 改查 `tcache->counts`](https://github.com/bminor/glibc/blob/glibc-2.30/malloc/malloc.c) | count 为 0、entry 非空的状态不再被消费；House of Atum 原始 entry/count 错位链终止。 |
| 2.30 | [09e1b0e：删除 legacy codecvt 函数表](https://sourceware.org/git/?p=glibc.git;a=commit;h=09e1b0e3f6facc1af2dbcfef204f0aaa8718772b) | `_IO_wide_data._wide_vtable` 从 x86-64 `+0x130` 变为 `+0xf0`；Apple3 从 `codecvt+0x18` 直接 do_in 改为 `codecvt+0x8 → step+0x28`。 |
| 2.31 | [70c6e15：缩小 `_IO_iconv_t`](https://sourceware.org/git/?p=glibc.git;a=commit;h=70c6e15654928c603c6d24bd01cf62e7a8e2ce9b) | `_wide_vtable` 再从 `+0xf0` 变为现代 `+0xe0`；Apple3 的 step 指针从 `codecvt+0x8` 移到 `+0x0`，两项持续到 2.43。 |
| 2.32 | [a1a486d：safe-linking](https://sourceware.org/git/?p=glibc.git;a=commit;h=a1a486d70ebcc47a686ff5846875eacad0940e41) | tcache/fastbin next 变为 `(pos>>12)^ptr`，取出检查 0x10 对齐。 |
| 2.34 | [fc859c3：随机化 tcache double-free key](https://sourceware.org/git/?p=glibc.git;a=commit;h=fc859c304898a5ec72e0ba5269ed136ed0ea10e1) | `e->key` 从 tcache metadata 地址改为进程随机值，House of IO 的 UAF key 泄露止于 2.33。 |
| 2.34 | [1e5a586：remove malloc hooks](https://sourceware.org/git/?p=glibc.git;a=commit;h=1e5a5866cb9541b5231dba3d86c8a1a35d516de9) | 正常 malloc/free 不再调用 `__malloc_hook/__free_hook`；旧 PoC 的最终目标需替换。 |
| 2.36 | [ac8047c：简化 `__malloc_assert`](https://sourceware.org/git/?p=glibc.git;a=commit;h=ac8047cdf326504f652f7db97ec96c0e0cee052f) | 改用 `__libc_message`，删除 `__fxprintf + fflush(stderr)`；House of Kiwi 专属 assert→FSOP 触发器止于 2.35。 |
| 2.37 | [118816d：`vswprintf` 改为 printf_buffer](https://sourceware.org/git/?p=glibc.git;a=commit;h=118816de3383ff12769349784689141355cc787c) | 删除 `_IO_wstrn_overflow/_IO_wstrn_jumps`，House of Apple1 的已知值写最终触发点止于 2.36。不要和仍在的 `_IO_wstr_overflow` 混淆。 |
| 2.37 | [5365acc：obstack printf 改为 buffers](https://sourceware.org/git/?p=glibc.git;a=commit;h=5365acc567a49270b4341b9d325794ec554258d9) | 删除经典 `_IO_obstack_jumps` printf 路径；`__printf_buffer_flush_obstack → _obstack_newchunk → chunkfun` 成为 House of Snake 最终触发点。 |
| 2.37 | [15a94e6：global_max_fast 改 uint8_t](https://sourceware.org/git/?p=glibc.git;a=commit;h=15a94e6668a6d7c5697e805d8d67f1d102d0d52e) | Corrosion/Crust 的超大尺寸 fastbin 远端写硬失效：最大 0xff 只能覆盖 fastbinsY 后约 0x6f 字节，不能到达一般 libc/ld 目标。 |
| 2.40 | [2a99e23：`_IO_list_all` 改双向链表](https://sourceware.org/git/?p=glibc.git;a=commit;h=2a99e2398d9d717c034e915f7846a49e623f5450) | `_IO_FILE+0xb8` 的 ABI padding 复用为 `_prevchain`；House of Some/Illusion 等把 fake FILE 挂入全局链时必须维护反向链接，否则摘链/finish 可空指针崩溃。 |
| 2.41 | [226e3b0：calloc 走 tcache](https://sourceware.org/git/?p=glibc.git;a=commit;h=226e3b0a413673c0d6691a0ae6dd001fe05d21cd) | 用 calloc 绕 tcache 的旧 fastbin PoC 必须先耗尽 tcache。 |
| 2.41 | [e2436d6：smallbin/stashing 重构](https://sourceware.org/git/?p=glibc.git;a=commit;h=e2436d6f5aa47ce8da80c2ba0f59dfb9ffde08f3) | 经典 TSU/TSU+ PoC 终止，Rust/Crust 组合窗口关闭。 |
| 2.42 | [eff1f68：tcache 全 bin double-free 扫描](https://sourceware.org/git/?p=glibc.git;a=commit;h=eff1f680cffb005a5623d1c8a952d095b988d6a2) | House of Kauri 的“改 size 换 bin”绕过终止。 |
| 2.42 | [7e10e30：tcache count 向下计数](https://sourceware.org/git/?p=glibc.git;a=commit;h=7e10e30e64aa2cc8ba50f2f83cb7cc2cdad134ad) | `counts` 语义变为剩余 slots，旧 metadata/relative-write 偏移与逻辑失效。 |
| 2.42 | [cbfd798：large tcache](https://sourceware.org/git/?p=glibc.git;a=commit;h=cbfd7988107b27b9ff1d0b57fa2c8f13a932e508) | 新增 12 个有序 logarithmic bins 与 metadata 布局；默认 `tcache_max` 未启用 large bins。2.42 同 bin 查找接受第一个 `size >= request`。 |
| 2.42 | [4cf2d86：largebin nextsize 检查](https://sourceware.org/git/?p=glibc.git;a=commit;h=4cf2d869367e3813c6c8f662915dedb1f3830c53) | 2.30～2.41 的 `bk_nextsize=target-0x20` 任意目标写终止。 |
| 2.42 | [d10176c：fastbin→tcache size 检查](https://sourceware.org/git/?p=glibc.git;a=commit;h=d10176c0ffeadbc0bcd443741f53ebd85e70db44) | fastbin reverse into tcache 需新的 fake size/链布局。 |
| 2.43 | [bf1015f 等：删除 fastbin allocation/consolidate/infrastructure](https://sourceware.org/git/?p=glibc.git;a=commit;h=bf1015fb2d7e4057925481960626533f8571a2fb) | fastbin dup、Mind fastbin、House of Corrosion 的 fastbin 指针搬运等不再有消费路径。 |
| 2.43 | [ad4caba：修复 `MAX_TCACHE_SMALL_SIZE`](https://sourceware.org/git/?p=glibc.git;a=commit;h=ad4caba4146583fc543cd434221dec7113c03e09) | 上限改用物理 chunk size 并处理严格 `<`，最后一个 small tcache class 恢复。 |
| 2.43 | [614cfd0：重写 mmap chunk layout](https://sourceware.org/git/?p=glibc.git;a=commit;h=614cfd0f8a2820aed54f9745077c7da0e6643bac) | mmap chunk header 与普通 chunk 一致；启用 large tcache 时 mmap chunk 可入 tcache，Muney PoC 需分支。 |
| 2.43 | [b2b4b46：large tcache 精确尺寸](https://sourceware.org/git/?p=glibc.git;a=commit;h=b2b4b46a5235d83eea6d52b44e8c18be7c65f0d9) | 不再把同 logarithmic bin 中更大的 chunk 返回给较小请求；poison fake size 必须精确。 |
| 2.43 | [0b9210b：默认 tcache count=16](https://sourceware.org/git/?p=glibc.git;a=commit;h=0b9210bd760b5281f2e9f3e6640368ccb5f4a7ae) | fastbin 删除后每个 tcache size class 默认容量从 7 增至 16。 |

## 直接源码阅读点

-堆管理器：`malloc/malloc.c` 中 `__libc_malloc`、`_int_malloc`、`__libc_free`、`tcache_*`、`unlink_chunk`。
- House of Lemon：2.23 `malloc/malloc.c` 的 `global_max_fast`、`fastbin_index` 和 `_int_free`；再对照 2.24 `libioP.h` 的 `IO_validate_vtable`。
- size/bin 映射：根目录 [MALLOC_SIZE_BIN_MAP.md](./MALLOC_SIZE_BIN_MAP.md)，对应 `request2size`、`csize2tidx`、`large_csize2tidx`。
- top/sysmalloc：`malloc/malloc.c` 中 `sysmalloc` 建立 fencepost 并调用 `_int_free(av, old_top, 1)` 的分支。
- arena/House of Mind/Gods：`malloc/arena.c`、`heap_for_ptr`、`arena_for_chunk`。
- IO vtable/wide FSOP：`libio/libioP.h`、`libio/vtables.c`、`libio/wfileops.c`、`libio/wstrops.c`。
- House of Some/Illusion：`libio/genops.c` 的 `_IO_flush_all_lockp`、`libio/fileops.c` 的 `_IO_new_file_underflow/_IO_file_read/_IO_do_write`、`libio/wgenops.c` 的 `_IO_wdoallocbuf`；2.40+ 另读 `_IO_link_in/_IO_un_link` 的 `_prevchain` 维护。
- House of Apple1：2.23～2.36 `libio/vswprintf.c` 的 `_IO_wstrn_overflow` 和 `libio/strfile.h` 的 `_IO_wstrnfile`；2.37 起改读 `stdio-common/wprintf_buffer_flush.c`，旧最终触发点已不存在。
- wide-data ABI：`libio/libio.h` 的 `_IO_wide_data/_IO_iconv_t`；本范围三个 x86-64 `_wide_vtable` 偏移是 2.23～2.29 `0x130`、2.30 `0xf0`、2.31～2.43 `0xe0`。
- House of Error：`libio/memstream.c` 的 `_IO_mem_sync` 与 `_IO_FILE_memstream`，以及触发调用所对应的 jump-table 槽。
- 标准流任意读写/Pig：`libio/fileops.c` 的 `_IO_new_file_underflow/new_do_write`；Pig 另需对比 2.27/2.28 `libio/strops.c`，前者消费 `_IO_strfile` 回调，后者才直接 `malloc/free`。
- cookie/obstack：`libio/iofopncook.c`、2.36 以前的 `libio/obprintf.c`、2.37 以后的 `stdio-common/printf_buffer_flush.c`。
- House of Husk：`stdio-common/reg-printf.c` 与 `vfprintf-internal.c`。
- House of Banana：各版本 `elf/dl-fini.c`、2.43 的 `elf/dl-call_fini.c` 与私有 `link_map` 定义；`l_info[DT_FINI_ARRAYSZ]` 是必需项，不能只伪造 ARRAY 指针。

## 两个常见误判

1. **最终触发点还在，不等于旧完整链还在。** 例如 2.43 仍有 `_IO_str_overflow`、wide vtable、printf handler 表；但 2.42 已经切断公开 PoC 常用的经典 largebin 任意写。
2. **发行版版本号相同，不等于行为相同。** 安全包会 backport tcache key、完整性检查；FILE 隐藏 symbol、ld.so 私有结构、one_gadget 更是构建相关。

历史论文名称与本范围的对应关系见 [HISTORICAL_NAME_BOUNDARIES.md](./HISTORICAL_NAME_BOUNDARIES.md)：尤其不要把 glibc 2.3.5 的 House of Prime 直接标成 2.23 可用，也不要把原文仅作为结语的 House of Chaos 虚构成堆管理器 PoC。
