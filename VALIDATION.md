# 验证记录

日期：2026-08-18  
架构：x86-64 / Docker（Colima）  
入口：`tools/check_all.sh`

## 运行时

- glibc 2.23：精确首发包 `2.23-0ubuntu3_amd64`
- glibc 2.26：精确首发包 `2.26-0ubuntu2_amd64`
- glibc 2.27：精确首发包 `2.27-3ubuntu1_amd64`
- glibc 2.28：精确首发包 `2.28-0ubuntu1_amd64`
- glibc 2.29：精确首发包 `2.29-0ubuntu2_amd64`
- glibc 2.30：精确首发包 `2.30-0ubuntu2_amd64`
- glibc 2.31～2.43：how2heap CI 对应的 Ubuntu 20.04～26.04 x86-64 镜像
- 构建器：`gcc:5`，`-O0 -g -fno-omit-frame-pointer`

精确包很重要：受安全更新的 Ubuntu 18.04 glibc 2.27 已可能回移 tcache key，会把上游首发版可用的 tcache dup 错判为失效。

## 结果

`validation_manifest.tsv` 共 198 个代表性条目，覆盖堆管理器/bin 核心分支及主要可执行 House：

- 清单覆盖全部 141 个 C PoC；同一文件会按关键版本边界选择多个运行点；
- House of Storm 不再依赖 20 次盲重试：PoC 比较堆指针高位 1/2/3 字节窗口，必要时以 16 MiB top padding 推进 flag 字节，精确 2.27 首轮以 `calloc == target` 严格通过；
- 两个 House of Muney 条目按上游性质标为 ASLR/映射相关，最终轮均成功；Roman 的低字节位置已用每次排布实际地址作教学 oracle，两个端点均为 strict。
- `small_bin_attack` 的 direct 2.23/2.39/2.43 与 tcache-stashing 2.39 汇总入口均纳入正式矩阵；2.43 direct 使用 16-slot tcache 专用链。
- 新增的标准流 IO_FILE 任意读写、freed/in-use chunk overlap 与 sysmalloc old-top free 均在范围两端（glibc 2.23/2.43）运行成功；旧 freed-unsorted overlap 只在其有效端点 2.23 纳入正向矩阵。
- Large tcache 的 2.42 `>=` 取块、2.43 精确尺寸，以及两版 poisoning 均通过；PoC 明确在启动前提高默认关闭的 `glibc.malloc.tcache_max`。
- House of Error 的 `_IO_mem_sync` 双写在 2.24/2.35/2.43 通过；House of Cat 的三种 wide-data ABI 在 2.24/2.29、2.30、2.31/2.43 通过。
- Poison Null Byte 在 2.23、2.27/2.28、2.29/2.30/2.31/2.42、2.43 四条版本分支全部通过，其中 2.28～2.30 使用精确首发 loader。
- House of Lemon 在精确 `2.23-0ubuntu3_amd64` 上完成超大尺寸 fastbin 越界写，并由 `fflush(stdout)` 跳入堆伪 vtable。
- TSU+ 与 TSU++ 均在 2.27/2.40 通过；相同 PoC 在 2.41 分别不再返回伪 chunk、也不再产生 libc 地址写，按预期断言失败。
- Tcache Relative Write 的四段 PoC 分别在 2.30、2.32、2.35、2.38 通过，原矩阵的 2.41 端点也通过；这同时覆盖补充资料中的 `mp_.tcache_bins` 攻击。
- House of Atum 的 entry/count 错位原语在精确 2.27/2.29 通过；同一 PoC 在精确 2.30 因 malloc 已改查 count 而按预期断言失败。
- House of IO 的两套 metadata 布局分别在精确 2.29、精确 2.30 和 2.33 通过；2.32+ 分支的伪 entry 同时满足 0x10 对齐与 safe-linking 编码 NULL 约束。
- House of Apple2 三套 `_IO_wide_data` ABI 在 2.24/2.29、2.30、2.31/2.43 全部经真实 `__woverflow→doallocate` 回调通过。
- House of Apple1 不再误用 `_IO_wstr_overflow` 解释：真实 `_IO_wstrn_overflow` 八字段已知值写在 2.23/2.24/2.36 通过；Obstack 旧后端在 2.23/2.36、Snake 新 printf_buffer 后端在 2.37/2.43 均以真实 `chunkfun(extra_arg,size)` 回调通过。
- House of Apple3 的三段 codecvt ABI 均经真实 `fgetwc→_IO_wfile_underflow` 验证：2.23/2.29 直接 `codecvt+0x18` 回调、精确 2.30 的 `step@codecvt+0x8`、2.31/2.43 的 `step@codecvt+0x0` 全部通过。
- House of Kiwi 的 top-size corruption 在 2.23/2.35 均进入 `__malloc_assert→fflush(stderr)` 回调；同一程序在 2.36 只打印 `__libc_message` fatal 并退出 134，确认触发器末版为 2.35。
- House of Lys 修正为 `FILE+0xe0 -> fake obstack` 和 `_IO_obstack_jumps+0x20` shifted vtable；显式提供第三参数的 xsputn→chunkfun 最终触发点在 2.23/2.36 通过。
- House of Pig 的旧 `_IO_strfile` allocate/free 回调在 2.23/2.27 均被真实消费；现代直接扩容最终触发点在 2.28/2.43 逐字节验证 malloc/memcpy/free/memset 效果。
- House of Banana 的真实主程序 link_map 动态项被修改后，2.23/精确 2.30/2.43 均经真实 `exit→_dl_fini→DT_FINI_ARRAY` 调用受控回调；回调用 `_exit(0)`，父进程严格排除普通 `exit(113)` 假阳性。
- Unsorted Bin Attack 的无前置 target 经典 PoC 在 2.23/精确 2.27 通过；`bdc3009` 进入精确 2.28 后同链报 `corrupted unsorted chunks 3`。另增 `target==victim` 受约束写，并在 2.28/2.43 两端通过。经典 Into Stack 同样以 2.27 正向、2.28 负向确认边界。
- House of Emma 在 2.23 验证明文 cookie 回调，在 2.24/2.31/2.43 从已知密文恢复 pointer_guard 后验证 mangled 回调；House of Husk handler 最终触发点在 2.23/2.43 通过。
- House of Lore 三个分支均改用 `malloc == fake user address` 严格判据，并在 2.23、2.41、2.42、2.43 通过。House of Roman 的 fastbin 路径在 2.23/2.24、tcache 重排路径在精确 2.26/2.27 均以 `__malloc_hook -> _exit(0)` 通过。
- 原语边界复核纠正了 House of Gods 的过强范围：本目录原版最小链只在 2.23/2.24 严格运行；2.25 沿用相同上游布局。stock 2.26 已有 tcache 且隐藏 `narenas` 相对位置随构建变化，归类为尚需独立迁移而非“思想失效”；2.27 `malloc_state.have_fastchunks` 使原链把 `main_arena+8` 当 size 的条件变成 0/1，才是原版单-UAF 链的结构硬边界。
- House of Illusion 的 shifted `_IO_file_jumps-8` 写链与 normal `_IO_file_jumps` 读链在 2.23/2.39/2.40/2.43 逐字节通过；2.40+ 明确设置 `FILE+0xb8` 的 `_prevchain`，覆盖双链切换点。
- House of Some 的 `wfile_overflow→wdoallocbuf→file_underflow→file_read` 任意写消费路径在 2.23/2.29、精确 2.30、2.31/2.43 通过，覆盖 `_wide_vtable` 的 `+0x130/+0xf0/+0xe0` 三段 ABI。
- fastbin `A→B→A` 在 tcache refill 中产生重复节点的变体在 2.27/2.42 通过；2.32+ 由 PoC 按实际 chunk 地址生成 safe-linking 编码，2.42 同时通过 refill size 检查。
- House of Rust 新增单文件汇总版，在 glibc 2.32 一次运行依次验证 TSU+、TSU、现代 largebin 写、stdout 泄漏与 `__free_hook` 终点；五段使用独立子进程，避免教学阶段故意留下的伪 bin 状态互相污染。
- House of Corrosion 的 fastbin 指针搬运改为纯 C 线性模型，在 2.27 和 2.32 分别验证明文 `fd` 与 safe-linking 编码；真实 2.27/2.29 链和 2.37 硬边界写在文件末尾的中文伪代码中。

额外负测试：

- House of Kauri 在 glibc 2.39、2.41 成功；
- 同一 PoC 在 glibc 2.42 按预期报 `free(): double free detected in tcache 2`，确认全 bin 扫描是准确失效边界。
- freed-unsorted size overlap 在 glibc 2.23 成功；同一 PoC 在 2.31 按预期报 `malloc(): mismatching next->prev_size (unsorted)`，确认 `b90ddd` 后的失效原因。
- TSU+/TSU++ 在 glibc 2.41 的负测试均退出 134；日志保存在 `build/validation/negative__2.41__tsu_*.log`，确认 `e2436d6` 是行为硬边界。
- House of Atum 在 glibc 2.30 的负测试退出 134，日志为 `build/validation/negative__2.30__house_of_atum.log`；这纠正了旧资料把变化写成 2.31 的 off-by-one。
- House of IO 的 2.30～2.33 PoC 在 2.34 读到随机 `tcache_key` 后退出 139，日志为 `build/validation/negative__2.34__house_of_io.log`，确认 UAF `key` 泄露 metadata 的窗口止于 2.33。
- 7-slot Lore PoC 在 2.43 退出 134，日志为 `build/validation/negative__2.43__house_of_lore_7slot.log`；确认默认 count=16 会让旧排布的 victim 仍从 tcache 返回，必须换专用链。
- Apple1 的 2.23～2.36 C PoC 在 2.37 不能产生任何目标字段写并于严格断言退出 134；结合 `118816de3383` 删除函数/jump table，确认 2.36/2.37 是硬边界。日志为 `build/validation/negative__2.37__house_of_apple1.log`。
- Kiwi 触发器在 glibc 2.36 退出 134，且 cookie stderr 回调未执行；fatal 文本来自 `__libc_message`，与 `ac8047c` 的源码变化一致。日志为 `build/validation/negative__2.36__house_of_kiwi.log`。
- Pig 旧回调 PoC 在精确 glibc 2.28 中两个回调计数仍为零并退出 134，确认 `4e8a6346` 是旧式最终触发点与现代直接 malloc/free 最终触发点的硬分界。
- 经典 Unsorted Bin Attack 与 Unsorted Bin Into Stack 的 2.23～2.27 PoC 在精确 glibc 2.28 均退出 134，fatal 文本为 `corrupted unsorted chunks 3`；确认 `bdc3009` 已在 2.28 加入首道 `bck->fd==victim` 检查，而不是等到 2.29。
- House of Roman 的同一 PoC 在精确 glibc 2.28 进入第 2 步后退出 134，fatal 同样为 `corrupted unsorted chunks 3`；日志为 `build/validation/roman_2.28_negative.log`。
- House of Storm 在精确 glibc 2.28 中已选出合法 fake size，但第二轮 fake-victim 摘链仍退出 134，fatal 为 `corrupted unsorted chunks 3`；证明不是 size-bit 概率失败。日志为 `build/validation/negative__2.28__house_of_storm.log`。
- Unsafe Unlink 的旧 size 布局在精确 2.29 退出 134，fatal 为 `corrupted size vs. prev_size while consolidating`；增加 fake size 的现代分支在同一 2.29 和 2.43 通过。
- House of Husk 的 largebin 双表投递链在 2.27/2.35/2.37/2.39/2.41 均真实进入版本标记回调。2.41 旧偏移会将堆地址写到错误的 libc 可写区并假退出 0；已用当前 `libc6-dbg` Build ID 更正三个隐藏符号偏移。
- 新增 fastbin→tcache refill PoC 在 glibc 2.43 退出 134，fatal 为 `double free detected in tcache 2`；free 不再落入 fastbin，确认该子型与其他 Fastbin Dup 一样止于 2.42。

静态审计：

- 141 个 C PoC 均包含逐步中文说明；
- 141 个 C PoC 全部通过 `gcc:5 -std=gnu99 -fsyntax-only`；
- 141 个 C PoC 全部至少在一个文件名范围内的 glibc 运行时进入 198 项动态矩阵，无未覆盖 C 文件；
- 手法目录中不再保留 Python PoC、布局生成器或阶段检查器；
- 每个手法目录都有 README，README 中枚举的 PoC 文件均存在。

Corrosion、Crust、Rust 是强题目菜单/Build ID 绑定的多原语组合。目录只保留可运行的 C 子原语、汇总演示和 C 文件末尾的迁移伪代码，不把局部阶段成功冒充端到端 RCE。此次源码复核另纠正：Corrosion 原文完整链是特定 2.27、Addendum 是特定 2.29；Crust 的超大尺寸 fastbin 指针搬运在 `global_max_fast` 于 2.37 缩为 `uint8_t` 时已经结束，而非延长到 2.40/2.42。

## 复现

```bash
cd heap_ultimate_cheatsheet
./tools/prepare_exact_libcs.sh /path/to/glibc-all-in-one
./tools/check_all.sh
./tools/audit_static.sh
```

日志位于 `build/validation/`（构建目录被 `.gitignore` 忽略）。
