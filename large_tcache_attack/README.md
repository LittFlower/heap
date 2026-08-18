# Large Tcache Attack

## 结论

- 适用范围：**glibc 2.42～2.43**；这是 2.42 新增的 12 个 logarithmic large tcache bins。
- **默认不开启 large tcache**：上游默认 `tcache_max` 仍停在 small tcache 上限。比赛环境必须已经设置，或在进程启动前设置 `GLIBC_TUNABLES=glibc.malloc.tcache_max=...`。
- 原语效果：与 small tcache poisoning 相同，覆盖空闲 large-tcache chunk 的 `next` 后，可让同尺寸 `malloc` 返回 0x10 对齐目标；但目标前的 fake `size` 必须能通过 large-bin 查找。
- 前置能力：large tcache 已启用、UAF/重叠写和 heap page 泄露（safe-linking）。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | large-tcache UAF/overlap 改 `next`，heap page leak |
| 关键环境与不变量 | 2.42+；启动前提高默认关闭的 `tcache_max`；fake size 合法 |
| 最终输出原语 | 大尺寸 AAF |
| 版本边界应如何理解 | 2.42 才引入该消费路径；2.43 从同 log-bin `>=` 改精确 size，是**适配**而非失效。默认关闭属于环境条件。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 版本变化

| 版本 | 查找语义 | 默认状态与容量 |
|---|---|---|
| 2.41 及以前 | 没有 large tcache | small tcache 64 bins，每 bin 默认 7 个 |
| 2.42 | 同一个 logarithmic bin 内返回第一个 `chunksize >= nb` 的 chunk；因此可能把更大的 chunk 整块返回给较小请求 | large bins 需提高 `tcache_max` 才启用；每 bin 默认 7 个 |
| 2.43 | 提交 `b2b4b46` 增加 `nb == chunksize(candidate)`，只消费精确物理尺寸 | large bins 仍需 tunable；删除 fastbin 后默认每 bin 16 个 |

2.42 的链按物理 `chunksize` 递增排序。`tcache->entries[idx]` 是**未编码的头指针**；只有 chunk 内的 `entry->next`，以及指向链中间 `next` 字段的链路槽，使用 `PROTECT_PTR/REVEAL_PTR`。因此普通 head poisoning 仍是改 `head_chunk->next`，写入 `target ^ ((uintptr_t)&head_chunk->next >> 12)`。

## 从源码看

重点函数是 `large_csize2tidx`、`tcache_location_large`、`tcache_put_large` 和 `tcache_get_large`：

- [2.42 large tcache 引入](https://sourceware.org/git/?p=glibc.git;a=commit;h=cbfd7988107b27b9ff1d0b57fa2c8f13a932e508)
- [2.43 精确尺寸匹配修复](https://sourceware.org/git/?p=glibc.git;a=commit;h=b2b4b46a5235d83eea6d52b44e8c18be7c65f0d9)
- [2.43 修复最后一个 small tcache bin 的上限](https://sourceware.org/git/?p=glibc.git;a=commit;h=ad4caba4146583fc543cd434221dec7113c03e09)
- [2.43 默认 tcache count 改为 16](https://sourceware.org/git/?p=glibc.git;a=commit;h=0b9210bd760b5281f2e9f3e6640368ccb5f4a7ae)

`tcache_max` 的比较对象是 `request2size` 后的物理 chunk size，而且源码使用严格小于号。不要把 tunable 的用户请求值、chunk header 中的 size 和 `malloc_usable_size` 混为一个数。常用换算见根目录的 [MALLOC_SIZE_BIN_MAP.md](../MALLOC_SIZE_BIN_MAP.md)。

## PoC

- [`poc_poisoning_2.42_2.43.c`](./poc_poisoning_2.42_2.43.c)：同尺寸 large tcache poisoning；在 2.42、2.43 都可运行。
- [`poc_best_fit_2.42.c`](./poc_best_fit_2.42.c)：证明 2.42 会把同一 logarithmic bin 中更大的 chunk 返回给较小请求。
- [`poc_exact_match_2.43.c`](./poc_exact_match_2.43.c)：同一排布在 2.43 不再命中，随后精确请求才能取回原 chunk。

三个程序第一次启动时都会写入 `GLIBC_TUNABLES` 并 `exec` 自身，因为 glibc 只在进程启动阶段读取 tunable。这不是题目漏洞；只是让 PoC 明确进入默认关闭的堆管理器分支。

```bash
./tools/run_in_docker.sh 2.42 large_tcache_attack/poc_best_fit_2.42.c
./tools/run_in_docker.sh 2.43 large_tcache_attack/poc_exact_match_2.43.c
./tools/run_in_docker.sh 2.43 large_tcache_attack/poc_poisoning_2.42_2.43.c
```

## 迁移到题目

1. 先检查进程启动环境或附件启动脚本；若没有提高 `glibc.malloc.tcache_max`，large chunk 根本不会进入 tcache。
2. 用 `request2size` 算物理尺寸，再用 `large_csize2tidx` 判断是否落入同一个 logarithmic bin。
3. 2.43 的 fake target 前必须放**精确**物理尺寸；不能沿用 2.42 的“更大也行”。
4. safe-linking 编码位置是被覆盖的 `entry->next` 字段地址，不是 tcache metadata 中的 `entries[idx]` 地址。
