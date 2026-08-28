# Small Bin Attack

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | direct/Lore：UAF 改 `bk` 并布置完整 fake 双链；TSU：可控 `bk` |
| 关键环境与不变量 | direct 要双链自洽；2.43 tcache count=16；TSU 依赖旧 stashing loop |
| 最终输出原语 | direct AAF；TSU 还可写 libc 指针 |
| 版本边界应如何理解 | direct/Lore 到 2.43 仅需排布适配。只改一个 `bk` 的“无条件任意写”早已是强约束。TSU 消费路径在 2.41 被重构掉，不能把 direct 的存活当作 TSU 存活。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

<!-- CHUNK_SIZE_REQUIREMENTS:START -->
## Chunk size 要求

- direct/Lore 与 TSU 都要求物理 `chunksize < MIN_LARGE_SIZE (0x400)` 的 **smallbin class**；为使普通 free 直接可合并/入 bin，通常选 `chunksize > get_max_fast()`，并处理同尺寸 tcache。
- direct/Lore 的真实节点、fake header 和最终请求必须精确同 class，PoC 用 `malloc(0x100) -> 0x110`。TSU 的真实节点与触发/取回请求同 class（PoC 为 `malloc(0x90) -> 0xa0`），但旧 stashing 循环不会另查被塞入 tcache 的 fake 节点 `size`；它要求的是 `bk` 布局可写和返回地址对齐。
<!-- CHUNK_SIZE_REQUIREMENTS:END -->

## 先厘清命名上的混用

CTF 文章里经常把三件不同的事都叫作 “small bin attack”：

1. **direct smallbin unlink / House of Lore**：控制 victim->bk，构造自洽的 fake 双链，让 malloc 直接返回位于栈或全局区的 fake chunk。这条路径在 glibc 2.23～2.43 之间一直可构造。
2. **经典 smallbin arbitrary write**：很多资料把它描述成"只改一个 bk 字段就能换来无条件任意写"，但在现代双链检查下，它早已不是无条件的写入原语。
3. **Tcache Stashing Unlink Attack（TSU/TSU+）**：smallbin 精确大小分配时，多出的节点被 stash 进 tcache，产生一次 libc 指针写和一次目标分配。典型 PoC 只适用于 2.26～2.40，2.41 的重构让它失效。

## 版本变化

| 版本 | direct smallbin / Lore | tcache stashing unlink |
|---|---|---|
| 2.23～2.25 | 可用；无 tcache | 不存在 |
| 2.26～2.31 | 可用；先填/耗尽 tcache | 可用 |
| 2.32～2.40 | 可用；smallbin 双链本身不做 safe-linking | 可用；目标与返回地址还要满足对齐 |
| 2.41～2.42 | 可用 | 2.41 的 smallbin/stashing 重构让旧 PoC 失效 |
| 2.43 | 可用；但默认 tcache count=16，必须扩展填充与 fake stashing 链 | 旧 TSU PoC 失效 |

## 从源码看

direct 分支要盯住的是 `_int_malloc` 里 exact-fit smallbin 的路径，以及 `unlink_chunk`：

- victim 的 fd/bk 必须构成自洽双链；
- 2.26 起同尺寸 free 默认先进 tcache，要先处理掉 tcache 才轮到 smallbin；
- safe-linking 只保护 tcache/fastbin 单链，不对 smallbin 的 fd/bk 编码。

TSU 分支看的是 2.40 之前 smallbin exact-fit 分配后的 tcache 预填充循环；[e2436d6](https://sourceware.org/git/?p=glibc.git;a=commit;h=e2436d6f5aa47ce8da80c2ba0f59dfb9ffde08f3) 在 2.41 重构了这条路径，让旧 PoC 失效。

## PoC

- [`poc_direct_2.23_2.25.c`](./poc_direct_2.23_2.25.c)：没有 tcache 时的 direct smallbin fake-chain。
- [`poc_direct_2.26_2.42.c`](./poc_direct_2.26_2.42.c)：带 7 槽 tcache 排布的现代 direct smallbin 版本。
- [`poc_direct_2.43.c`](./poc_direct_2.43.c)：针对 16 槽 tcache 的专用排布。
- [`poc_tcache_stash_2.26_2.40.c`](./poc_tcache_stash_2.26_2.40.c)：TSU 版本，展示 `bck->fd` 写入和目标 stash 的过程。

这三个 direct 文件只是 `house_of_lore/` 权威实现的薄封装入口，避免汇总目录里的副本再与主实现产生偏差。成功判据是 `malloc` 返回事先伪造的 fake user address，而不是改写 main 的返回地址。

快速验证：

```bash
./tools/run_in_docker.sh 2.43 small_bin_attack/poc_direct_2.43.c
./tools/run_in_docker.sh 2.39 small_bin_attack/poc_tcache_stash_2.26_2.40.c
```

成功判据与 `house_of_lore/`、`tcache_stashing_unlink_attack/` 中的权威版本一致；本目录只解决术语检索和版本对照。
