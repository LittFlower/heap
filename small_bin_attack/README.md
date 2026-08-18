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

## 先消除命名歧义

CTF 文章常把三件事都叫 “small bin attack”：

1. **direct smallbin unlink / House of Lore**：控制 victim->bk，并构造自洽 fake 双链，让 malloc 直接返回栈/全局区 fake chunk。该分支在 glibc 2.23～2.43 仍可构造。
2. **经典 smallbin arbitrary write**：试图只改一个 bk 获得无条件任意写；现代双向链检查下不能把它当成无约束原语。
3. **Tcache Stashing Unlink Attack（TSU/TSU+）**：smallbin 精确大小分配时，额外节点被 stash 到 tcache，产生 libc 指针写与目标分配。典型 PoC 适用于 2.26～2.40，2.41 重构后失效。

## 版本变化

| 版本 | direct smallbin / Lore | tcache stashing unlink |
|---|---|---|
| 2.23～2.25 | 可用；无 tcache | 不存在 |
| 2.26～2.31 | 可用；先填/耗尽 tcache | 可用 |
| 2.32～2.40 | 可用；smallbin 双链本身不做 safe-linking | 可用；目标与返回地址仍需满足对齐 |
| 2.41～2.42 | 可用 | 2.41 的 smallbin/stashing 重构使旧 PoC 失效 |
| 2.43 | 可用；但默认 tcache count=16，必须扩展填充与 fake stashing 链 | 旧 TSU PoC 失效 |

## 从源码看

direct 分支关注 `_int_malloc` 的 exact-fit smallbin 路径与 `unlink_chunk`：

- victim 的 fd/bk 必须形成一致双链；
- 2.26 起，同尺寸 free 默认先进入 tcache，必须先处理 tcache；
- safe-linking 只保护 tcache/fastbin 单链，不直接编码 smallbin fd/bk。

TSU 分支关注 2.40 以前 smallbin exact-fit 后的 tcache prefill 循环；[e2436d6](https://sourceware.org/git/?p=glibc.git;a=commit;h=e2436d6f5aa47ce8da80c2ba0f59dfb9ffde08f3) 在 2.41 重构了这条路径。

## PoC

- [`poc_direct_2.23_2.25.c`](./poc_direct_2.23_2.25.c)：无 tcache direct smallbin fake-chain。
- [`poc_direct_2.26_2.42.c`](./poc_direct_2.26_2.42.c)：带 7-slot tcache 排布的现代 direct smallbin。
- [`poc_direct_2.43.c`](./poc_direct_2.43.c)：16-slot tcache 专用排布。
- [`poc_tcache_stash_2.26_2.40.c`](./poc_tcache_stash_2.26_2.40.c)：TSU 版本，展示 `bck->fd` 写和目标 stash。

三个 direct 文件是 `house_of_lore/` 权威实现的薄入口，避免“汇总目录副本”
再次与主实现漂移。其成功判据是 `malloc == fake user address`，不是改 main 返回地址。

快速验证：

```bash
./tools/run_in_docker.sh 2.43 small_bin_attack/poc_direct_2.43.c
./tools/run_in_docker.sh 2.39 small_bin_attack/poc_tcache_stash_2.26_2.40.c
```

这些文件与 `house_of_lore/`、`tcache_stashing_unlink_attack/` 中的权威分类版本保持相同成功判据；本目录只解决术语检索与版本对照。
