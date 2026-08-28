# Tcache Stashing Unlink Attack Plus（TSU+）

## 结论

- 适用范围：**glibc 2.26～2.40**。
- 原语效果：控制住 smallbin victim 的 `bk` 之后，就能把任意一个 0x10 对齐的地址 stash 进 tcache，再由 `malloc` 返回给我们。
- 2.41 起失效：提交 `e2436d6` 重构了 smallbin/unsorted 小块的投递方式，经典的 stashing 循环已经不存在了。

名称里的“Plus”不是指“标准 TSU 在新版本上的写法”。标准 TSU 主要靠 `bck->fd = bin` 拿到一次 libc 地址写；TSU+ 额外安排好 tcache 容量和两个 smallbin 节点，让循环沿伪造的 `bk` 继续走，把 `target-0x10` 当作 chunk header 放进 tcache。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 控制 smallbin victim `bk`，布置 fake `bk` |
| 关键环境与不变量 | 同上，且 fake chunk/反向链满足具体返回路径 |
| 最终输出原语 | 任意对齐地址进 tcache 并返回 |
| 版本边界应如何理解 | 2.26～2.40 为排布窗口；2.41 核心 stashing 消费路径消失。加任意写去重建 tcache 头会退化成 metadata poisoning。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

<!-- CHUNK_SIZE_REQUIREMENTS:START -->
## Chunk size 要求

- 真实 victim、stash 触发和最终取回必须属于同一个物理 `chunksize < 0x400` 的 smallbin class，并让对应 tcache 留出槽位；PoC 使用 `malloc(0x100) -> chunksize 0x110`。
- 旧循环不会校验 `target-0x10` 处的 fake `size`，所以目标附近不必真的声明 `0x110`；但 `target` 必须 0x10 对齐，fake `bk` 槽（`target+8`）必须指向可写区。更换真实 class 时仍要同步 tcache 容量与全部请求。
<!-- CHUNK_SIZE_REQUIREMENTS:END -->

## 前置条件

1. tcache 已存在，所以最低版本是 2.26，不是某些旧笔记写的 2.23。
2. 同一 size class 里 `tcache + smallbin` 的排布要能让 smallbin 分配后继续预填充。
3. 至少两个真实 smallbin chunk，并能通过 UAF/overflow 把被遍历 victim 的 `bk` 改成 `target-0x10`。
4. `target` 要 0x10 对齐；`target+8` 会被当作伪 chunk 的 `bk`，指向的位置必须可写。
5. 经典 PoC 用 `calloc` 绕开 malloc 的 tcache 快路径，直接走 smallbin 分支。

## PoC

- [`poc_2.26_2.40.c`](./poc_2.26_2.40.c)：真实构造出 7 个 tcache chunk 和 2 个 smallbin chunk，修改 `bk` 之后断言 `malloc(0x100) == target`。

```bash
./tools/run_in_docker.sh 2.27 tcache_stashing_unlink_attack_plus/poc_2.26_2.40.c
./tools/run_in_docker.sh 2.40 tcache_stashing_unlink_attack_plus/poc_2.26_2.40.c
```

## 从源码看

关键不在 safe-linking，而在 2.40 `_int_malloc` 的 smallbin 精确尺寸分支：返回一个 victim 后，循环把剩下的 smallbin 节点放进 tcache，过程中执行双向链表的 `bck->fd = bin` 更新。smallbin 的 `fd/bk` 不经过 `PROTECT_PTR` 加密，只有写入 tcache 的 `next` 才用 safe-linking。所以 2.32 起只是多了对齐约束，并不会单独让本 PoC 失效。

2.41 把小块释放/预填充改成 `tcache_put` 之后的另一套流程，原来那段无检查的 stashing 步骤随之消失，Rust/Crust 系列手法中依赖 TSU+ 的部分也就此截止。

## 迁移提示

- 先在 `_int_malloc` 打断点确认 tcache 剩余容量；数量差一都会导致伪节点没被 stash，或被 `calloc` 当场返回。
- `target` 是用户地址，写进 smallbin `bk` 的值是 `target-0x10`。
- 2.32 后若报 `unaligned tcache chunk detected`，先查目标地址对齐，再查 tcache 内 safe-linking 的 `next`；别把 tcache 编码和 smallbin 明文 `bk` 混改。

## 资料

- [glibc 2.40 `malloc.c`](https://github.com/bminor/glibc/blob/glibc-2.40/malloc/malloc.c)
- [glibc 2.41 smallbin 重构提交](https://sourceware.org/git/?p=glibc.git;a=commit;h=e2436d6f5aa47ce8da80c2ba0f59dfb9ffde08f3)
- [ALateFall 图解 glibc 堆利用（用户指定资料）](https://github.com/ALateFall/blogs/blob/main/system/tricks/%E5%9B%BE%E8%A7%A3glibc%E5%A0%86%E5%88%A9%E7%94%A8.md)
- [House of Rust 原始说明](https://github.com/c4ebt/House-of-Rust)
