# Tcache Stashing Unlink Attack Plus（TSU+）

## 结论

- 适用范围：**glibc 2.26～2.40**。
- 原语效果：控制住 smallbin victim 的 `bk` 之后，就能把任意一个 0x10 对齐的地址 stash 进 tcache，再由 `malloc` 返回给我们。
- 2.41 起失效：提交 `e2436d6` 重构了 smallbin/unsorted 小块的投递方式，经典的 stashing 循环已经不存在了。

名称里的“Plus”指的不是“标准 TSU 在新版本上的写法”。标准 TSU 主要靠 `bck->fd = bin` 拿到一次 libc 地址写；TSU+ 则额外安排好 tcache 容量和两个 smallbin 节点，让循环沿着伪造的 `bk` 继续往下走，把 `target-0x10` 当成 chunk header 放进 tcache 里。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 控制 smallbin victim `bk`，布置 fake `bk` |
| 关键环境与不变量 | 同上，且 fake chunk/反向链满足具体返回路径 |
| 最终输出原语 | 任意对齐地址进 tcache 并返回 |
| 版本边界应如何理解 | 2.26～2.40 为排布窗口；2.41 核心 stashing 消费路径消失。加任意写去重建 tcache 头会退化成 metadata poisoning。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 前置条件

1. tcache 已经存在，所以最低版本是 2.26，不是某些旧笔记里写的 2.23。
2. 同一个 size class 里 `tcache + smallbin` 的排布要能让 smallbin 分配之后还继续做预填充。
3. 至少有两个真实的 smallbin chunk，并且能通过 UAF/overflow 修改被遍历的 victim，把它的 `bk` 改成 `target-0x10`。
4. `target` 要 0x10 对齐；`target+8` 会被当成伪 chunk 的 `bk`，它指向的位置必须可写。
5. 经典 PoC 用 `calloc` 绕开 malloc 的 tcache 快路径，直接走 smallbin 分支。

## PoC

- [`poc_2.26_2.40.c`](./poc_2.26_2.40.c)：真实构造出 7 个 tcache chunk 和 2 个 smallbin chunk，修改 `bk` 之后断言 `malloc(0x100) == target`。

```bash
./tools/run_in_docker.sh 2.27 tcache_stashing_unlink_attack_plus/poc_2.26_2.40.c
./tools/run_in_docker.sh 2.40 tcache_stashing_unlink_attack_plus/poc_2.26_2.40.c
```

## 从源码看

关键不在 safe-linking，而在 2.40 `_int_malloc` 的 smallbin 精确尺寸分支：返回一个 victim 之后，循环会把剩下的 smallbin 节点放进 tcache，过程中会执行双向链表的 `bck->fd = bin` 更新。smallbin 的 `fd/bk` 不经过 `PROTECT_PTR` 加密；只有写入 tcache 的 `next` 才使用 safe-linking，所以 2.32 起主要是多了对齐约束，并不会单独让这个 PoC 失效。

2.41 把小块释放/预填充的路径改成了走 `tcache_put` 之后的另一套流程，原来那段没有检查的 stashing 步骤也就消失了，因此 Rust/Crust 系列手法里依赖 TSU+ 的部分也随之截止。

## 迁移提示

- 先在 `_int_malloc` 打断点确认 `tcache` 剩余的容量；数量差一都会导致伪节点没被 stash 进去，或者被 `calloc` 当场返回掉。
- `target` 指的是用户地址，所以写进 smallbin `bk` 的值是 `target-0x10`。
- 如果 2.32 之后最终报了 `unaligned tcache chunk detected`，先查目标地址是否对齐，再查 tcache 内 safe-linking 的 `next`，别把这两套编码规则和 smallbin 的明文 `bk` 混在一起改。

## 资料

- [glibc 2.40 `malloc.c`](https://github.com/bminor/glibc/blob/glibc-2.40/malloc/malloc.c)
- [glibc 2.41 smallbin 重构提交](https://sourceware.org/git/?p=glibc.git;a=commit;h=e2436d6f5aa47ce8da80c2ba0f59dfb9ffde08f3)
- [ALateFall 图解 glibc 堆利用（用户指定资料）](https://github.com/ALateFall/blogs/blob/main/system/tricks/%E5%9B%BE%E8%A7%A3glibc%E5%A0%86%E5%88%A9%E7%94%A8.md)
- [House of Rust 原始说明](https://github.com/c4ebt/House-of-Rust)
