# Tcache Stashing Unlink Attack Plus（TSU+）

## 结论

- 适用范围：**glibc 2.26～2.40**。
- 原语效果：控制 smallbin victim 的 `bk` 后，把任意 0x10 对齐地址 stash 到 tcache，再由 `malloc` 返回。
- 2.41 起失效：提交 `e2436d6` 重构 smallbin/unsorted 小块投递，经典 stashing 循环不再存在。

名称中的 “Plus” 不是“标准 TSU 在新版本的写法”。标准 TSU 主要利用 `bck->fd = bin` 取得 libc 地址写；TSU+ 额外安排 tcache 容量和两个 smallbin 节点，使循环沿伪 `bk` 继续走，把 `target-0x10` 当作 chunk header 放进 tcache。

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

1. tcache 已存在，故最低版本是 2.26，不是某些旧笔记所写的 2.23。
2. 同一 size class 中 `tcache + smallbin` 的排布能让 smallbin 分配后仍继续预填充。
3. 至少两个真实 smallbin chunk，并能 UAF/overflow 修改被遍历 victim 的 `bk = target-0x10`。
4. `target` 0x10 对齐；`target+8` 作为伪 chunk 的 `bk`，它指向的位置必须可写。
5. 经典 PoC 用 `calloc` 绕开 malloc 的 tcache 快路径，直接进入 smallbin 分支。

## PoC

- [`poc_2.26_2.40.c`](./poc_2.26_2.40.c)：真实构造 7 个 tcache chunk、2 个 smallbin chunk，修改 `bk` 后断言 `malloc(0x100) == target`。

```bash
./tools/run_in_docker.sh 2.27 tcache_stashing_unlink_attack_plus/poc_2.26_2.40.c
./tools/run_in_docker.sh 2.40 tcache_stashing_unlink_attack_plus/poc_2.26_2.40.c
```

## 从源码看

关键不是 safe-linking，而是 2.40 `_int_malloc` 的 smallbin 精确尺寸分支：返回一个 victim 后，循环把剩余 smallbin 节点放入 tcache，并执行双链的 `bck->fd = bin` 更新。smallbin 的 `fd/bk` 不经过 `PROTECT_PTR`；进入 tcache 时写入的 `next` 才使用 safe-linking，所以 2.32+ 主要多出对齐约束，不会单独杀死该 PoC。

2.41 把小块释放/预填充路径改为 `tcache_put` 后的不同流程，原有无检查 stashing 步骤消失，因此 Rust/Crust 中依赖的 TSU+ 也同时截止。

## 迁移提示

- 先在 `_int_malloc` 断点确认 `tcache` 剩余容量；数量差一会导致伪节点没有被 stash，或被 `calloc` 当场返回。
- `target` 指用户地址，因此 smallbin `bk` 写 `target-0x10`。
- 若 2.32+ 最后报 `unaligned tcache chunk detected`，先查目标对齐，再查 tcache 内的 safe-linking `next`，不要误改 smallbin 的明文 `bk`。

## 资料

- [glibc 2.40 `malloc.c`](https://github.com/bminor/glibc/blob/glibc-2.40/malloc/malloc.c)
- [glibc 2.41 smallbin 重构提交](https://sourceware.org/git/?p=glibc.git;a=commit;h=e2436d6f5aa47ce8da80c2ba0f59dfb9ffde08f3)
- [ALateFall 图解 glibc 堆利用（用户指定资料）](https://github.com/ALateFall/blogs/blob/main/system/tricks/%E5%9B%BE%E8%A7%A3glibc%E5%A0%86%E5%88%A9%E7%94%A8.md)
- [House of Rust 原始说明](https://github.com/c4ebt/House-of-Rust)
