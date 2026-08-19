# Tcache Stashing Unlink Attack Plus Plus（TSU++）

## 结论

- 适用范围：**glibc 2.26～2.40**；2.41 删除了它所依赖的 stashing 循环，TSU++ 那种“一次循环拿到两个输出”的路径就此彻底失效。用两条其他原语分别拿到相同输出并不算 TSU++ 仍然可用。
- 原语效果：一次 smallbin stashing 同时做到两件事——把任意地址的 chunk 塞进 tcache，同时向另一个任意地址写入一个 main_arena/smallbin 指针。
- 漏洞前置：能修改 smallbin victim 的 `bk`；目标区域对齐，并且能布置一个伪造的 `bk`。

TSU++ 可以看作是把 TSU+ 里“目标附近必须有可写指针”这个约束，反过来变成了第二个可以利用的目标：

```text
victim->bk      = fake_chunk - 0x10
fake_chunk->bk  = secret - 0x10

stash(fake_chunk)  => tcache 中得到 fake_chunk
bck->fd = bin      => *(secret) = smallbin/main_arena 地址
```

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | TSU+ 条件，再控制另一 fake `bk` |
| 关键环境与不变量 | 两个目标区可写、对齐、链关系自洽 |
| 最终输出原语 | 一次取得 AAF + 另一地址的 libc 指针写 |
| 版本边界应如何理解 | 与 TSU+ 同一 2.41 硬边界；两个输出可由其他原语组合获得，但不代表一次 stashing 双效果仍在。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## PoC

- [`poc_2.26_2.40.c`](./poc_2.26_2.40.c)：布置 7 个 tcache chunk 和 5 个 smallbin chunk，触发后同时断言 `malloc` 返回了栈上的伪 chunk，并且 `secret` 被写成了一个非零的 libc 地址。

```bash
./tools/run_in_docker.sh 2.27 tcache_stashing_unlink_attack_plus_plus/poc_2.26_2.40.c
./tools/run_in_docker.sh 2.40 tcache_stashing_unlink_attack_plus_plus/poc_2.26_2.40.c
```

## 版本变化与源码

- 2.26：引入 tcache 之后才有了“smallbin 取一个、剩余节点预填充进 tcache”这个组合，所以不存在 2.23 版本的 TSU++。
- 2.32：safe-linking 只编码 tcache/fastbin 那条单向链表的 `next`；smallbin 的 `fd/bk` 仍然是明文。目标需要 0x10 对齐，但经典的攻击结构依然成立。
- 2.41：提交 `e2436d6` 重构了小块的投递方式，旧的 stashing 循环消失了，TSU、TSU+、TSU++ 以及由它们拼出来的 Rust/Crust 都没法照搬了。

源码阅读入口：

- [glibc 2.40 `malloc.c`](https://github.com/bminor/glibc/blob/glibc-2.40/malloc/malloc.c)
- [glibc 2.41 smallbin 重构提交](https://sourceware.org/git/?p=glibc.git;a=commit;h=e2436d6f5aa47ce8da80c2ba0f59dfb9ffde08f3)
- [ALateFall 图解 glibc 堆利用（用户指定资料）](https://github.com/ALateFall/blogs/blob/main/system/tricks/%E5%9B%BE%E8%A7%A3glibc%E5%A0%86%E5%88%A9%E7%94%A8.md)

## 调试重点

1. 调用 `calloc` 之前先确认 tcache 里恰好还剩两个节点，smallbin 里有五个真实节点；这就是本 PoC 能一路遍历到 `chunks[11]` 的原因。
2. `fake_chunk` 是我们期望 malloc 最终返回的用户地址，写入 victim 的其实是 `fake_chunk-0x10`。
3. 第二个目标要按 `bck->fd` 的字段偏移往回推，所以写的是 `secret-0x10`；如果不小心直接写 `secret`，实际落点就会偏出去 0x10。
4. 如果 2.32 之后链表损坏了，要分别检查 smallbin 的明文双向链表和 tcache 的 safe-linked 单向链表，别把这两套编码规则混在一起改。
