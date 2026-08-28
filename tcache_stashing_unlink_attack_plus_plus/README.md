# Tcache Stashing Unlink Attack Plus Plus（TSU++）

## 结论

- 适用范围：**glibc 2.26～2.40**；2.41 删除了它依赖的 stashing 循环，“一次循环拿到两个输出”的路径彻底失效。用两条其他原语分别拿到相同输出，不代表 TSU++ 还能用。
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

<!-- CHUNK_SIZE_REQUIREMENTS:START -->
## Chunk size 要求

- 两个输出都来自同一次 smallbin stashing，所以真实节点、触发和消费请求必须是同一个物理 `chunksize < 0x400` 的 smallbin class，且对应 tcache 有空槽；PoC 使用 `malloc(0x100) -> chunksize 0x110`。
- 旧循环不校验被引入 fake 节点的 `size`；两个目标区域真正需要满足的是 0x10 对齐、`bk/fd` 槽可写和反向链关系。换真实 class 时仍要同步 tcache 容量与所有请求。
<!-- CHUNK_SIZE_REQUIREMENTS:END -->

## PoC

- [`poc_2.26_2.40.c`](./poc_2.26_2.40.c)：布置 7 个 tcache chunk 和 5 个 smallbin chunk，触发后断言 `malloc` 返回栈上的伪 chunk，且 `secret` 被写入非零 libc 地址。

```bash
./tools/run_in_docker.sh 2.27 tcache_stashing_unlink_attack_plus_plus/poc_2.26_2.40.c
./tools/run_in_docker.sh 2.40 tcache_stashing_unlink_attack_plus_plus/poc_2.26_2.40.c
```

## 版本变化与源码

- 2.26：引入 tcache 后才有“smallbin 取一个、剩余节点预填充进 tcache”这个组合，所以不存在 2.23 版本的 TSU++。
- 2.32：safe-linking 只编码 tcache/fastbin 单链的 `next`，smallbin 的 `fd/bk` 还是明文。目标得 0x10 对齐，但经典攻击结构照样成立。
- 2.41：提交 `e2436d6` 重构了小块投递方式，旧的 stashing 循环消失，TSU、TSU+、TSU++ 及由它们拼出的 Rust/Crust 都无法照搬。

源码阅读入口：

- [glibc 2.40 `malloc.c`](https://github.com/bminor/glibc/blob/glibc-2.40/malloc/malloc.c)
- [glibc 2.41 smallbin 重构提交](https://sourceware.org/git/?p=glibc.git;a=commit;h=e2436d6f5aa47ce8da80c2ba0f59dfb9ffde08f3)
- [ALateFall 图解 glibc 堆利用（用户指定资料）](https://github.com/ALateFall/blogs/blob/main/system/tricks/%E5%9B%BE%E8%A7%A3glibc%E5%A0%86%E5%88%A9%E7%94%A8.md)

## 调试重点

1. 调用 `calloc` 前先确认 tcache 恰好剩两个节点、smallbin 有五个真实节点；这是本 PoC 能遍历到 `chunks[11]` 的原因。
2. `fake_chunk` 是期望 malloc 返回的用户地址，写入 victim 的是 `fake_chunk-0x10`。
3. 第二个目标按 `bck->fd` 的字段偏移回推，写 `secret-0x10`；直接写 `secret` 落点会偏 0x10。
4. 2.32 后若链表损坏，分别检查 smallbin 明文双链和 tcache safe-linked 单链，别把两套编码混改。
