# Tcache Stashing Unlink Attack Plus Plus（TSU++）

## 结论

- 适用范围：**glibc 2.26～2.40**；2.41 删除所依赖的 stashing loop，TSU++ 的“一次循环双输出”消费路径硬失效。用两条其他原语分别取得相同输出不算 TSU++ 仍可用。
- 原语效果：一次 smallbin stashing 同时完成“任意地址 chunk 进入 tcache”和“向另一任意地址写一个 main_arena/smallbin 指针”。
- 漏洞前置：能修改 smallbin victim 的 `bk`；目标区对齐并能布置一个伪 `bk`。

TSU++ 可以看作把 TSU+ 的“目标附近必须有可写指针”变成第二个利用目标：

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

- [`poc_2.26_2.40.c`](./poc_2.26_2.40.c)：布置 7 个 tcache chunk 与 5 个 smallbin chunk；触发后同时断言 `malloc` 返回栈上伪 chunk、`secret` 被写为非零 libc 地址。

```bash
./tools/run_in_docker.sh 2.27 tcache_stashing_unlink_attack_plus_plus/poc_2.26_2.40.c
./tools/run_in_docker.sh 2.40 tcache_stashing_unlink_attack_plus_plus/poc_2.26_2.40.c
```

## 版本变化与源码

- 2.26 引入 tcache，才有“smallbin 取一个、剩余节点预填充 tcache”的组合；所以不存在 2.23 版 TSU++。
- 2.32 safe-linking 只编码 tcache/fastbin 单链 `next`；smallbin 的 `fd/bk` 仍为明文。目标需要 0x10 对齐，但经典攻击结构仍成立。
- 2.41 提交 `e2436d6` 重构小块投递，旧 stashing 循环消失，TSU、TSU+、TSU++ 以及由它们拼成的 Rust/Crust 都不能照搬。

源码阅读入口：

- [glibc 2.40 `malloc.c`](https://github.com/bminor/glibc/blob/glibc-2.40/malloc/malloc.c)
- [glibc 2.41 smallbin 重构提交](https://sourceware.org/git/?p=glibc.git;a=commit;h=e2436d6f5aa47ce8da80c2ba0f59dfb9ffde08f3)
- [ALateFall 图解 glibc 堆利用（用户指定资料）](https://github.com/ALateFall/blogs/blob/main/system/tricks/%E5%9B%BE%E8%A7%A3glibc%E5%A0%86%E5%88%A9%E7%94%A8.md)

## 调试重点

1. `calloc` 前确认 tcache 中恰好剩两个节点、smallbin 有五个真实节点；这是本 PoC 能遍历到 `chunks[11]` 的原因。
2. `fake_chunk` 是期望返回的用户地址，写入 victim 的是 `fake_chunk-0x10`。
3. 第二个目标按 `bck->fd` 的字段偏移逆推，因此写 `secret-0x10`；如果误写 `secret`，实际落点会偏 0x10。
4. 2.32+ 若最终链损坏，分别检查 smallbin 明文双链与 tcache safe-linked 单链，不要混为一个编码规则。
