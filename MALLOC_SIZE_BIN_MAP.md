# x86-64 malloc size 与 bin 速查

本页只讨论本项目基线：x86-64、`SIZE_SZ=8`、`MALLOC_ALIGNMENT=0x10`、`MINSIZE=0x20`。比赛附件要是改了 ABI、开了 memory tagging 或带发行版补丁，就回到它的源码重算。

## 用户请求到物理 chunk size

```c
request2size(req) = max(0x20, (req + 8 + 0xf) & ~0xf)
```

常见映射：

| `malloc(req)` | header 中 `chunksize` | small tcache idx |
|---:|---:|---:|
| `0x18` | `0x20` | 0 |
| `0x20` | `0x30` | 1 |
| `0x80` | `0x90` | 7 |
| `0x100` | `0x110` | 15 |
| `0x400` | `0x410` | 63 |

公式里只加 `SIZE_SZ=8`，因为分配给用户的可用区会复用下一 chunk 的 `prev_size` 那 8 字节；不要机械地把 0x10 header 全加到 request 上。

## bin 索引

| 结构 | x86-64 公式/边界 | 版本注意 |
|---|---|---|
| fastbin | `fastbin_index(sz) = (sz >> 4) - 2` | 2.23～2.42；2.43 删除 fastbin 消费/基础设施 |
| smallbin | `smallbin_index(sz) = sz >> 4`，`sz < 0x400` | 双链；tcache 存在时先处理 tcache |
| small tcache | `csize2tidx(sz) = (sz - 0x20) / 0x10` | 2.26～2.43，共 64 bins |
| large tcache | `64 + clz(MAX_TCACHE_SMALL_SIZE) - clz(sz)` | 2.42～2.43，另有 12 bins，最大约 4 MiB |

这里的 `sz` 都是去掉标志位后的物理 `chunksize`，不是用户传给 `malloc` 的 `req`。

## tcache 容量与上限时间线

| 版本 | 默认每 bin 数量 | 默认最大范围 | 备注 |
|---|---:|---|---|
| 2.26～2.41 | 7 | small tcache 最后一个 size class | 64 个 small bins |
| 2.42 | 7 | 代码引入 12 个 large bins，但默认 `tcache_max` 没有开启它们 | `MAX_TCACHE_SMALL_SIZE` 错用了 usable size，且比较为 `<`，最后一个 small class 默认也落不到 tcache |
| 2.43 | 16 | 默认仍只到 small tcache；最后一个 class 已修复 | large bins 仍需提高 `glibc.malloc.tcache_max` |

启用 2.42+ large tcache 的示例：

```bash
GLIBC_TUNABLES=glibc.malloc.tcache_max=0x10000 ./chall
```

glibc 在进程启动时读取 tunable。数值先经 `request2size`，源码再与物理 `nb` 比较；2.42 使用 `< mp_.tcache_max_bytes`，2.43 将内部上限保存为 `nb + 1`，不要用“恰好等于”的直觉猜边界。

## safe-linking 编码位置

```c
encoded_next = ((uintptr_t)&entry->next >> 12) ^ (uintptr_t)target;
```

- 2.32+ small/large tcache chunk 内的 `entry->next` 和 fastbin `fd` 使用 safe-linking（fastbin 到 2.42）。
- `tcache->entries[idx]` 的**头指针本身是明文**；从 large-tcache 链中间插入/删除时，指向中间节点的槽位位于前一节点的 `next` 字段，那个槽位才按它自己的地址编码。
- 目标地址需满足 0x10 对齐；若堆管理器会继续读取 fake target 的 `next`，还要在目标处准备 `target >> 12` 作为编码后的 NULL。

## 源码入口

- [glibc 2.42 `malloc/malloc.c`](https://github.com/bminor/glibc/blob/glibc-2.42/malloc/malloc.c)
- [glibc 当前 `malloc/malloc.c`](https://github.com/bminor/glibc/blob/master/malloc/malloc.c)
- [2.42 large tcache 提交](https://sourceware.org/git/?p=glibc.git;a=commit;h=cbfd7988107b27b9ff1d0b57fa2c8f13a932e508)
- [2.43 `MAX_TCACHE_SMALL_SIZE` 修复](https://sourceware.org/git/?p=glibc.git;a=commit;h=ad4caba4146583fc543cd434221dec7113c03e09)
- [2.43 默认 count 16](https://sourceware.org/git/?p=glibc.git;a=commit;h=0b9210bd760b5281f2e9f3e6640368ccb5f4a7ae)

