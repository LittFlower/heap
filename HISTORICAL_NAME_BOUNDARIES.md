# 历史 House 名称边界：为什么没有 Prime / Chaos PoC

本页专门处理“终极清单里为什么少了某个著名名字”。本项目范围是 **x86-64 glibc 2.23～2.43**，不会为了凑齐名称而把 2005 年、glibc 2.3.5、32 位结构上的理论描述伪装成现代 PoC。

## House of Prime：原版不在本项目版本范围

*Malloc Maleficarum* 的原始 House of Prime 使用 glibc 2.3.5，第一步依赖：

```text
fastbin_index(8) == -1
&arena->fastbins[-1] == &arena->max_fast
```

也就是 free 一个伪造 `size=8` 的 chunk，利用负下标把 `av->max_fast` 改成 chunk 地址；再用第二个超大 fastbin 下标越界覆盖构建相关的 `arena_key`。

这不是 glibc 2.23 的布局。2.23 的 `struct malloc_state` 中已没有 `max_fast` 字段；边界变成独立的文件静态变量 `global_max_fast`。因此 `fastbinsY[-1]` 不会按原论文描述命中它，`arena_key` 终点也不是可移植的现代目标。

结论：

- 不创建 `house_of_prime/poc_2.23...`，因为那会错误暗示原始算法适用于本项目版本。
- 如果已经有一次 libc 任意写，扩大 `global_max_fast` 后再做 fastbin 数组越界，实际可执行的 glibc 2.23 标准流链是 [`House of Lemon`](./house_of_lemon/README.md)。
- `global_max_fast` 在 2.37 改成 `uint8_t`，Lemon/Corrosion 一类“任意扩大 fastbin 范围”的基础又出现硬边界。

## House of Chaos：原文不是堆管理器技术

原始 *Malloc Maleficarum* 的目录确实列出 “The House of Chaos”，但该节是文章的哲学式结语；它没有漏洞前置、malloc/free 路径、元数据构造或控制原语。把标题本身当作一种 heap exploitation technique，再编造一个 PoC，是不准确的。

结论：本项目不为 House of Chaos 创建手法目录，也不把别的现代组合链重命名为 Chaos。

## 原文六个名称在本项目中的去向

| 2005 原文名称 | 2.23～2.43 的处理 |
|---|---|
| House of Prime | 原版结构前提已过时；记录于本页，现代可实现的相关链见 Lemon/Corrosion。 |
| House of Mind | 收录 [`house_of_mind/`](./house_of_mind/README.md) 的现代 fastbin-arena 变体。 |
| House of Force | 收录 [`house_of_force/`](./house_of_force/README.md)，2.23～2.28；2.29 top 检查终止。 |
| House of Lore | 收录 [`house_of_lore/`](./house_of_lore/README.md)，并与 [`small_bin_attack/`](./small_bin_attack/README.md) 消歧。 |
| House of Spirit | 收录 [`house_of_spirit/`](./house_of_spirit/README.md) 的 fastbin/tcache 分支。 |
| House of Chaos | 原文无堆管理器技术内容；不生成虚构 PoC。 |

## 一手资料

- [The Malloc Maleficarum 原文存档](https://gist.github.com/martinstnv/e3541ea15477017a01e278480875acd3)
- [glibc 2.23 `malloc.c`：`malloc_state` 与 `global_max_fast`](https://github.com/bminor/glibc/blob/glibc-2.23/malloc/malloc.c)
- [House of Lemon 原作者题解](https://bbs.kanxue.com/article-446.htm)
- [glibc：`global_max_fast` 改为 `uint8_t`](https://sourceware.org/git/?p=glibc.git;a=commit;h=15a94e6668a6d7c5697e805d8d67f1d102d0d52e)
