# House of Lemon

## 一句话结论

House of Lemon 是 **glibc 2.23 的标准流劫持链**：先把 `global_max_fast` 改大，再利用 `_int_free` 对 `fastbin_index(size)` 缺少上界检查，让超大 chunk 的 fastbin 头写越过 `main_arena.fastbinsY`，覆盖相邻 `_IO_2_1_stdout_` 的 vtable。原版完整终点在 **2.23 可用，2.24 起失效**。

这不是 House of Prime 的同义词。House of Prime 是 2005 年 *Malloc Maleficarum* 中没有完整实作的理论链；House of Lemon 是 2016 年题目中实际使用的“扩大 `global_max_fast` + fastbin 数组越界 + 标准流对象”组合。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 写大 `global_max_fast`；free 超大 chunk；stdout 邻接目标；旧版可控 vtable |
| 关键环境与不变量 | fastbin index 越界能到标准流；最终 vtable/trigger 可用 |
| 最终输出原语 | OOB heap-pointer 写到 stdout 并劫持 CF |
| 版本边界应如何理解 | 2.24 先硬封 heap fake-vtable 终点，但 2.24～2.36 底层 OOB 投递仍可换目标；2.37 uint8_t `global_max_fast` 再硬封投递本身。必须分两层。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

<!-- CHUNK_SIZE_REQUIREMENTS:START -->
## Chunk size 要求

- **必须能先申请、再 free 一个由目标槽反算出的精确超大 chunk。** x86-64 上 `chunksize = 2 * (target-fastbinsY) + 0x20`，request 再由该物理尺寸换算；示例 stdout vtable 得到 `chunksize=0x17c0`、`malloc(0x17b0)`。
- 该 chunk 应在扩大 `global_max_fast` 前先分配好，随后再把 `global_max_fast` 提高到至少覆盖 `chunksize`；否则超大 `malloc`/`free` 不会按预期走越界 fastbin 索引。
- 所以本手法不是“能申请任意 small chunk 即可”，而是题目菜单的最大 request 必须覆盖按附件 Build ID 重算出的那个值。
<!-- CHUNK_SIZE_REQUIREMENTS:END -->

## 版本矩阵

| glibc | 结论 | 原因 |
|---|---|---|
| 2.23 | **原版完整链可用** | `_int_free` 的 fastbin 下标无上界检查，且 FILE vtable 还可指向堆。 |
| 2.24～2.36 | **原版 RCE 终点失效；底层 OOB 写思路还要按构建复核** | 2.24 引入 `IO_validate_vtable`，堆虚表不再被默认接受。改大 `global_max_fast` 之后的越界 fastbin 头写本身不会因此消失，但必须换目标/终点。 |
| 2.37～2.43 | **该投递原语也失效** | `global_max_fast` 改为 `uint8_t`；它不能再容纳足以产生超大 fastbin 下标的值。 |

版本号只代表上游基线；发行版可能回移检查，`main_arena`、`global_max_fast` 与 FILE 私有布局也随构建变化。实战以附件 Build ID 为准。

## 从源码推导 0x17b0

glibc 2.23 x86-64 版本里相关的关键代码，简化之后大致是这样：

```c
if (size <= get_max_fast()) {
    unsigned int idx = (size >> 4) - 2;
    fb = &av->fastbinsY[idx];
    *fb = p;
}
```

这个构建里：

```text
main_arena             = libc + 0x3c3b20
fastbinsY              = main_arena + 0x8
global_max_fast        = libc + 0x3c5848
_IO_2_1_stdout_.vtable = libc + 0x3c4620 + 0xd8

idx  = (stdout_vtable - fastbinsY) / 8 = 0x17a
size = (idx + 2) << 4                 = 0x17c0
request                               = 0x17b0
```

只要 `global_max_fast >= 0x17c0`，执行 `free(malloc(0x17b0))` 就会把 chunk header 的地址写进 stdout 的 vtable 槽位。2.23 还没有对 vtable 做合法区检查，把伪造的 vtable 放在这个 chunk 上就能直接拿到控制流。

## PoC

- [`poc_2.23.c`](./poc_2.23.c)：只在版本精确匹配 `2.23-0ubuntu3_amd64` 时正确执行。它以“已拿到一次 libc 任意写”为前置，先扩大 `global_max_fast`，再执行超大尺寸 fastbin 越界写，最后通过 `fflush(stdout)` 跳到 `win()`。

这份 PoC 没有重复实现 unsafe unlink：它是通用的任意写投递手法，已在 [`unsafe_unlink`](../unsafe_unlink/README.md) 单独验证过；这里只保留 Lemon 本身最值得在 GDB 里逐步观察的部分。

```bash
cd heap_ultimate_cheatsheet
./tools/prepare_exact_libcs.sh /path/to/glibc-all-in-one
./tools/run_in_docker.sh 2.23 house_of_lemon/poc_2.23.c
```

预期输出：

```text
[+] House of Lemon: stdout 的虚表调用已经劫持到堆上。
```

## 迁移到题目

1. 用 unsafe unlink、unsorted-bin write，或者题目里现成的任意写去扩大 `global_max_fast`；**一定要先分配好这个超大尺寸的 chunk，再去改大这个值**，否则这个尺寸对应的 `malloc` 路径会提前把 arena 弄坏。
2. 从附件 ELF 或调试符号重新求出 `main_arena`、`global_max_fast` 和标准流目标槽地址，再按上面的逆推公式重算 chunk size，不能直接照搬本文数值。
3. 伪造的 vtable 要指向 chunk header；`free` 会把旧的 fastbin 头写进 `p->fd`，所以不要把唯一关键的函数指针放在 `user[0]`。
4. 2.24 起不要照搬这份 heap vtable 的最终触发点。先确认新版本可用的消费路径，不要只看到 OOB 写成功就断言整条 House of Lemon 还能用。

## 一手资料

- [House of Lemon 原作者题解](https://bbs.kanxue.com/article-446.htm)
- [glibc 2.23 `malloc.c`](https://github.com/bminor/glibc/blob/glibc-2.23/malloc/malloc.c)
- [glibc 2.24 `libioP.h`：`IO_validate_vtable`](https://github.com/bminor/glibc/blob/glibc-2.24/libio/libioP.h)
- [glibc：将 `global_max_fast` 改为 `uint8_t` 的提交](https://sourceware.org/git/?p=glibc.git;a=commit;h=15a94e6668a6d7c5697e805d8d67f1d102d0d52e)
- [Malloc Maleficarum 原文存档](https://gist.github.com/martinstnv/e3541ea15477017a01e278480875acd3)
