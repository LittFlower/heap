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

## 版本矩阵

| glibc | 结论 | 原因 |
|---|---|---|
| 2.23 | **原版完整链可用** | `_int_free` 的 fastbin 下标无上界检查，且 FILE vtable 还可指向堆。 |
| 2.24～2.36 | **原版 RCE 终点失效；底层 OOB 写思路仍需按构建复核** | 2.24 引入 `IO_validate_vtable`，堆虚表不再被默认接受。修改 `global_max_fast` 后的越界 fastbin 头写本身并未因此自动消失，但必须换目标/终点。 |
| 2.37～2.43 | **该投递原语也失效** | `global_max_fast` 改为 `uint8_t`；它不能再容纳足以产生超大 fastbin 下标的值。 |

发行版可能回移检查，`main_arena`、`global_max_fast` 与 FILE 私有布局也受具体构建影响；实战必须以题目附件 libc 的 Build ID 为准。

## 从源码推导 0x17b0

glibc 2.23 x86-64 的关键代码可以化成：

```c
if (size <= get_max_fast()) {
    unsigned int idx = (size >> 4) - 2;
    fb = &av->fastbinsY[idx];
    *fb = p;
}
```

该构建中：

```text
main_arena             = libc + 0x3c3b20
fastbinsY              = main_arena + 0x8
global_max_fast        = libc + 0x3c5848
_IO_2_1_stdout_.vtable = libc + 0x3c4620 + 0xd8

idx  = (stdout_vtable - fastbinsY) / 8 = 0x17a
size = (idx + 2) << 4                 = 0x17c0
request                               = 0x17b0
```

因此 `free(malloc(0x17b0))` 在 `global_max_fast >= 0x17c0` 时会把 chunk header 地址写入 stdout 的 vtable 槽。2.23 还没有 vtable 合法区检查，伪 vtable 放在该 chunk 即可取得控制流。

## PoC

- [`poc_2.23.c`](./poc_2.23.c)：在精确 `2.23-0ubuntu3_amd64` 上可执行。它把“已有一次 libc 任意写”作为前置条件，直接扩大 `global_max_fast`，随后执行超大尺寸 fastbin 越界写，并通过 `fflush(stdout)` 跳到 `win()`。

PoC 刻意没有再拼接一遍 unsafe unlink：前者是通用任意写投递，已经由 [`unsafe_unlink`](../unsafe_unlink/README.md) 单独验证；本文件只保留 Lemon 独有、最值得在 GDB 中观察的部分。

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

1. 用 unsafe unlink、unsorted-bin write 或题目现成任意写扩大 `global_max_fast`；**必须先分配超大尺寸 chunk，再改大该值**，否则该尺寸的 `malloc` 路径会提前踩坏 arena。
2. 从附件 ELF/调试符号重新求 `main_arena`、`global_max_fast` 和标准流目标槽，按上面的逆公式计算 chunk size。
3. 伪 vtable 指向 chunk header；`free` 会把旧 fastbin 头写进 `p->fd`，所以不要把唯一关键函数指针放在 `user[0]`。
4. 2.24+ 不要照搬 heap vtable 终点；应先确认新的消费路径，而不是只看到 OOB 写成功就宣称整条 House 仍可用。

## 一手资料

- [House of Lemon 原作者题解](https://bbs.kanxue.com/article-446.htm)
- [glibc 2.23 `malloc.c`](https://github.com/bminor/glibc/blob/glibc-2.23/malloc/malloc.c)
- [glibc 2.24 `libioP.h`：`IO_validate_vtable`](https://github.com/bminor/glibc/blob/glibc-2.24/libio/libioP.h)
- [glibc：将 `global_max_fast` 改为 `uint8_t` 的提交](https://sourceware.org/git/?p=glibc.git;a=commit;h=15a94e6668a6d7c5697e805d8d67f1d102d0d52e)
- [Malloc Maleficarum 原文存档](https://gist.github.com/martinstnv/e3541ea15477017a01e278480875acd3)
