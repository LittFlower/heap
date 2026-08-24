# House of Pig

## 结论

- 适用范围：**旧 `_IO_strfile` 回调最终触发点为 2.23～2.27；现代 House of Pig 的直接 `malloc→memcpy→free` 最终触发点为 2.28～2.43**。原题完整链绑定 glibc 2.31；经典 `__free_hook` 终点可讨论到 2.33；Pig PLUS 的已知 `memset` IFUNC/GOT 终点主要用于 2.34～2.41 特定构建；2.42～2.43 只承诺最终触发点。
- 原语/效果：2.28 起利用 `_IO_str_overflow` 内部直接分配、复制和释放串联受控投递与覆盖；2.23～2.27 的同名函数调用的是 FILE 尾部两个可控函数指针，应归入旧式合法-vtable FSOP，不能称为同一数据流。
- 版本变化：2.28 删除旧回调消费并改成直接 malloc/free；2.34 hooks 删除后须换终点；2.41 终止经典 stashing；2.42 经典 largebin 写被封堵；2.43 最终触发点仍在，但 fastbin 也已删除。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | fake `_IO_strfile`/字段，能投递并触发 overflow；现代链还需可控复制源/长度 |
| 关键环境与不变量 | 旧版尾部回调或 2.28+直接 malloc/memcpy/free；终点 Build-ID/RELRO |
| 最终输出原语 | 旧版间接回调；现代版分配+拷贝+free 组合写/CF 链 |
| 版本边界应如何理解 | 2.28 不是简单偏移，而是从可控回调换成直接函数调用；现代 Pig 最终触发点到 2.43 仍在，但 2.34 hooks、2.42 largebin 分别切断旧终点和投递。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 从源码看

### 2.23～2.27：旧式 `_IO_strfile` 回调

这一段的 `libio/strops.c` 实际执行：

```c
new_buf = (*((_IO_strfile *) fp)->_s._allocate_buffer)(new_size);
memcpy(new_buf, old_buf, old_blen);
(*((_IO_strfile *) fp)->_s._free_buffer)(old_buf);
```

在 x86-64 上，合法 jump table 之后的 `FILE+0xe0` 和 `FILE+0xe8` 分别是两个回调。2.24 虽加入 vtable 白名单，但攻击者仍可使用白名单中的 `_IO_str_jumps/_IO_mem_jumps`，再覆盖这两个表外回调。[`poc_legacy_callbacks_2.23_2.27.c`](./poc_legacy_callbacks_2.23_2.27.c) 用真实 `open_memstream` 和合法 `_IO_mem_jumps` 验证这两个回调均被消费。

提交 `4e8a6346` 在 2018-06-01 删除所有这些间接调用，字段仅为 ABI 兼容而改名 `*_unused`；变化进入 glibc 2.28。同一 PoC 在精确 2.28 首发包中两个计数均为零并按预期断言失败。因此不能用 2.24 的旧回调 FSOP 来证明 2.28 以后现代 Pig 的语义，反之亦然。

### 2.28～2.43：现代扩容最终触发点

从 2.28 起，`libio/strops.c` 的 `_IO_str_overflow` 在扩容分支按顺序执行：

```c
new_size = 2 * old_blen + 100;
new_buf = malloc(new_size);
memcpy(new_buf, old_buf, old_blen);
free(old_buf);
memset(new_buf + old_blen, 0, new_size - old_blen);
```

这给出三段不同的利用面：控制 `malloc` 返回位置、用 `memcpy` 覆盖该位置、再由 `free` 或 `memset` 消费。[`poc_str_overflow_sink_2.28_2.43.c`](./poc_str_overflow_sink_2.28_2.43.c) 逐字节验证旧数据被复制、新尾部被清零、增长公式为 `2 * old_blen + 100`。不能把“函数还在”直接等价为“完整 House 还在”。

### 2.31～2.33：经典终点窗口

原始 XCTF Final 2021 题目使用 glibc 2.31，把 Tcache Stashing Unlink+、两次 largebin attack 和 FSOP 串联：先使内部 `malloc(new_size)` 返回 `__free_hook` 附近，`memcpy` 写入 `system`，紧接着 `free(old_buf)` 触发。2.32/2.33 还须分别处理 safe-linking 和目标构建差异；本目录把它们称为“终点窗口”，不声称原题 exploit 可以不改直接运行。2.34 起 malloc/free 主路径不再调用 hooks，因此这个终点结束。

### 2.34～2.41：House of Pig PLUS（强构建相关）

补充资料给出的 PLUS 变体把内部 `malloc` 导向 libc 自身 `memset` 的 IFUNC/GOT 槽，再由 `memcpy` 把槽改成转换寄存器的 gadget；随后源码中的 `memset` 间接调用 gadget，并衔接 `setcontext+61`/ROP。它有四个必须逐附件验证的条件：

1. 目标 libc 确实通过可定位的 IFUNC/GOT 槽发起这次内部 `memset`；
2. 该槽运行时可写。GNU_RELRO、`.got/.got.plt` 边界与 BIND_NOW 都由构建决定，不能只看版本；
3. 在 `memset` 前发生的 `free(old_buf)` 必须通过，因此 old_buf 及 next chunk header 要合法；
4. gadget 的寄存器输入和 `setcontext` 偏移必须按附件反汇编确认。

2.34 的 Ubuntu 21.10 构建可看到指向 `memset` IFUNC resolver 的 `R_X86_64_IRELATIVE` 槽位于 `.got.plt`；这只是一个可复现实例，不是所有发行版 2.34～2.41 的 ABI 保证。

### 2.42～2.43：只保留最终触发点

`_IO_str_overflow` 的 malloc/memcpy/free/memset 数据流仍在，但经典 largebin `bk_nextsize` 写和旧 tcache-stashing 投递已经结束。若题目另给 tcache metadata hijack、任意写或 overlap，仍可把这里当最终触发点；本目录不把这种“另有强原语”的组合冒充通用 House PoC。

源码中仍能走到最终触发点，不等于旧利用链仍成立：投递方式、私有结构和控制流终点都要按附件 libc/ld 的 Build ID 复核。

源码与背景：

- [GNU glibc 2.41 strops.c](https://github.com/bminor/glibc/blob/glibc-2.41/libio/strops.c)
- [GNU glibc 2.43 strops.c](https://sourceware.org/cgit/glibc/tree/libio/strops.c?h=release/2.43/master)
- [glibc `4e8a6346`：删除 `_allocate_buffer/_free_buffer` 间接调用](https://sourceware.org/git/?p=glibc.git;a=commit;h=4e8a6346cd3da2d88bbad745a1769260d36f2783)
- [glibc 2.34 malloc hooks 移除](https://sourceware.org/git/?p=glibc.git;a=commit;h=1e5a5866cb9541b5231dba3d86c8a1a35d516de9)
- [GNU glibc 当前开发分支](https://github.com/bminor/glibc/tree/master)
- [CTF Wiki：XCTF Final 2021 House of Pig 原题链](https://ctf-wiki.org/pwn/linux/user-mode/heap/ptmalloc2/house-of-pig/)
- [作者原始技术分享的镜像：题目与 2.31 背景](https://cn-sec.com/archives/383992.html)
- [House of all 综述](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/)
- [高版本 heap exploitation](https://roderickchan.github.io/zh-cn/2023-03-01-analysis-of-glibc-heap-exploitation-in-high-version/)
- [看雪《CTF 中 glibc 堆利用及 IO_FILE 总结》离线存档](/Users/flower/Zotero/storage/QPI8VQE6/thread-272098-1.html)

## PoC

- [`poc_legacy_callbacks_2.23_2.27.c`](./poc_legacy_callbacks_2.23_2.27.c)：真实合法 vtable 下消费旧 allocate/free 回调；2.28 负测试失败
- [`poc_str_overflow_sink_2.28_2.43.c`](./poc_str_overflow_sink_2.28_2.43.c)：真实 `_IO_str_overflow` 扩容，严格验证 malloc/memcpy/free/memset 数据效果

现代 C 文件末尾分别整理经典 hook 窗口、PLUS 构建检查和 2.42～2.43 替代投递伪代码；可执行主体只承诺真实扩容数据流。

## Python 离线板子

[`pig.py`](./pig.py) 提供 `build_house_of_pig`，把 `_IO_str_overflow` 的扩容数据流算成可直接用的计划对象。

### 函数用途

```text
计算扩容时的 new_size = 2 * old_blen + 100
按版本区分旧式回调槽和现代直接 malloc/memcpy/free 数据流
```

### 对应 PoC

- [`poc_legacy_callbacks_2.23_2.27.c`](./poc_legacy_callbacks_2.23_2.27.c)：2.23～2.27 消费 `FILE+0xe0` 的 `_allocate_buffer` 与 `FILE+0xe8` 的 `_free_buffer`；
- [`poc_str_overflow_sink_2.28_2.43.c`](./poc_str_overflow_sink_2.28_2.43.c)：2.28+ 直接执行 `malloc(new_size)`、`memcpy`、`free(old)`、`memset`。

### 参数

| 参数 | 含义 |
|---|---|
| `version` | 目标 glibc 版本，支持 `2.23`～`2.43`。 |
| `old_buffer_addr` | 扩容前 `_IO_buf_base`，即旧缓冲区地址。 |
| `old_length` | 旧缓冲区长度 `_IO_buf_end - _IO_buf_base`，必须大于 0。 |
| `stream_addr` | `_IO_strfile` 对象地址。仅 2.23～2.27 必须提供，用于计算旧式回调槽；2.28+ 可省略。 |

### 返回对象 `PigPlan`

| 字段 | 含义 |
|---|---|
| `old_buffer_addr` | 传入的旧缓冲区地址。 |
| `old_length` | 传入的旧长度。 |
| `new_size` | `2 * old_length + 100`，即扩容后申请的大小。 |
| `allocate_slot_addr` | 2.23～2.27 为 `stream_addr + 0xe0`；2.28+ 为 `None`。 |
| `free_slot_addr` | 2.23～2.27 为 `stream_addr + 0xe8`；2.28+ 为 `None`。 |

### 最小使用示例

```python
from pig import build_house_of_pig

# 2.28+：直接 malloc/memcpy/free 数据流
plan = build_house_of_pig(
    version="2.35",
    old_buffer_addr=0x300000,   # 旧 _IO_buf_base
    old_length=0x40,            # old_blen
)
print(plan.new_size)            # 2 * 0x40 + 100 = 0xc4
print(plan.allocate_slot_addr, plan.free_slot_addr)  # None, None

# 2.23～2.27：需要 stream_addr，返回旧回调槽
plan = build_house_of_pig(
    version="2.27",
    old_buffer_addr=0x300000,
    old_length=0x40,
    stream_addr=0x200000,       # _IO_strfile 对象
)
print(hex(plan.allocate_slot_addr), hex(plan.free_slot_addr))
# 0x2000e0, 0x2000e8
```

### 调用者必须提供

```text
可被 _IO_str_overflow 消费的 memstream/_IO_strfile 对象
能触发 overflow 的 write_ptr == write_end 条件
2.28+ 控制内部 malloc 返回位置所需的堆原语
2.23～2.27 覆盖 FILE+0xe0/0xe8 回调槽的能力
```

### 函数不负责

```text
不生成完整 payload
不负责 malloc 投递到 __free_hook / GOT / setcontext
不处理 PLUS 分支的 IFUNC/GOT、RELRO 和 gadget 约束
```


## 迁移与调试

1. 先确认投递路径和最终触发点在目标 Build ID 中都存在。
2. 把占位地址和 add/edit/free 顺序替换成题目能力。
3. 在消费函数下断点，逐字段核对 size、对齐、safe-linking、FILE/link_map 私有布局。
