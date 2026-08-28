# House of Pig

## 结论

**一句话**：能控制 `_IO_str_overflow` 扩容时 `malloc` 返回的地址，就有 House of Pig；2.23～2.27 走的是另一套回调，不是同一条数据流。

| 版本 | 你能拿到什么 | 备注 |
|---|---|---|
| 2.23～2.27 | FILE 尾部两个可控函数指针（旧式合法-vtable FSOP） | 与 2.28+ 不是同一数据流；`4e8a6346` 后这两个字段只剩 ABI 占位 |
| **2.28～2.43** | `_IO_str_overflow` 内部 `malloc→memcpy→free/memset`，本目录默认指这一条 | 现代 Pig 核心，本仓库主力验证对象 |
| 2.31～2.33 | 原题终点窗口：TSU+ + 两次 largebin attack + `__free_hook` | 绑定 glibc 2.31 原题；2.32/2.33 需另处理 safe-linking/构建差异 |
| 2.34～2.41 | PLUS：`memset` IFUNC/GOT → gadget → `setcontext`/ROP | 强构建相关，4 个条件需逐附件核实（见下） |
| 2.42～2.43 | 仅剩最终触发点本身 | largebin/旧 stashing 投递已失效，需另一强原语负责投递 |

前置能力：2.28+ 要能控制 `_IO_str_overflow` 内部复制的源/长度，让扩容后的 `malloc` 落到目标地址；2.23～2.27 只需能改 FILE 尾部这两个函数指针。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | fake `_IO_strfile`/字段，能投递并触发 overflow；现代链还需可控复制源/长度 |
| 关键环境与不变量 | 旧版尾部回调或 2.28+直接 malloc/memcpy/free；终点 Build-ID/RELRO |
| 最终输出原语 | 旧版间接回调；现代版分配+拷贝+free 组合写/CF 链 |
| 版本边界应如何理解 | 2.28 不是简单偏移，而是从可控回调换成直接函数调用；现代 Pig 最终触发点到 2.43 仍在，但 2.34 hooks、2.42 largebin 分别切断旧终点和投递。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

<!-- CHUNK_SIZE_REQUIREMENTS:START -->
## Chunk size 要求

- **旧回调版没有固定 chunk size。** 2.28+ 现代版虽然也无固定 bin 范围，但内部 request 被严格限定为 `new_size = 2*old_blen + 100`；要让这次 malloc 命中某个 poisoned class，必须能控制 FILE 的 buffer 差值，使 `request2size(new_size)` 精确落入该 class。
- 若复现原题的 largebin+tcache 投递，仍需能申请物理 `chunksize >= 0x400` 的有序 largebin 节点以及所选 tcache class；这些数值由目标表地址和 Build ID 决定，不属于 Pig sink 的通用要求。
<!-- CHUNK_SIZE_REQUIREMENTS:END -->

## 从源码看

### 2.23～2.27：旧式 `_IO_strfile` 回调

这一段的 `libio/strops.c` 实际执行：

```c
new_buf = (*((_IO_strfile *) fp)->_s._allocate_buffer)(new_size);
memcpy(new_buf, old_buf, old_blen);
(*((_IO_strfile *) fp)->_s._free_buffer)(old_buf);
```

在 x86-64 上，合法 jump table 之后的 `FILE+0xe0` 和 `FILE+0xe8` 是两个回调。2.24 虽然加了 vtable 白名单，攻击者还是能用白名单里的 `_IO_str_jumps/_IO_mem_jumps`，再覆盖这两个表外回调。[`poc_legacy_callbacks_2.23_2.27.c`](./poc_legacy_callbacks_2.23_2.27.c) 用真实 `open_memstream` 和合法 `_IO_mem_jumps` 验证这两个回调都被消费。

提交 `4e8a6346` 在 2018-06-01 删掉了所有这些间接调用，字段只为 ABI 兼容改名 `*_unused`；变化进了 glibc 2.28。同一份 PoC 在精确的 2.28 首发包里两个计数都是零，按预期断言失败。所以别拿 2.24 的旧回调 FSOP 去证明 2.28 之后现代 Pig 的语义，反过来也一样。

### 2.28～2.43：现代扩容最终触发点

从 2.28 起，`libio/strops.c` 的 `_IO_str_overflow` 在扩容分支按顺序执行：

```c
new_size = 2 * old_blen + 100;
new_buf = malloc(new_size);
memcpy(new_buf, old_buf, old_blen);
free(old_buf);
memset(new_buf + old_blen, 0, new_size - old_blen);
```

这给出三段利用面：控制 `malloc` 的返回位置，用 `memcpy` 覆盖那个位置，再交给 `free` 或 `memset` 消费。[`poc_str_overflow_sink_2.28_2.43.c`](./poc_str_overflow_sink_2.28_2.43.c) 逐字节验证旧数据被复制、新尾部被清零、增长公式是 `2 * old_blen + 100`。函数还在，不等于完整 House 还在。

### 2.31～2.33：经典终点窗口

原始 XCTF Final 2021 题目用 glibc 2.31，把 Tcache Stashing Unlink+、两次 largebin attack 和 FSOP 串起来：先让内部 `malloc(new_size)` 返回 `__free_hook` 附近，`memcpy` 写入 `system`，紧接着 `free(old_buf)` 触发。2.32/2.33 还得分别处理 safe-linking 和目标构建差异。这里把它们叫“终点窗口”——原题 exploit 不是不改就能跑的。2.34 起 malloc/free 主路径不再调 hooks，这个终点就结束了。

### 2.34～2.41：House of Pig PLUS（强构建相关）

补充资料给出的 PLUS 变体把内部 `malloc` 导向 libc 自己 `memset` 的 IFUNC/GOT 槽，再由 `memcpy` 把槽改成转换寄存器的 gadget；接下来源码里的 `memset` 间接调用 gadget，接上 `setcontext+61`/ROP。它有四个必须逐附件验证的条件：

1. 目标 libc 确实通过可定位的 IFUNC/GOT 槽发起这次内部 `memset`；
2. 这个槽运行时要可写。GNU_RELRO、`.got/.got.plt` 边界和 BIND_NOW 都由构建决定，只看版本号不够；
3. `memset` 前的 `free(old_buf)` 必须能通过，所以 old_buf 和 next chunk header 都要合法；
4. gadget 的寄存器输入和 `setcontext` 偏移必须按附件反汇编确认。

2.34 的 Ubuntu 21.10 构建里，指向 `memset` IFUNC resolver 的 `R_X86_64_IRELATIVE` 槽在 `.got.plt`；这只是一个可复现的例子，不是所有发行版 2.34～2.41 的 ABI 保证。

### 2.42～2.43：只保留最终触发点

`_IO_str_overflow` 的 malloc/memcpy/free/memset 数据流还在，但经典 largebin `bk_nextsize` 写和旧 tcache-stashing 投递已经没了。题目要是另外给了 tcache metadata hijack、任意写或 overlap，还能把这里当最终触发点用——不过那是借了别的强原语，不算通用 House PoC。

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

现代 C 文件末尾分别整理了经典 hook 窗口、PLUS 构建检查和 2.42～2.43 替代投递伪代码；可执行主体只承诺真实扩容数据流。

## 迁移与调试

1. 先确认投递路径和最终触发点在目标 Build ID 中都存在。
2. 把占位地址和 add/edit/free 顺序替换成题目能力。
3. 在消费函数下断点，逐字段核对 size、对齐、safe-linking、FILE/link_map 私有布局。
