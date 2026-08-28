# 内存破坏、原语升级与利用策略

这篇不按漏洞名字背 payload，而是把根因、首次破坏、可观测原语和最终目标分开。相同的 OOB 在不同对象布局下可能只造成崩溃，也可能升级成稳定任意读写。

## 四层描述法

分析一个漏洞时分四层写：

```text
根因：整数截断 / 生命周期错误 / 边界检查错误 / 类型混淆 / 竞态
首次破坏：越界读写、UAF dereference、double free、错误对象解释
原语：地址范围、内容、次数、时机和副作用都明确的 read/write/free/call
目标：泄漏、任意写、合法回调、ROP、数据状态或 syscall
```

“存在 UAF”只到第二层；“可反复编辑已释放 0x90 chunk 的前 0x20 bytes，且不会立即重分配”才接近可用于堆分析的输入原语。

## 长度与整数链

每个长度都画出类型流：

```text
文本/网络 bytes
  -> parser 返回类型
  -> 校验时类型
  -> 加法/乘法/对齐
  -> allocation size_t
  -> copy/read 参数 size_t
  -> 循环 index 类型
```

重点检查：

- 负的有符号值转换成很大的 `size_t`；
- `count * element_size` 在窄类型先溢出，再扩展；
- `len + header + alignment` 回绕；
- 64 位解析后截断到 32/16/8 位字段；
- 比较时发生 usual arithmetic conversions，导致负值按 unsigned 比较；
- 分配按截断后的长度，复制按原始长度；
- byte count 与 element count 混用；
- `<= capacity` 为 NUL 留位错误，造成 off-by-one；
- 指针相减转成无符号长度前没有验证顺序。

验证时记录边界集合，而不是只试一个大数：

```text
-1, 0, 1
limit-1, limit, limit+1
TYPE_MAX-1, TYPE_MAX
乘法/加法刚好溢出的前后值
page、allocator alignment、协议 frame 边界
```

## OOB read

先回答：

- 起点相对哪个对象？能向前、向后还是两者？
- 最大长度由哪个字段决定，遇到 NUL/换行/fault 是否提前结束？
- 输出是 raw bytes、字符串、hex、数值还是被转义后的数据？
- 能否多次移动窗口，跨页失败是否保留之前的结果？
- 泄漏对象在输出前会不会被另一个线程或 allocator 改写？

常见升级目标：对象指针、vptr、返回地址、saved frame pointer、canary、GOT/loader 指针、FILE 指针、heap metadata。泄漏值必须先归属到实际 mapping，再减附件偏移。

## OOB write

写原语至少用五元组描述：

```text
(relative/absolute address, writable length, byte constraints, repetitions, trigger timing)
```

特别区分：

- **线性覆盖**：前缀也会被破坏；不能直接等价于任意地址写。
- **单 byte/off-by-null**：信息量很小，但相邻长度、flag 或指针低位可能有放大作用。
- **部分指针覆盖**：高位保留，低位选择同一映射附近目标；成功率取决于页内 offset、ASLR 熵、canonical address 与输入限制。
- **add/xor/or 写**：目标初值影响最终值，需要先泄漏或利用代数不变量。
- **字符串写**：NUL、空白、编码和自动 terminator 都会改变 payload。
- **write-what-where 但一次性**：应优先选择能继续产出读写能力或可靠最终动作的目标。

### 低带宽破坏的放大器

只有一字节或一次部分写时，先找后续会把小状态解释成“大范围动作”的字段：

| 小修改目标 | 可能的后续放大 | 必须验证 |
|---|---|---|
| saved RIP 低位 | 跳到同一地址范围内的输入/ROP入口 | 保留高位、PIE 页内 offset、栈状态 |
| 指针或二重指针低位 | 把既有读写窗口重定向到邻近对象 | ASLR 熵、对齐、可读写 mapping |
| length/capacity/end pointer | 下一次 copy、loop、refill 扩大范围 | 单位、比较顺序、目标边界 |
| `FILE` buffer 边界 | stdio refill 形成较长线性覆盖 | glibc 布局、stream 状态、相邻对象 |
| dynamic tag/linker pointer | resolver 或 fini 按新表解释数据 | loader 版本、RELRO、派生索引 |
| object type/tag/opcode | 合法方法把 payload 当成另一类字段 | 全部类型检查、析构与 callback ABI |

“小写入→大动作”只是候选路线。必须在真正消费点记录读了哪个字段、算出多大的范围，还有线性覆盖会先破坏哪些前缀。

## UAF、double free 与类型混淆

生命周期问题要画事件序列：

```text
allocate -> publish aliases -> use -> release -> reuse -> stale use
```

检查：

- 释放的是对象本体、内部 buffer、控制块还是引用计数最后一个 owner？
- stale alias 能 read、write、free、call 哪个字段？
- 复用类型的大小、对齐、构造和析构是否匹配？
- allocator 是否会清零、扰动或覆写 freelist metadata？
- 多线程引用计数与业务锁是否产生第二条竞态？
- double free 是否发生在同一 allocator/arena，第二次 free 前 chunk 状态如何变化？

C++ 对象布局见 [`CPP_REVERSE.md`](./CPP_REVERSE.md)，glibc chunk 路线见根目录各手法 README。

## Stack overflow

不要只求到 return address 的 offset。依次标注：

```text
local buffers
其他局部变量 / spilled registers
canary
saved frame pointer
return address
caller frame 与后续栈空间
```

需要验证：

- 输入是一次写完，还是可以 staged read？
- 覆盖在函数返回前是否经过 strlen/free/printf/exception cleanup？
- ABI 要求的 stack alignment；x86-64 调函数前后 `rsp` 是否满足 16-byte 约束？
- saved frame pointer 被破坏后，epilogue 是 `leave; ret` 还是直接恢复 `rsp`？
- red zone、VLA、`alloca`、优化和 omit-frame-pointer 是否改变反编译形状？
- 只能控制低 1/2 bytes 时，目标页内 offset 和重随机行为如何？

用 cyclic pattern 定 offset 前，确认 crash 的 PC/SP 和被覆盖宽度；UTF-8、line reader、toupper、NUL 截断会破坏 pattern。

### 输入变换链

payload 到达漏洞前若经历 parser、解码或字符替换，应单独记录每一层：

```text
network bytes -> framing -> text parse/decode -> in-memory bytes -> vulnerable copy
```

cyclic pattern、地址、格式串和 shellcode 都要对最终内存 bytes 求逆像。ROT13、base64、float decimal、locale、UTF-8 和大小写折叠不只是“坏字符”；它们可能多对一、改变长度，或根本没有目标 byte 的逆像。相关实例见 [`INPUT_AND_IO.md`](./INPUT_AND_IO.md#文本输入承载精确-bit-pattern)、[`FORMAT_STRING.md`](./FORMAT_STRING.md#sink-前存在输入变换)和 [`SHELLCODE.md`](./SHELLCODE.md#受限字符与输入变换)。

## Format string 与 variadic type confusion

格式串既可能泄漏，也可能通过 `%n` 形成受约束写。除此之外，variadic API 没有运行时参数个数和类型元数据；format 与真实参数不一致会让函数按错误宽度/类型取寄存器保存区或栈。

分析应记录：format 是否可控、参数来自寄存器还是栈、positional 参数是否混用、已输出字符数、目标指针层数和 libc 的边界检查。具体写法见 [`FORMAT_STRING.md`](./FORMAT_STRING.md)。

## Race / TOCTOU

竞态不等于“多发几个请求”。先画两个 actor 的状态机，找出共享资源和缺少同步的区间：

```text
T1: check object/path/refcount ---- use/free
T2:             replace/close/free/reallocate
```

稳定触发方法取决于目标：线程屏障、阻塞 syscall、userfaultfd/FUSE、pipe/socket backpressure、CPU affinity、优先级、反复循环或扩大临界区。哪些接口可用受内核、权限和 seccomp 限制。

调试器单步会改变调度。先用带时间戳的轻量日志或条件断点确认顺序，再设计同步点。成功一次后还要证明状态破坏与利用消费之间不会被清理。

## 从原语到终点

### 信息泄漏

优先级通常是：先泄漏能消除当前路线最大不确定性的地址，而不是“能看到的第一个指针”。

```text
PIE pointer -> 主程序 gadgets/global
libc/loader pointer -> 函数、合法回调、动态链接状态
stack pointer -> ROP/frame/argv/envp
heap pointer -> chunk/object 相对定位
canary -> 栈覆盖保持校验
kernel pointer -> 对应内核构建的 KASLR base
```

一个值可能是 mangled/tagged/safe-linked pointer、文件 offset 或 handle。先验证 canonical form、mapping、alignment 和重复性。

### 任意写

目标选择顺序：

1. 能扩展成稳定任意读写的对象字段；
2. 会在可控时机消费、且满足保护机制的合法 callback/data pointer；
3. 控制授权、长度、路径、uid、flag 状态等 data-only 目标；
4. 返回地址、vptr、GOT 等传统控制流目标，仅在对应保护允许时；
5. 一次性 crash-sensitive 目标放最后。

写入成功不等于目标会被消费。必须在消费点断下，确认对象身份、调用点、锁/引用计数和参数。

### PC 控制

| 路线 | 硬条件 | 常见失败原因 |
|---|---|---|
| ret2win/ret2libc | 可控返回路径、已知目标、正确 ABI | PIE/libc 未泄漏、栈未对齐、参数或返回链错误 |
| ROP | 足够 gadgets、可控栈、NX 不影响代码复用 | SHSTK、坏字符、栈空间不足、gadget 副作用 |
| SROP | sigreturn syscall/trampoline、伪 frame、可控 SP | frame 与内核 ABI 不匹配、seccomp 禁 syscall、CET/架构差异 |
| ret2dlresolve | loader resolver 路线、可写伪表、二阶段输入 | ABI/索引/对齐/version 错、目标 scope 不含 symbol |
| JOP/COP | dispatcher 与一组可控间接跳转/call | IBT/BTI/CFI 目标集合、寄存器状态难串联 |
| COOP | 可控 C++ 对象/vptr、合法虚调用循环 | 对象布局、this 调整、析构和 CFI class hierarchy |
| BROP | 同映像可反复 crash、可区分响应 | crash 后重随机、负载均衡、请求预算和网络噪声 |
| shellcode | 可执行 payload 页或可改变权限 | NX、seccomp、坏字符、架构/缓存/状态错误 |

SROP 利用的是 kernel 从用户栈 signal frame 恢复 PC、SP 和寄存器的机制；frame 是架构和内核 ABI 相关数据，不是固定跨平台结构。BROP 原始前提和流程见 [Hacking Blind](https://www.scs.stanford.edu/~dm/home/papers/bittau%3Abrop.pdf)，COOP 原始研究见 [Counterfeit Object-oriented Programming](https://informatik.rub.de/veroeffentlichungenbkp/syssec/veroeffentlichungen/2015/pdfs/2015_Counterfeit_Object_oriented_Programming__On_the_Difficulty_of_Preventing_Code_Reuse_Attacks_in_C%2B%2B_Applications.pdf)。

## 数据流利用

强控制流保护下，先找“不改变 PC 也能完成题目目标”的字段：

- 已认证/管理员 flag、uid/gid、capability 或访问模式；
- 文件名、目录 fd、offset、长度和输出 fd；
- 对象 type/state、数组 count、权限 bitmap；
- 已经存在且合法签名的 callback 参数；
- 解密后的指针、key index、message opcode；
- 程序自然会输出/写文件的 buffer pointer 与 length。

data-only 路线也要给出不变量：目标字段生命周期、并发访问、校验发生顺序和最终外部效果。

## 概率与可靠性

如果单次成功率为 `p`，独立尝试 `n` 次至少成功一次的理论概率是：

```text
1 - (1 - p)^n
```

但 CTF 利用中的尝试常不独立：worker 继承地址、allocator 状态累积、负载均衡切换实例、失败改变全局计数。实际要分别测：

- 新连接同一 worker；
- crash 后 fork；
- crash 后 exec；
- 容器/服务整体重启；
- 不同远端实例。

脚本记录每阶段成功次数，而不是只记录最终拿 flag 次数，这样才能定位概率损失发生在哪一段。

## 根因参考

- [CWE-125：Out-of-bounds Read](https://cwe.mitre.org/data/definitions/125.html)
- [CWE-787：Out-of-bounds Write](https://cwe.mitre.org/data/definitions/787.html)
- [CWE-190：Integer Overflow or Wraparound](https://cwe.mitre.org/data/definitions/190.html)
- [CWE-416：Use After Free](https://cwe.mitre.org/data/definitions/416.html)
- [CWE-415：Double Free](https://cwe.mitre.org/data/definitions/415.html)
- [CWE-362：Race Condition](https://cwe.mitre.org/data/definitions/362.html)
- [Linux `sigreturn(2)`](https://man7.org/linux/man-pages/man2/sigreturn.2.html)
