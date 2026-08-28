# CTF 博客、Writeup 与会议材料索引

本页记录第二轮互联网检索得到的用户态 Pwn 案例资料，检索日期为 **2026-08-28**。范围包括中英文原创博客、题目作者或参赛战队 Writeup、公开会议论文和演讲材料；按要求不整理 Kernel Pwn。

这些材料的价值是展示“题目怎样把弱原语放大”，但它们通常绑定某个附件。正文只吸收可以写出严格前提的模式，地址、offset、one-gadget 和私有结构布局都不直接抄进通用结论。

## 怎么读本页

每条案例拆成四项：

```text
入口能力：题目真正给了什么 read/write/free/call
放大器：利用了哪个库、loader、stdio、对象或进程行为
输出能力：最终得到什么更强原语
绑定条件：libc/ld、架构、进程模型、输入编码和触发次数
```

来源等级采用：

- **A**：题目作者、原始战队 Writeup，附源码、附件或 exploit；
- **B**：参赛者完整复现，含关键反汇编、调试状态和脚本；
- **C**：教程或汇总，只用于发现关键词，不能单独支撑版本结论；
- **会议材料**：用于攻击模型和方法论；迁移到 CTF 附件还要动态验证。

## 提炼出的高价值模式

| 模式 | 可迁移结论 | 必须重新验证 | 已整理到 |
|---|---|---|---|
| libc 隐式 allocator | 输入/输出函数内部也可能形成 `malloc/realloc/free` trigger | 目标 libc 源码分支、首次 request、增长序列、最终释放 | [`INPUT_AND_IO.md`](./INPUT_AND_IO.md) |
| 受编码的 payload | 先求输入变换的逆像，再判断目标 bytes 是否可表达 | parser round-trip、locale、NaN 归一化、NUL/换行 | [`INPUT_AND_IO.md`](./INPUT_AND_IO.md)、[`SHELLCODE.md`](./SHELLCODE.md) |
| 一字节或低带宽写 | 优先改长度、循环次数、指针低位或可重复消费的 loader/stdio 字段 | 高位不变量、ASLR 熵、调用次数、写后副作用 | [`MEMORY_CORRUPTION_AND_STRATEGY.md`](./MEMORY_CORRUPTION_AND_STRATEGY.md) |
| 动态链接元数据 | `JMPREL/SYMTAB/STRTAB/VERSYM` 是一条相关数据流，不是三张孤立表 | 目标 loader 实现、symbol version、对齐、relocation 类型 | [`ELF_LINKING_AND_RELOCATION.md`](./ELF_LINKING_AND_RELOCATION.md) |
| 分裂的 sandbox 能力 | fork 后各进程可能分别拥有 open/read/write/ptrace 等能力 | filter 安装时机、fd/内存继承、等待关系和 IPC | [`SANDBOX_AND_SHELL.md`](./SANDBOX_AND_SHELL.md) |
| C++ 对象伪造 | 仅伪造函数槽未必够；RTTI、address point、`this` 调整可能同样被消费 | 编译器、ABI、继承形状、CFI 和析构路径 | [`CPP_REVERSE.md`](./CPP_REVERSE.md) |
| VM/语言运行时 | 先把 guest 状态损坏升级成 host read/write，再考虑宿主利用 | opcode、对象表、GC、native bridge、unsafe/FFI | [`RUNTIME_AND_VM_PWN.md`](./RUNTIME_AND_VM_PWN.md) |
| exit 消费面 | `.fini_array`、TLS destructor、exit handler、loader fini 是不同目标 | `exit` 与 `_exit`、pointer guard、RELRO、私有布局、Build ID | [`LIBC_AND_LOADER.md`](./LIBC_AND_LOADER.md) |
| 布局搜索 | 把 grooming 片段、目标邻接关系和成功判据显式化，可做搜索和最小化 | allocator 状态、线程/arena、噪声 allocation、远端重启模型 | [`FIELD_WORKFLOW.md`](./FIELD_WORKFLOW.md) |

## Ltfall 技巧汇总的审阅结果

用户指定的 [《CTF-PWN做题的思路小记》](https://ltfa1l.top/2023/12/28/system/tricks/tricks/)是一篇持续更新的个人题解索引，页面标注发布于 2023-12-28、更新到 2025-03-10。它适合发现题型，但不同小节的证据强度不一致，因此本轮逐项处理如下：

| 原文主题 | 处理 | 落点或原因 |
|---|---|---|
| LLVM Pass Pwn | 收入，补齐 Legacy/New PM 区分 | [`LLVM_PASS_PWN.md`](./LLVM_PASS_PWN.md) |
| `scanf` 未赋值泄漏旧栈值 | 收入，限定为返回值未检查和目标未初始化 | [`INPUT_AND_IO.md`](./INPUT_AND_IO.md#scanf-转换失败与未初始化目标) |
| 关闭 stdout、`writev`、socket 输出 | 收入为 fd 拓扑，不假设 fd 0 一定可写 | [`SANDBOX_AND_SHELL.md`](./SANDBOX_AND_SHELL.md#先恢复文件描述符拓扑) |
| file-backed `mmap` 替代 `read` | 收入；纠正“匿名映射必定失败” | [`SANDBOX_AND_SHELL.md`](./SANDBOX_AND_SHELL.md#file-backed-mmap-可替代-read) |
| x86-64/32 位切换 | 收入为 compat ABI 检查项 | [`ARCHITECTURES_AND_SYSCALLS.md`](./ARCHITECTURES_AND_SYSCALLS.md#x86-64-long-mode-与-compat-mode-切换) |
| canary 泄漏、fork oracle、TLS guard | 收入，拆开进程/线程与消费点条件 | [`BINARY_RECON_AND_MITIGATIONS.md`](./BINARY_RECON_AND_MITIGATIONS.md#绕过路线按消费点分类) |
| C++ 异常导向其他 catch | 收入为 LSDA/landing-pad 路线 | [`CPP_REVERSE.md`](./CPP_REVERSE.md#让-unwinder-选择另一条-landing-pad) |
| 未绑定 GOT 表项重定向 PLT | 收入，要求 lazy binding、可写 slot 和 ABI 匹配 | [`ELF_LINKING_AND_RELOCATION.md`](./ELF_LINKING_AND_RELOCATION.md#未绑定-got-slot-重定向到另一条-plt-解析路径) |
| 一次格式串借 fini 获得下一轮 | 收入，增加 GNU_RELRO 与退出方式条件 | [`FORMAT_STRING.md`](./FORMAT_STRING.md#只有一次格式串调用时争取重新进入) |
| ret2csu 调用低副作用函数 | 收入为间接 callee 选择方法 | [`ABI_ROP_AND_STACK.md`](./ABI_ROP_AND_STACK.md#只借-csu-设置寄存器时选择低副作用-callee) |
| glibc `rand/random` 状态预测 | 收入 recurrence，但绑定目标 API/状态 | [`LIBC_AND_LOADER.md`](./LIBC_AND_LOADER.md#rand-与内部状态) |
| protobuf-c descriptor 与 IDA 类型导入 | 已收入；纠正编辑系统头文件和仅凭 `default_value` 判版本 | [`PROTOBUF_REVERSE.md`](./PROTOBUF_REVERSE.md#导入生成结构体时) |
| `printf` 大 width 隐式分配 | 已由 EasiestPrintf 和 glibc 路线覆盖 | [`INPUT_AND_IO.md`](./INPUT_AND_IO.md#历史-printf-大字段宽度的-allocator-side-effect) |
| `l_addr`/fini、`_IO_buf_base`、`mp_.tcache_bins` | 已有版本化 PoC，不重写固定偏移 | [`../house_of_banana/README.md`](../house_of_banana/README.md)、[`../io_file_arbitrary_read_write/README.md`](../io_file_arbitrary_read_write/README.md)、[`../tcache_relative_write/README.md`](../tcache_relative_write/README.md) |
| tcache fake size、mmap threshold、Botcake 等堆技巧 | 回到相应堆 README 与 chunk-size 条件，不建立第二套结论 | [`../house_of_spirit/README.md`](../house_of_spirit/README.md)、[`../house_of_muney/README.md`](../house_of_muney/README.md)、[`../house_of_botcake/README.md`](../house_of_botcake/README.md) |
| `pid+1` 找子进程 | 明确拒绝；PID 不保证连续 | [`DEBUGGING_AND_ENVIRONMENT.md`](./DEBUGGING_AND_ENVIRONMENT.md#gdb-常用命令) |
| `int3` 绕 ptrace、固定 `setcontext+N`、`alarm+5`、exit hook/one-gadget offset | 只保留为搜索线索 | 前者只对错误 tracer 状态机成立；其余绑定指令序列、私有布局与 Build ID |
| ret2vDSO 固定 frame 偏移、SUID shell 自动继承权限 | 不收入通用规则 | kernel/vDSO、shell 降权、secure-execution 与进程凭据都要独立验证 |

## 案例笔记

### `scanf` 超长数字触发 scratch buffer

[redpwnCTF 2021 Simultaneity Writeup](https://ctftime.org/writeup/29251) 在 glibc 2.28 环境展示了数值 `scanf` 的 scratch buffer：超过内嵌空间的连续数字触发增长，函数退出时释放临时块。它直接否定“只有 glibc 2.39 才有”这一说法。

可迁移部分是“数字 token 长度不受目标整数宽度限制”；不能迁移的是固定为 1024/2048、必进 unsorted、必进 `sysmalloc` 或必触发 hook。当前仓库已经按 2.3～2.44 源码分段，见 [`INPUT_AND_IO.md`](./INPUT_AND_IO.md)。

### `printf` 大字段宽度触发旧 `vfprintf` 分配

[0CTF 2017 EasiestPrintf](https://blog.dragonsector.pl/2017/03/0ctf-2017-easiestprintf-pwn-150.html) 和[另一份复现](https://poning.me/2017/03/23/EasiestPrintf/)展示了旧 glibc `vfprintf` 在大 width 下申请临时 work buffer，随后释放。原题借格式串写 hook，再在同一次 `printf` 中用大 width 触发 allocator。

这是旧实现的案例，不是所有 glibc 的稳定接口。必须在目标 `vfprintf` 路径断住 `malloc/free`，还要注意 2.34 起经典 malloc hooks 已经不再由正常分配路径消费。

### 一字节写放大为 stdio 线性覆盖

[GlacierCTF 2023 Write Byte Where](https://ctftime.org/writeup/38299) 的关键不是“任意一字节可直接 RCE”，而是目标恰好允许改写无缓冲 `stdin` 的 `_IO_buf_end`。下一次 `getchar` 仍只返回一个字符，却会先把更多输入填进被扩大的 stdio buffer，从而覆盖相邻标准流对象。

需要同时满足目标对象邻接、输入 refill、可写范围和后续 stdio 消费路径。它应被记录成“受约束写→长度字段→线性覆盖”的实例，而不是固定 `_IO_FILE` offset。

### 一字节写反复改 loader 元数据

[DiceCTF 2022 Nightmare 的替代解](https://github.com/LMS57/Nightmare-Writeup)通过 exit loop 和 partial overwrite，逐步影响 `DT_JMPREL`、`DT_STRTAB`、link map 与 fini 状态。Writeup 明确说明题目对 Docker、libc/ld 和 CPU feature 很敏感，随意 `patchelf` 会改变布局连续性。

可迁移结论是：低带宽写优先找“能产生下一轮写”的循环消费点。具体 dynamic tag 偏移、函数内部 gadget 和 IFUNC 选择都绑定环境。

### x86-64 ret2dlresolve 的 `VERSYM` 距离问题

[redpwnCTF 2021 devnull-as-a-service 作者 Writeup](https://www.tjcsec.club/writeups/redpwnctf-2021-devnull/)说明 resolver 除了 `JMPREL/SYMTAB/STRTAB`，还可能用同一 symbol index 访问 `VERSYM`。当伪表放在离真实表很远的可写区时，不同 entry size 会把 version lookup 推到不可访问位置。

[UMassCTF 2022 zip_parser 复现](https://acad.garywei.dev/blog/2022/ctf-zip-parser/)进一步比较了 pwntools 自动布局和伪造 `link_map` 的办法。结论不是“.bss 固定加 0x800”，而是把每次地址计算、对齐和 version lookup 都实际算出来。

### AArch64 ROP 不是 x86 gadget 表换寄存器名

[Perfect Blue 的 AArch64 ROP Writeup](https://blog.perfect.blue/ROPing-on-Aarch64)强调：`ret` 从 `x30` 取下一 PC，只有能恢复或控制 `x30` 的 epilogue gadget 才容易串链；函数参数走 `x0`～`x7`，一条 gadget 往往同时恢复多组寄存器和 `sp`。

还要单独核对 BTI/PAC、栈对齐、AArch64 syscall ABI 和 instruction cache。跨架构表见 [`ARCHITECTURES_AND_SYSCALLS.md`](./ARCHITECTURES_AND_SYSCALLS.md)。

### 输入是 float，不代表只能表达数值语义

[Facebook CTF 2019 Overfloat](https://ling.re/fbctf-overfloat/)把每个 64 位 ROP qword 拆成两个 32 位 bit pattern，再寻找能由目标 float parser 恢复的十进制文本。这里真正的原语是“文本→IEEE-754 bits→数组越界”，而不是普通 raw-byte 输入。

实战必须让本地生成器与远端 parser 做 round-trip；NaN payload、locale 小数点、舍入模式、`inf` 接受规则和不同 libc 转换实现都可能改变 bits。

### 过滤后的 payload 先求逆像

[SunshineCTF 2018 Rot13](https://ctftime.org/writeup/9549)展示输入先 ROT13、再到格式串 sink；[0CTF 2017 char](https://blog.dragonsector.pl/2017/03/0ctf-2017-char-shellcoding-132.html)则把每个输入 byte 和 gadget 地址都限制到可打印 ASCII。

通用方法是先写出变换 `T(input)=memory_bytes`，再求目标 payload 的 preimage。若没有直接 preimage，就构造小 decoder、在内存中用 add/xor/sub 合成值，或用受限地址上的 gadget 完成第二阶段。

### fork 后的能力可以互补

[Balsn CTF 2021 orxw](https://ctftime.org/writeup/31420)中父子进程拥有不同 seccomp allowlist，同一份栈内容在 fork 两侧被不同方式消费；[Balsn CTF 2022 Asian Parents](https://ctftime.org/writeup/35285)利用 parent 的 ptrace 能力处理 child 的 `SECCOMP_RET_TRACE` 事件。

分析时给每个 actor 单独列 syscall、fd、mapping、可控栈和执行顺序，不能只画一张合并的 allowlist。

### C++ fake vtable 可能还要伪造 RTTI

[Hack.lu CTF 2022 placemat](https://pwner.gg/ctf-writeups/2022-10-30-hacklu-placemat)中程序除了虚调用，还做动态类型相关检查。解法让 fake vtable address point 前方保留兼容 typeinfo，同时把虚函数槽换成另一类的方法。

因此 vptr hijack 的检查单位应是“整条对象消费路径”：RTTI、offset-to-top、thunk、函数槽、`this`、析构和后续 free，而不是只看一条 `call [vptr+off]`。

### 高版本 glibc 的 exit 终点要区分 pointer guard

[glibc 2.35 `tls_dtor_list` 案例](https://tttang.com/archive/1749/)展示 `exit` 调用 TLS destructors 时会 demangle 函数指针。文章把 `fs:0x30` 与 tcache key 混称，迁移时必须纠正：x86-64 glibc 这里使用的是 TLS pointer guard；它与 allocator 的 tcache key 不是同一概念。

[glibc 偏门利用技巧汇总](https://tttang.com/archive/1429/)列出的 `_rtld_global`、`_dl_fini` 和固定偏移只能作为搜索入口。目标是否还可写、字段是否还会被调用、参数是否合适，都要拿附件 Build ID 的 loader 反汇编确认。

### Rust 和自定义 VM 也得落到宿主原语

[redpwnCTF 2020 Rust Pwn](https://www.willsroot.io/2020/06/redpwnctf-2020-rust-pwn-writeups.html)的关键是 unsafe 生命周期错误留下 stale pointer；[bi0sCTF 2025 Uninitialized VM](https://bi0sblog-1271c6.gitlab.io/2025/06/13/Pwn/UninitializedVM-bi0sCTF2025/)则从 VM 状态破坏逐步获得 host read/write。

两者都不应只记成“Rust UAF”或“VM OOB”。可迁移的分析单位是 guest/runtime/host 三层、对象所有权，以及最终被宿主当作 pointer、length、callback 或 syscall 参数的字段。完整检查表见 [`RUNTIME_AND_VM_PWN.md`](./RUNTIME_AND_VM_PWN.md)。

### 布局和原语也可以系统化搜索

[USENIX Security 2018 SHRIKE](https://www.usenix.org/conference/usenixsecurity18/presentation/heelan)把可复用 allocation/free 片段组合起来，按目标邻接关系搜索 heap layout；[USENIX Security 2020 ArcHeap](https://www.usenix.org/conference/usenixsecurity20/presentation/yun)把 allocator 操作、漏洞能力和 arbitrary write/overlap 等结果建模，并最小化找到的 action sequence。

对 CTF 的直接启发是：将菜单操作写成纯函数片段，自动记录 request size、返回对象、释放状态和目标距离；成功后删减无关操作，而不是永久保留靠运气堆出的长脚本。

## 中文资料

| 来源 | 等级 | 适合查什么 | 使用限制 |
|---|---|---|---|
| [跳跳糖：Pwn 基础总结（除堆以外）](https://tttang.com/archive/1361/) | C | 旧式 ROP、PLT/GOT、基础命令入口 | 教程较旧，固定 offset 和 hook 结论须重验 |
| [跳跳糖：glibc 中偏门利用技巧](https://tttang.com/archive/1429/) | B/C | exit、fini、loader 私有目标的检索关键词 | 多处强版本相关，不作为 ABI |
| [跳跳糖：`tls_dtor_list`](https://tttang.com/archive/1749/) | B | glibc 2.35 TLS destructor 消费路径 | pointer guard 与 tcache key 必须区分 |
| [Ex：Balsn CTF 2019 PlainText](https://blog.eonew.cn/2019/10/08/Balsn-CTF-2019-pwn-PlainText----glibc-2.29-off-by-one-pypass/) | B | `setcontext` 入口差异、数据搬运 gadget、ORW | 绑定 glibc 2.29 和题目布局 |
| [arttnba3：Linux x86 用户态环境](https://arttnba3.cn/2024/03/31/PWN-0X03-USERMODE-ENV/) | B | Docker、GDB、插件和基础环境 | 工具命令以安装版本为准 |
| [ph4ntom：ret2dl](https://ph4ntonn.github.io/ret2dl) | B | `VERSYM` 与伪 symbol index 的关系 | 示例绑定特定 glibc/架构 |
| [CTF Wiki：ret2dlresolve](https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86/advanced-rop/ret2dlresolve/) | C | 中文流程和调试入口 | 需回到目标 `_dl_fixup` 验证 |
| [HKCERT CTF Pwn Workshop](https://ctf.hkcert.org/wp-content/uploads/2023/10/HKCERT-CTF-2023-Webinar-02.pdf) | 会议材料 | Stack、ROP、FSOP、ret2dlresolve、seccomp 教学路线 | 属于课程导航，不提供版本保证 |
| [Ltfall：CTF-PWN 做题思路小记](https://ltfa1l.top/2023/12/28/system/tricks/tricks/) | B/C | LLVM Pass、输入失败、fd、fini、ABI、堆与调试题型入口 | 持续更新的题目笔记；固定 offset 和简化因果已在上表纠正 |

## 英文原创博客与 Writeup

| 来源 | 等级 | 主要启发 |
|---|---|---|
| [Dragon Sector：EasiestPrintf](https://blog.dragonsector.pl/2017/03/0ctf-2017-easiestprintf-pwn-150.html) | A/B | 旧 `vfprintf` width 引发 allocator side effect |
| [redpwnCTF Simultaneity](https://ctftime.org/writeup/29251) | B | 数值 `scanf` scratch buffer 的实战触发 |
| [devnull-as-a-service](https://www.tjcsec.club/writeups/redpwnctf-2021-devnull/) | A | ret2dlresolve 的 `VERSYM`、无输出目标和 dynamic tag 路线 |
| [DiceCTF Nightmare 替代解](https://github.com/LMS57/Nightmare-Writeup) | B | 一字节写、exit loop、loader 元数据和环境敏感性 |
| [GlacierCTF Write Byte Where](https://ctftime.org/writeup/38299) | B | `_IO_buf_end` 一字节放大和 stdio refill |
| [Perfect Blue：AArch64 ROP](https://blog.perfect.blue/ROPing-on-Aarch64) | B | `x30`、epilogue gadget 与多阶段 ORW |
| [Hack.lu placemat](https://pwner.gg/ctf-writeups/2022-10-30-hacklu-placemat) | B | fake vtable、typeinfo 与对象连续布局 |
| [Balsn orxw](https://ctftime.org/writeup/31420) | B | fork 两侧 seccomp 能力拆分 |
| [Balsn Asian Parents](https://ctftime.org/writeup/35285) | B | ptrace 与 `SECCOMP_RET_TRACE` 协作 |
| [Facebook CTF Overfloat](https://ling.re/fbctf-overfloat/) | B | float 文本承载精确 ROP bits |
| [0CTF char](https://blog.dragonsector.pl/2017/03/0ctf-2017-char-shellcoding-132.html) | A/B | printable-address ROP、代数合成和第二阶段 |
| [SkullSecurity：base64/alphanumeric shellcode](https://www.skullsecurity.org/2017/solving-b-64-b-tuff-writing-base64-and-alphanumeric-shellcode) | B | 自修改 decoder 与编码约束 |
| [DUCTF 2023 onebyte](https://halcyondream.org/2023/09/19/onebyte-writeup.html) | B | saved return address 低字节覆盖 |
| [UMassCTF zip_parser](https://acad.garywei.dev/blog/2022/ctf-zip-parser/) | B | x86-64 ret2dlresolve 远距离伪表和 fake link map |
| [Faraz：Lazyhouse exploit analysis](https://faraz.faith/2019-10-24-hitconctf-lazyhouse-balsn-exploit-analysis/) | B | heap 上 staging ROP、pivot 与 ORW |
| [redpwnCTF 2020 Rust Pwn](https://www.willsroot.io/2020/06/redpwnctf-2020-rust-pwn-writeups.html) | B | unsafe 生命周期错误、stale pointer 与 UAF 原语 |
| [bi0sCTF 2025 Uninitialized VM](https://bi0sblog-1271c6.gitlab.io/2025/06/13/Pwn/UninitializedVM-bi0sCTF2025/) | A/B | VM stack 状态破坏到 host 任意读写 |
| [Rusty CodePad](https://ctftime.org/writeup/11911) | B | Rust 编译环境、symbol export 与文件能力边界 |
| [nobodyisnobody Writeup 总库](https://github.com/nobodyisnobody/write-ups) | B/C | ptrace、seccomp、FixedASLR、stdio、跨平台题目入口 |
| [Perfect Blue Writeup 总库](https://github.com/perfectblue/ctf-writeups) | B/C | 多届比赛附件、脚本和解题路线 |

## 会议论文与演讲材料

| 材料 | 严格前提或方法论 |
|---|---|
| [Black Hat Asia 2018 return-to-csu](https://i.blackhat.com/briefings/asia/2018/asia-18-Marco-return-to-csu-a-new-method-to-bypass-the-64-bit-Linux-ASLR.pdf) | 利用启动代码里的寄存器恢复与间接调用序列；当前二进制未必还生成经典 gadget |
| [Black Hat USA 2010 Payload Already Inside](https://media.blackhat.com/bh-us-10/whitepapers/Le/BlackHat-USA-2010-Le-Paper-Payload-already-inside-data-reuse-for-ROP-exploits-wp.pdf) | 从现有代码和数据组合调用，不把 gadget 当成无副作用指令 |
| [Blind Format String Attacks](https://eudl.eu/pdf/10.1007/978-3-319-23802-9_23) | 无回显和 heap-resident format string 下建立 oracle/写原语 |
| [BROP](https://www.scs.stanford.edu/~dm/home/papers/bittau%3Abrop.pdf) | crash 后同一映像可重复尝试，并能区分 stop/crash 行为 |
| [SROP](https://www.cs.vu.nl/~herbertb/papers/srop_sp14.pdf) | 控制 signal frame、sigreturn 入口和目标架构 kernel ABI |
| [COOP](https://informatik.rub.de/veroeffentlichungenbkp/syssec/veroeffentlichungen/2015/pdfs/2015_Counterfeit_Object_oriented_Programming__On_the_Difficulty_of_Preventing_Code_Reuse_Attacks_in_C%2B%2B_Applications.pdf) | 伪对象沿合法 virtual call sites 调度整函数 |
| [Jump-oriented Programming](https://doi.org/10.1145/1966913.1966919) | 需要 dispatcher 与可串联的 indirect-jump gadgets |
| [Data-Oriented Programming](https://ieeexplore.ieee.org/document/7546545) | 不劫持控制流，组合对业务数据和状态的读写 |
| [Block Oriented Programming](https://arxiv.org/abs/1805.04767) | 以任意写改变状态，沿合法 CFG 使用 basic blocks 完成数据流 payload |
| [SHRIKE](https://www.usenix.org/conference/usenixsecurity18/presentation/heelan) | 将 heap interaction fragments 组合并搜索目标布局 |
| [ArcHeap](https://www.usenix.org/conference/usenixsecurity20/presentation/yun) | 对 allocator action、漏洞能力和输出原语建模并最小化 PoC |
| [Play with FILE Structure](https://www.slideshare.net/slideshow/play-with-file-structure-yet-another-binary-exploit-technique/81635564) | 从 FILE 状态机与 vtable 消费点推导 FSOP；具体结构按版本重建 |

## 没有直接收入通用正文的说法

- “某 libc 版本的 one-gadget offset”：只保留约束求解思路，不保存地址。
- “Full RELRO 就一定没有 loader 利用面”：RELRO 只回答相应 mapping/relocation 时机，还得分析实际 resolver 和可写目标。
- “同一 glibc 大版本就能复用”：发行版回移、Build ID、ld、CPU HWCAP/IFUNC 都可能改变路径。
- “`fs:0x30` 就是 tcache key”：在 x86-64 glibc pointer mangling 语境中它是 pointer guard，不能混用名称。
- “任意大 width/token 必然整理 bins”：是否分配、扩容、释放、合并和 sorting 取决于对应源码与当时堆状态。
- “ptrace 或 seccomp 有一个 syscall 漏洞就能通用绕过”：只有目标 filter/tracer 状态机确实留下这个能力时才成立。
- 没有附件、源码、关键反汇编或可复现实验的短帖，只作为搜索线索，不进入版本矩阵。

## 以后继续维护

新增 Writeup 时先回答：

1. 是不是题目作者或实际参赛者的原文？附件和 exploit 还拿不拿得到？
2. 新信息是漏洞根因、放大器、最终触发点，还是只有一组固定 offset？
3. 能否用一个最小实验把博客结论与目标 libc/ld/架构分开验证？
4. 与现有专题重复时，应把严格条件补进原专题，而不是再建一份散乱笔记。
5. 资料若只覆盖 Kernel Pwn，本轮索引不收录。
