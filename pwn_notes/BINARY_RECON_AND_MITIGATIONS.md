# ELF 体检与保护机制

`checksec` 适合快速提示，但保护状态不是一个布尔总开关。本篇给出如何从 ELF 自身和运行时验证 PIE、NX、RELRO、canary、FORTIFY、CET、BTI/PAC 等条件，以及它们对利用路线真正改变了什么。

## 一次性采集

```bash
file ./chall
sha256sum ./chall

readelf -hW ./chall
readelf -lW ./chall
readelf -SW ./chall
readelf -dW ./chall
readelf -nW ./chall
readelf -sW ./chall
readelf -rW ./chall
readelf -VW ./chall

objdump -drwC -Mintel ./chall > chall.disasm
objdump -RwT ./chall > chall.dynamic.txt
```

先读 program headers，因为 loader 映射的是 segment，不是 section。section header 对链接和逆向很方便，但运行时权限、文件偏移和虚拟地址要看 `PT_LOAD` 等 program header。

## 基本身份

| 检查 | ELF 证据 | 意义 |
|---|---|---|
| 架构/位数/端序 | ELF header 的 Class、Data、Machine | 决定指针宽度、指令编码、ABI 和 syscall |
| 可执行类型 | `e_type`：`ET_EXEC`/`ET_DYN` | PIE 通常表现为可执行的 `ET_DYN`，共享库也是 `ET_DYN`，还要结合入口和 dynamic 信息 |
| interpreter | `PT_INTERP` | 内核加载哪个动态加载器 |
| Build ID | `.note.gnu.build-id` | 给二进制/DSO 绑定唯一构建线索；偏移应附带它 |
| 动态依赖 | `DT_NEEDED`、RPATH/RUNPATH | 决定依赖和搜索顺序 |
| stripped | 是否还有 `.symtab` | 去除静态符号不等于没有 `.dynsym`、relocation 或 unwind 信息 |

```bash
readelf -lW ./chall | rg 'INTERP|LOAD|GNU_STACK|GNU_RELRO'
readelf -nW ./chall | rg -A4 'Build ID|GNU_PROPERTY'
readelf -dW ./chall | rg 'NEEDED|RPATH|RUNPATH|BIND_NOW|FLAGS'
```

## PIE 与 ASLR

- PIE 让主程序像共享对象一样可重定位；通常要先泄漏主程序地址，才能用它的绝对地址。
- ASLR 是运行时地址随机化策略；PIE 是二进制是否可重定位的构建属性。两者不能混成一个开关。
- 非 PIE 主程序的 text/data 常保持固定地址，但 stack、heap、mmap、共享库和 vDSO 还会随机化。
- Linux `randomize_va_space=1` 随机化 mmap base、stack、vDSO 和 PIE code；值 2 进一步随机化 brk heap。发行版与架构的具体熵不能从这个值直接推断。
- GDB 在 GNU/Linux 上通常默认关闭被启动进程的随机化；真实复现使用：

```gdb
set disable-randomization off
run
```

运行时确认：

```bash
for i in 1 2 3; do ./chall & pid=$!; head -n 8 /proc/$pid/maps; kill "$pid"; done
```

如果进程退出太快，在题目正常等待点查看，或在 GDB 使用 `info proc mappings`。读取其他进程 maps 会受 ptrace 权限检查约束。

## NX / W^X

- `PT_GNU_STACK` 没有 executable flag，通常表示主线程栈不要求执行；手写汇编缺少 `.note.GNU-stack` 时，链接器的默认行为可能与目标有关。
- NX 不表示进程中绝无可执行可写页。JIT、自定义 `mmap`、驱动共享区或后续 `mprotect` 都要看运行时 maps 和程序行为。
- 有 `RWX` segment 是强信号，但 section flag 还要映射回 `PT_LOAD` 才能判断真实页权限。
- NX 阻止直接在不可执行数据页运行 shellcode，不阻止 ret2libc/ROP，也不阻止程序自己把页改成可执行，前提是 syscall/沙盒允许。

```bash
readelf -lW ./chall | rg 'GNU_STACK|LOAD'
# 运行后
cat /proc/$pid/maps
```

## Stack canary

常见证据是函数 prologue 从 TLS 读取 guard，epilogue 比较后调用 `__stack_chk_fail`。但只看到动态符号不代表每个函数都受保护。

- `-fstack-protector`、`-strong`、`-all` 的覆盖范围不同。
- canary 保护的是选中函数从进入到正常返回间的栈破坏检测，不保护任意 heap/global OOB。
- 不经过受保护 epilogue 的控制流、先泄漏后原样回填、非返回控制数据和逻辑漏洞需要分别分析。
- fork 产生的子进程通常继承现有地址空间状态；canary 是否能跨连接复用取决于服务是否在同一父进程 fork，需实测。

```bash
readelf -sW ./chall | rg '__stack_chk_fail|__stack_chk_guard'
objdump -drwC -Mintel ./chall | rg -n 'fs:|stack_chk'
```

### 绕过路线按消费点分类

| 路线 | 硬条件 | 容易忽略的失败点 |
|---|---|---|
| 泄漏并回填 | 能读出目标线程 guard，覆盖时保留完整值 | 字符串泄漏被 NUL 截断、泄漏与触发不在同一线程 |
| fork oracle 逐 byte 猜测 | worker 由同一已初始化父进程 fork，崩溃可区分且不会 exec | rate limit、负载均衡、父进程重启、错误判据污染后续 byte |
| 改 `__stack_chk_fail` 调用目标 | 对应 GOT/调用槽可写，失败路径必达且目标 ABI 可用 | Full RELRO、FORTIFY wrapper、目标返回后栈已经损坏 |
| 改 TLS `stack_guard` | 能在受保护 epilogue 前写到当前线程 TLS，且知道保存值如何配合 | TLS/stack 相对布局不是 ABI、其他活跃 frame 还保存旧 guard |
| 避开 epilogue | 能从 signal、exception、longjmp、回调或数据流路径结束目标 | 不代表任意异常退出都会跳过清理或检查 |

“子进程 canary 一样”只适用于继承同一地址空间状态的进程模型；“超长栈溢出能碰到 TLS”也只属于特定线程栈映射布局。[Ltfall 的 canary 技巧汇总](https://ltfa1l.top/2023/12/28/system/tricks/tricks/)可作为候选路线索引，最终应分别在 parent/worker/thread 上读取 maps、TLS base 和 guard 消费指令验证。

## RELRO

`PT_GNU_RELRO` 表示 relocation 后应改成只读的一段；`BIND_NOW`/`DF_1_NOW` 要求启动时完成动态符号解析。

| 状态 | 常见 ELF 组合 | 利用影响 |
|---|---|---|
| 无 RELRO | 没有 `PT_GNU_RELRO` | GOT 等区域可能保持可写，还得看实际映射 |
| Partial RELRO | 有 `PT_GNU_RELRO`，未要求 NOW | `.got.plt` 常需保留 lazy binding 写入能力 |
| Full RELRO | 有 `PT_GNU_RELRO`，并要求 NOW | relocation 后相关 GOT 位于只读页，直接 GOT overwrite 通常不可用 |

不要把 Full RELRO 写成“所有函数指针只读”。程序自己的 `.data`/heap callback、C++ object、exit handler、loader 私有数据是否可写要分别确认。

```bash
readelf -lW ./chall | rg 'GNU_RELRO'
readelf -dW ./chall | rg 'BIND_NOW|FLAGS.*NOW'
```

## FORTIFY_SOURCE

FORTIFY 依赖编译优化、可推导的对象大小和被替换函数。看到 `__read_chk`、`__memcpy_chk`、`__sprintf_chk` 等符号说明某些调用被强化，不说明所有边界错误都被覆盖。

```bash
readelf -sW ./chall | rg '__.*_chk|__fortify_fail'
objdump -T ./chall | rg '__.*_chk|__fortify_fail'
```

逆向时要看额外传入的 object size、运行时检查条件和最终调用；不要只因为存在一个 `_chk` 符号就跳过相邻未强化的调用点。

## x86 CET：IBT 与 SHSTK

ELF 的 `.note.gnu.property` 可以声明 IBT/SHSTK 兼容，但“存在标记”“CPU 支持”“内核支持”“loader 实际启用”是四件不同的事。

- IBT 要求受保护的间接 `call`/`jmp` 落到合法 `ENDBRANCH` 目标；它不直接验证 `ret`。
- SHSTK 用独立 shadow stack 校验返回地址，主要打击传统 ret 链。
- Linux 用户态 SHSTK 需要硬件、内核配置、用户库和 loader 协作。仅凭 `endbr64` 或 property note 不能确认运行中已启用。

```bash
readelf -nW ./chall | rg -i 'IBT|SHSTK|x86 feature'
rg -w 'user_shstk|ibt' /proc/cpuinfo
```

若题目涉及 CET，记录所有 DSO 的 property、实际内核和 glibc tunable；不要假设宿主机与远端启用状态相同。

## AArch64 BTI、PAC 与 tagged pointer

- BTI 限制部分间接分支目标，ELF property 与 loader 映射时的 `PROT_BTI` 都参与生效。
- PAC 给指针附加认证码；保护哪些 code/data pointer、使用哪个 key/modifier 取决于编译方案和 ABI，看到 `paciasp` 不能推导所有指针都受保护。
- TBI 允许用户态地址的 top byte 在部分场景作为 tag，但传入 syscall 的 tagged pointer 受 Linux Tagged Address ABI 限制；不是任意带 tag 指针都被内核接受。

```bash
readelf -nW ./chall | rg -i 'AArch64|BTI|PAC|GCS'
objdump -drwC ./chall | rg 'bti|paci|auti|retab'
```

## 运行时确认页权限和辅助向量

```gdb
info proc mappings
info auxv
maintenance info sections ALLOBJ
```

```bash
cat /proc/$pid/maps
cat /proc/$pid/smaps_rollup
LD_SHOW_AUXV=1 ./chall
```

auxv 可提供 program headers、page size、vDSO、随机数据、硬件能力和 `AT_SECURE` 等启动信息。具体 `AT_*` 含义按目标 libc/kernel headers 核对；不要把本机 auxv 地址写进 exploit。

## 从保护状态回到利用原语

| 保护 | 它直接限制什么 | 接下来问什么 |
|---|---|---|
| PIE/ASLR | 绝对地址可预测性 | 有哪类信息泄漏、低位是否稳定、进程是否重启重随机？ |
| NX | 数据页执行 | 能否复用代码、调用 syscall、改变页权限或找到合法 RX buffer？ |
| Canary | 选中函数返回前的栈破坏 | 能否泄漏/保留、是否可改非返回数据、是否能避开 epilogue？ |
| Full RELRO | relocation 后 RELRO 页写入 | 还有哪些真实可写且会被消费的 data pointer/state？ |
| IBT/BTI | 部分间接分支目标 | 目标是否有 landing pad，调用点检查的是哪类分支？ |
| SHSTK | `call`/`ret` 配对 | 是否存在非 ret 控制流、数据流目标或合法调用路径？ |
| PAC | 被签名指针完整性 | 哪类指针被签、modifier 来源、能否复用已签名值？ |

保护只删掉某些边，不会自动消除漏洞。最后还是按 [`FIELD_WORKFLOW.md`](./FIELD_WORKFLOW.md) 的原语账本选择路线。

## 上游依据

- [GNU ld 的 `-z relro/now/noexecstack/shstk` 选项](https://sourceware.org/binutils/docs/ld/Options.html)
- [GCC instrumentation 与 control-flow protection](https://gcc.gnu.org/onlinedocs/gcc/Instrumentation-Options.html)
- [Linux `randomize_va_space`](https://docs.kernel.org/admin-guide/sysctl/kernel.html#randomize-va-space)
- [GDB 启动与 `disable-randomization`](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Starting.html)
- [Linux x86 用户态 shadow stack](https://www.kernel.org/doc/html/next/x86/shstk.html)
- [Arm ABI 规范仓库](https://github.com/ARM-software/abi-aa)
- [Linux AArch64 Tagged Address ABI](https://www.kernel.org/doc/html/latest/arch/arm64/tagged-address-abi.html)
