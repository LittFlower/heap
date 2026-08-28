# 互联网一手资料索引

本索引记录本轮扩充使用的上游规范、官方文档、项目仓库与原始论文，检索日期为 **2026-08-28**。正文已把常用结论整理成现场检查项；遇到实现细节、版本边界或非 x86-64 目标时，从这里回到原文。

## 采用口径

- ABI、ELF、指令与 syscall：优先架构组织规范、System V psABI、Linux kernel/man-pages。
- 编译器、linker、libc、debugger：优先 GCC、LLVM、GNU binutils、glibc、GDB 官方手册。
- 工具行为：优先 pwntools、AFL++、Pwndbg、checksec 自身文档/源码。
- 攻击方法：优先作者主页、论文 PDF 或出版 DOI；博客只用于发现关键词，不作为跨版本结论来源。
- 当前仓库的 glibc heap 版本结论还是以对应 tag 源码、提交和动态回归为准，不由泛化教程覆盖。

中英文博客、CTF Writeup 和会议材料单独按证据强度整理在 [`BLOG_WRITEUPS_AND_TALKS.md`](./BLOG_WRITEUPS_AND_TALKS.md)。本页继续只维护规范、上游项目文档和原始研究入口，避免把实现事实与题目特例混成同一层。

## ELF、linker 与 glibc loader

| 来源 | 主要用途 |
|---|---|
| [AMD64 psABI draft 0.98](https://refspecs.linuxfoundation.org/elf/x86_64-abi-0.98.pdf) | x86-64 calling convention、ELF relocation、GOT/PLT、TLS |
| [GNU Binary Utilities](https://sourceware.org/binutils/docs/binutils.html) | `readelf`、`objdump`、`nm`、`objcopy` 的真实选项和输出边界 |
| [GNU ld](https://sourceware.org/binutils/docs/ld/index.html) | linker script、PIE、`-z relro/now/noexecstack`、property notes |
| [glibc Dynamic Linker](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker.html) | loader invocation、环境变量、introspection、IFUNC 与 hardening |
| [glibc loader 环境变量](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Environment-Variables.html) | `LD_DEBUG` 的 libs/reloc/symbols/bindings/versions 等类别 |
| [glibc Auxiliary Vector](https://sourceware.org/glibc/manual/latest/html_node/Auxiliary-Vector.html) | `getauxval`、HWCAP 与 `AT_*` 的接口边界 |
| [Linux `ld.so(8)`](https://man7.org/linux/man-pages/man8/ld.so.8.html) | 搜索顺序、`$ORIGIN`、secure-execution、`--library-path/--list-diagnostics` |

glibc 手册提供各发行版页面；研究旧版本行为时，应切换到匹配版本的页面，不要默认用 latest 页面解释旧附件：[glibc manuals](https://sourceware.org/glibc/manual/)。

## 编译保护与运行时

| 来源 | 主要用途 |
|---|---|
| [GCC instrumentation options](https://gcc.gnu.org/onlinedocs/gcc/Instrumentation-Options.html) | stack protector、stack clash、CF protection、sanitizer coverage |
| [GNU ld options](https://sourceware.org/binutils/docs/ld/Options.html) | `PT_GNU_RELRO`、NOW、GNU_STACK、IBT/SHSTK property 生成条件 |
| [Linux ASLR sysctl](https://docs.kernel.org/admin-guide/sysctl/kernel.html#randomize-va-space) | `randomize_va_space` 的 0/1/2 语义 |
| [Linux x86 shadow stack](https://www.kernel.org/doc/html/next/x86/shstk.html) | 用户态 SHSTK 的硬件、kernel、ELF note 与 loader 条件 |
| [Intel SDM](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html) | CET、ENDBRANCH、shadow stack 与 x86 指令语义 |
| [Linux AArch64 pointer authentication](https://www.kernel.org/doc/html/latest/arch/arm64/pointer-authentication.html) | PAC 暴露、keys 与 ptrace regset |
| [Linux AArch64 tagged address ABI](https://www.kernel.org/doc/html/latest/arch/arm64/tagged-address-abi.html) | tagged pointer 传 syscall 的启用方式与例外 |
| [checksec 官方文档](https://github.com/slimm609/checksec/blob/main/docs/index.md) | 工具检查项和输出含义；结论最后还是用 ELF/运行时事实复核 |

## 架构与 syscall ABI

| 来源 | 主要用途 |
|---|---|
| [Linux `syscall(2)`](https://man7.org/linux/man-pages/man2/syscall.2.html) | 多架构 syscall 指令、number、参数和返回寄存器表 |
| [Arm ABI specifications](https://github.com/ARM-software/abi-aa) | AAPCS32/64、AAELF、BTI、PAC、GCS 等 ABI 文档 |
| [RISC-V ELF psABI](https://github.com/riscv-non-isa/riscv-elf-psabi-doc) | calling convention、ELF、DWARF、relocation 与 relaxation |
| [GNU objdump](https://sourceware.org/binutils/docs/binutils/objdump.html) | architecture/endian/disassembler options 和 raw mnemonic |
| [glibc System Calls](https://sourceware.org/glibc/manual/latest/html_node/System-Calls.html) | libc wrapper 与通用 `syscall()` 的差异和限制 |

MIPS、PowerPC 等 ABI 变体很多。遇到目标时以 ELF flags、目标 sysroot headers 和对应工具链文档为准，不从一张通用寄存器表猜 o32/n32/n64。

## LLVM Pass 与编译器宿主

| 来源 | 主要用途 |
|---|---|
| [LLVM `opt` command guide](https://llvm.org/docs/CommandGuide/opt.html) | IR/bitcode 输入、`-load`、pass 列表与验证选项 |
| [LLVM New Pass Manager](https://llvm.org/docs/NewPassManager.html) | Legacy/New PM 状态、`-load-pass-plugin` 与 pipeline 语法 |
| [Writing an LLVM Pass](https://llvm.org/docs/WritingAnLLVMNewPMPass.html) | New PM plugin 注册入口和 callback 结构 |
| [Legacy Pass Manager guide](https://llvm.org/docs/WritingAnLLVMPass.html) | `RegisterPass`、legacy pass 类型与依赖关系 |

## Linux 进程、signal 与 seccomp

| 来源 | 主要用途 |
|---|---|
| [Linux seccomp filter](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html) | BPF 返回动作、架构检查、过滤语义 |
| [Linux `seccomp(2)`](https://man7.org/linux/man-pages/man2/seccomp.2.html) | filter 安装条件、flags、action 与 USER_NOTIF 接口 |
| [`proc_pid_maps(5)`](https://man7.org/linux/man-pages/man5/proc_pid_maps.5.html) | maps 字段、权限和 ptrace access check |
| [`ptrace(2)`](https://man7.org/linux/man-pages/man2/ptrace.2.html) | attach、Yama、访问权限和事件 |
| [`process_vm_readv(2)`](https://man7.org/linux/man-pages/man2/process_vm_readv.2.html) | 跨进程读写、partial transfer 与权限 |
| [`sigreturn(2)`](https://man7.org/linux/man-pages/man2/sigreturn.2.html) | signal frame、trampoline、寄存器恢复与架构差异 |
| [`signal(7)`](https://man7.org/linux/man-pages/man7/signal.7.html) | signal delivery、mask、frame 和系统调用重启 |
| [`memfd_create(2)`](https://man7.org/linux/man-pages/man2/memfd_create.2.html) | 匿名文件、fd 继承、mapping 与 sealing |

## Linux Kernel Pwn 与动态检测

| 来源 | 主要用途 |
|---|---|
| [Kernel Self-Protection](https://www.kernel.org/doc/html/latest/security/self-protection.html) | KASLR、strict permissions、SMEP/SMAP、PXN/PAN、stack protection 的设计目标 |
| [userfaultfd](https://www.kernel.org/doc/html/latest/admin-guide/mm/userfaultfd.html) | page-fault 控制、feature negotiation 与 unprivileged 限制 |
| [Kernel development tools](https://www.kernel.org/doc/html/latest/dev-tools/index.html) | KASAN/KFENCE/KMSAN/KCSAN、gdb、testing 总入口 |
| [KASAN](https://www.kernel.org/doc/html/latest/dev-tools/kasan.html) | kernel OOB/UAF 的 allocation/free/access 报告 |
| [KFENCE](https://www.kernel.org/doc/html/latest/dev-tools/kfence.html) | 低开销抽样 heap error detection |
| [KMSAN](https://www.kernel.org/doc/html/latest/dev-tools/kmsan.html) | kernel uninitialized value 和 origin tracking |
| [KCSAN](https://www.kernel.org/doc/html/latest/dev-tools/kcsan.html) | data race 的抽样 watchpoint 检测 |

## GDB 与复现

| 来源 | 主要用途 |
|---|---|
| [GDB manual](https://sourceware.org/gdb/current/onlinedocs/gdb.html/) | 当前 GDB 的完整事实源 |
| [Starting / ASLR](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Starting.html) | `set disable-randomization` 的默认行为 |
| [Forks](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Forks.html) | follow-fork-mode、detach-on-fork 与 inferiors |
| [Catchpoints](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Set-Catchpoints.html) | syscall、signal、fork、exec、load/unload 断点 |
| [Watchpoints](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Set-Watchpoints.html) | hardware/software watchpoint 的能力和限制 |
| [Record and replay](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Process-Record-and-Replay.html) | `record full/btrace` 与 reverse execution |
| [Core generation](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Core-File-Generation.html) | `gcore`、coredump filter 与 excluded mappings |

## pwntools 与 exploit 辅助

| 来源 | 主要用途 |
|---|---|
| [pwntools documentation](https://docs.pwntools.com/en/stable/) | tubes、ELF、ROP、corefile、shellcraft 等接口 |
| [pwntools Corefile](https://docs.pwntools.com/en/stable/elf/corefile.html) | core maps/registers 与 cyclic offset 自动化 |
| [pwntools ROP](https://docs.pwntools.com/en/stable/rop/rop.html) | gadget 搜索、ROP dump、SROP/ret2csu 支持 |
| [pwntools ret2dlresolve](https://docs.pwntools.com/en/stable/rop/ret2dlresolve.html) | `Ret2dlresolvePayload` 参数、payload 和限制 |
| [pwntools DynELF](https://docs.pwntools.com/en/stable/dynelf.html) | 用任意地址泄漏解析已加载 ELF symbol |
| [Pwndbg repository](https://github.com/pwndbg/pwndbg) | 命令以安装版本 `help` 和对应源码为准 |

## Sanitizer 与 fuzzing

| 来源 | 主要用途 |
|---|---|
| [Clang AddressSanitizer](https://clang.llvm.org/docs/AddressSanitizer.html) | ASan 构建、报告、symbolization 与限制 |
| [Clang UBSan](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html) | integer/alignment/shift 等 UB 检查 |
| [LLVM libFuzzer](https://llvm.org/docs/LibFuzzer.html) | harness、corpus、merge、artifact 与运行限制 |
| [Clang SanitizerCoverage](https://clang.llvm.org/docs/SanitizerCoverage.html) | coverage callback、trace-cmp 等插桩 |
| [AFL++ repository](https://github.com/AFLplusplus/AFLplusplus) | compiler/QEMU/Frida/Unicorn mode、CmpLog、persistent mode |
| [Valgrind manual](https://valgrind.org/docs/manual/manual.html) | Memcheck 等动态分析工具的报告语义 |

## 攻击方法原始资料

| 来源 | 可提炼的严格前提 |
|---|---|
| [Hacking Blind / BROP](https://www.scs.stanford.edu/~dm/home/papers/bittau%3Abrop.pdf) | 无附件远程探测要求 crash 后服务可反复尝试且地址布局保持 |
| [Stanford BROP 项目页](https://www.scs.stanford.edu/brop/) | stop gadget、BROP gadget、write 与导出 ELF 的原始流程 |
| [Sigreturn-oriented Programming](https://www.cs.vu.nl/~herbertb/papers/srop_sp14.pdf) | 利用 signal frame 恢复完整 machine context，布局和 syscall 都看架构 |
| [COOP 原始论文](https://informatik.rub.de/veroeffentlichungenbkp/syssec/veroeffentlichungen/2015/pdfs/2015_Counterfeit_Object_oriented_Programming__On_the_Difficulty_of_Preventing_Code_Reuse_Attacks_in_C%2B%2B_Applications.pdf) | 伪造 C++ 对象并沿合法虚调用 sites 复用整函数 |
| [Jump-oriented Programming DOI](https://doi.org/10.1145/1966913.1966919) | 不依赖 `ret` 的 dispatcher/gadget 代码复用模型 |

论文说明攻击模型，不保证今天某个 loader、kernel 或硬件组合还能按示例工作。迁移到题目时还得回到当前附件的消费路径和运行时保护。

## 协议与 C++

| 来源 | 主要用途 |
|---|---|
| [protobuf-c repository](https://github.com/protobuf-c/protobuf-c) | 生成代码、runtime API 与版本 |
| [protobuf-c header](https://github.com/protobuf-c/protobuf-c/blob/master/protobuf-c/protobuf-c.h) | message/field/enum descriptor 的目标版本布局 |
| [Itanium C++ ABI](https://itanium-cxx-abi.github.io/cxx-abi/abi.html) | GCC/Clang 常用 C++ ABI 的 vtable、RTTI、member pointer、exception 基础 |
| [Arm C++ ABI](https://github.com/ARM-software/abi-aa/tree/main/cppabi64) | AArch64 平台对 C++ ABI 的补充 |

标准库容器对象布局还是实现细节。要同时绑定 libstdc++/libc++ 版本、编译 ABI 和目标反汇编，不能只读语言 ABI 文档。

## 维护方式

1. 外部页面发生版本漂移时，在正文标出读取版本或提交，不把“latest”结论倒灌到旧附件。
2. 技巧若依赖固定 offset，必须补附件 hash/Build ID 和推导命令。
3. 工具自动化输出与手工 ELF/运行时验证冲突时，以目标 bytes、loader/kernel 行为为准，并记录工具版本。
4. 新资料先归入现有专题；只有出现独立检索维度时才新增 Markdown，避免再次变成散乱链接库。
