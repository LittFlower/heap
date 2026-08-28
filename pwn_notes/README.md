# 非堆 Pwn 笔记索引

这一目录整理父目录长期积累的零散 Pwn 笔记，并用上游规范、官方文档、项目源码、原创博客、Writeup 和会议材料补齐 ELF 体检、保护机制、动态链接、内存破坏、跨架构和 fuzzing。它不重复当前仓库已经重构完成的 60 个堆手法。

## 怎么用

拿到题目后按利用阶段检索，不要从头顺读：

1. 第一次做题按 [`FIELD_WORKFLOW.md`](./FIELD_WORKFLOW.md) 建立事实表和原语账本。
2. 用 [`BINARY_RECON_AND_MITIGATIONS.md`](./BINARY_RECON_AND_MITIGATIONS.md) 和 [`ELF_LINKING_AND_RELOCATION.md`](./ELF_LINKING_AND_RELOCATION.md) 核对 ELF、保护、loader 与 relocation。
3. 用 [`INPUT_AND_IO.md`](./INPUT_AND_IO.md) 确认输入函数的终止、补零、缓冲和隐式分配行为。
4. 用 [`MEMORY_CORRUPTION_AND_STRATEGY.md`](./MEMORY_CORRUPTION_AND_STRATEGY.md) 把根因升级成原语，再用 [`ABI_ROP_AND_STACK.md`](./ABI_ROP_AND_STACK.md) 核对调用约定、ROP、栈迁移和 SROP。
5. 从 [`EXPLOIT_SCRIPTING.md`](./EXPLOIT_SCRIPTING.md) 取干净的 pwntools 骨架；崩溃定位和 fuzzing 查 [`FUZZING_AND_CRASH_TRIAGE.md`](./FUZZING_AND_CRASH_TRIAGE.md)。
6. 格式化字符串、seccomp、C++、Rust/VM、Kernel、Protobuf 等专题入口见下表；博客二手材料从专门索引反查。

```bash
# 从整个仓库按能力或现象检索
rg -n -i 'partial overwrite|stack pivot|scanf|seccomp|protobuf' -g '*.md'

# 堆题还是先按输入/输出原语筛选
rg -n 'double free|UAF|任意写|off.by.null' PRIMITIVE_REQUIREMENTS_MATRIX.md
```

## 专题导航

| 专题 | 内容 |
|---|---|
| [`FIELD_WORKFLOW.md`](./FIELD_WORKFLOW.md) | 从附件体检、漏洞事实表、原语账本到远端稳定性的完整现场流程 |
| [`BINARY_RECON_AND_MITIGATIONS.md`](./BINARY_RECON_AND_MITIGATIONS.md) | ELF segment、PIE/ASLR、NX、RELRO、canary、FORTIFY、CET、BTI/PAC |
| [`ELF_LINKING_AND_RELOCATION.md`](./ELF_LINKING_AND_RELOCATION.md) | load bias、dynamic symbol、relocation、PLT/GOT、IFUNC、ret2dlresolve、DynELF/BROP |
| [`MEMORY_CORRUPTION_AND_STRATEGY.md`](./MEMORY_CORRUPTION_AND_STRATEGY.md) | 整数、OOB、UAF、stack、race 的原语升级与控制流/data-only 路线 |
| [`ARCHITECTURES_AND_SYSCALLS.md`](./ARCHITECTURES_AND_SYSCALLS.md) | x86、Arm、AArch64、MIPS、RISC-V 调用约定、syscall、端序与 QEMU |
| [`FUZZING_AND_CRASH_TRIAGE.md`](./FUZZING_AND_CRASH_TRIAGE.md) | ASan/UBSan、libFuzzer、AFL++、corpus、core dump 与首次破坏定位 |
| [`INPUT_AND_IO.md`](./INPUT_AND_IO.md) | `read`/stdio/字符串函数边界、转换失败、EOF、缓冲与数值 scanf 的隐藏堆操作 |
| [`DEBUGGING_AND_ENVIRONMENT.md`](./DEBUGGING_AND_ENVIRONMENT.md) | GDB、Pwndbg/Pwngdb、gdbserver、QEMU、Docker、Build ID 复现 |
| [`ABI_ROP_AND_STACK.md`](./ABI_ROP_AND_STACK.md) | x86 条件跳转、i386/amd64 ABI、ROP、pivot、ret2csu、SROP |
| [`FORMAT_STRING.md`](./FORMAT_STRING.md) | 泄漏、`%n` 写、参数索引、分阶段指针改写 |
| [`SANDBOX_AND_SHELL.md`](./SANDBOX_AND_SHELL.md) | seccomp 判断、ORW、fd 拓扑、命令过滤、ptrace 题型与侧信道 |
| [`EXPLOIT_SCRIPTING.md`](./EXPLOIT_SCRIPTING.md) | pwntools 启动、收发、泄漏、菜单、重试与 safe-linking 工具 |
| [`SHELLCODE.md`](./SHELLCODE.md) | shellcode 生成、坏字符、C 转裸 `.text` 与 relocation 检查 |
| [`LIBC_AND_LOADER.md`](./LIBC_AND_LOADER.md) | glibc/loader 识别、stdio/exit、延迟绑定与构建相关技巧 |
| [`CPP_REVERSE.md`](./CPP_REVERSE.md) | libstdc++ 容器、SSO、shared_ptr、iostream 与异常展开识别 |
| [`RUNTIME_AND_VM_PWN.md`](./RUNTIME_AND_VM_PWN.md) | Rust unsafe/FFI、自定义 VM、GC 与 guest→host 原语升级 |
| [`LLVM_PASS_PWN.md`](./LLVM_PASS_PWN.md) | LLVM IR/bitcode + `opt` pass plugin：工具链匹配、注册入口恢复与调试 |
| [`KERNEL_PWN.md`](./KERNEL_PWN.md) | 模块/对象生命周期、缓解项、竞态、KASAN/KCSAN，以及 initramfs/调试环境 |
| [`PROTOBUF_REVERSE.md`](./PROTOBUF_REVERSE.md) | protobuf-c descriptor 恢复、结构体导入与 Python 交互 |
| [`SOURCE_MAP.md`](./SOURCE_MAP.md) | 父目录旧笔记到新专题的映射，以及被纠正/降级的旧结论 |
| [`UPSTREAM_REFERENCES.md`](./UPSTREAM_REFERENCES.md) | 本轮互联网检索的一手资料、适用主题与维护口径 |
| [`BLOG_WRITEUPS_AND_TALKS.md`](./BLOG_WRITEUPS_AND_TALKS.md) | 中英文原创博客、CTF Writeup、会议论文/演讲，以及可迁移条件；不收 Kernel 资料 |

## 可信度口径

- **稳定规则**：ABI、函数边界、协议编码等有标准或上游接口支撑的内容，可以直接作为分析起点。
- **实现相关**：glibc、libstdc++、loader、Pwndbg 插件命令和内部结构，必须用题目附件、Build ID 或 `help` 再确认。
- **题目技巧**：固定偏移、特定 gadget、命令过滤和 ptrace 绕路只说明一种思路，不能脱离目标条件复用。
- **外部资料**：规范与手册提供定义，论文提供攻击模型，工具文档提供接口；适不适用眼前的题目，还得拿附件和运行时验证。一手入口见 [`UPSTREAM_REFERENCES.md`](./UPSTREAM_REFERENCES.md)，博客/Writeup/会议材料及可信度分级见 [`BLOG_WRITEUPS_AND_TALKS.md`](./BLOG_WRITEUPS_AND_TALKS.md)。
- **堆结论**：统一以仓库根目录 [`README.md`](../README.md)、[`PRIMITIVE_REQUIREMENTS_MATRIX.md`](../PRIMITIVE_REQUIREMENTS_MATRIX.md) 和各手法 README 为准；父目录旧 [`heap_cheatsheet.md`](../../heap_cheatsheet.md) 只保留为历史来源。

父目录原文件没有被删除或覆盖。迁移中发现的错误、缺图和未验证片段统一记录在 [`SOURCE_MAP.md`](./SOURCE_MAP.md)，避免整理后反而失去原始上下文。
