# 旧笔记迁移与勘误

父目录旧文件保持原样，作为题目片段、历史命令和整理来源；新专题只收录能说明适用条件的结论。这里记录迁移去向和未直接沿用的内容，避免“整理”变成无依据地抄写。

## 文件映射

| 旧文件 | 新位置 | 处理 |
|---|---|---|
| [`cheatsheet.md`](../../cheatsheet.md) | [`INPUT_AND_IO.md`](./INPUT_AND_IO.md)、[`DEBUGGING_AND_ENVIRONMENT.md`](./DEBUGGING_AND_ENVIRONMENT.md)、[`ABI_ROP_AND_STACK.md`](./ABI_ROP_AND_STACK.md)、[`FORMAT_STRING.md`](./FORMAT_STRING.md)、[`SANDBOX_AND_SHELL.md`](./SANDBOX_AND_SHELL.md)、[`LIBC_AND_LOADER.md`](./LIBC_AND_LOADER.md) | 按利用阶段拆分；修正函数语义、跳转别名、mmap 标志和 seccomp 结论 |
| [`template.md`](../../template.md) | [`EXPLOIT_SCRIPTING.md`](./EXPLOIT_SCRIPTING.md) | 去掉固定地址和重复脚手架，保留 bytes-only、收发、菜单、缓存、重试与 Docker 模板 |
| [`shellcodes.md`](../../shellcodes.md) | [`SHELLCODE.md`](./SHELLCODE.md) | 保留生成流程；增加 relocation、ABI、栈和坏字符检查，未把实验性完整程序当成通用 shellcode |
| [旧 C++ 笔记](<../../c++ cheatsheet.md>) | [`CPP_REVERSE.md`](./CPP_REVERSE.md) | 改为按 libstdc++ 常见实现识别，固定对象布局全部标成实现相关 |
| [`kernel.md`](../../kernel.md) | [`KERNEL_PWN.md`](./KERNEL_PWN.md) | 整理解包、静态编译、上传、GDB/QEMU 和 `IA32_LSTAR` 条件；省略失效图片 |
| [`protobuf/protobuf.md`](../../protobuf/protobuf.md) | [`PROTOBUF_REVERSE.md`](./PROTOBUF_REVERSE.md) | 从固定 dword 偏移改成按目标版本 descriptor 恢复，并补 wire/传输层验证 |
| [`__libc_csu_init.md`](../../__libc_csu_init.md) | [`ABI_ROP_AND_STACK.md`](./ABI_ROP_AND_STACK.md) | 合并 ret2csu；修正寄存器映射、间接调用表达式与循环退出条件 |
| [`libc_version_diff.md`](../../libc_version_diff.md) | 根目录 [`README.md`](../README.md)、[`SOURCE_TIMELINE.md`](../SOURCE_TIMELINE.md) | 旧发行版映射和堆时间线不再作为事实源；当前结论按上游 tag 和 Build ID 记录 |
| [`heap_cheatsheet.md`](../../heap_cheatsheet.md) 与[旧堆数据结构笔记](<../../堆相关数据结构.md>) | 根目录 60 个手法 README、[`PRIMITIVE_REQUIREMENTS_MATRIX.md`](../PRIMITIVE_REQUIREMENTS_MATRIX.md)、[`MALLOC_SIZE_BIN_MAP.md`](../MALLOC_SIZE_BIN_MAP.md) | 已由当前堆专题取代，不重复复制 |

## 已纠正的旧结论

### 输入与 libc

- `fgets(buf, n, stream)` 最多存 `n-1` 个输入字节，并在成功且 `n > 0` 时补 NUL；换行若被读入会保留。它不是“读取 n 字节后再补零”。
- `read` 不补 NUL；`strncpy` 在源串过长时也可能不补 NUL。正文已按真实边界区分。
- 无字段宽度的数值 `scanf` 可因 glibc scratch buffer 扩容产生隐藏分配，但是否进入 `sysmalloc`、整理 bin 或处理 top 取决于当时堆状态，不是输入超长串后的固定效果；历史版本窗口已经在 [`INPUT_AND_IO.md`](./INPUT_AND_IO.md) 单列。
- 旧文件对 tcache、calloc 和 hook 的版本表已经滞后，堆相关内容统一转到当前仓库的源码时间线和每个手法 README。

### ABI、跳转与 ROP

- x86 无符号“大于”是 `JA`/`JNBE`；旧表中的 `JBNE` 不是对应别名。
- 常见 x86-64 ret2csu 调用 gadget 的目标是 `[r15 + rbx*8]`，传参通常是 `rdx=r13`、`rsi=r14`、`edi=r12d`。单次循环常令 `rbx=0, rbp=1`，不是令二者相等；后续通常还要跨过 7 个 qword 的栈清理。
- `read+固定偏移`、某一条 vsyscall gadget、固定 libc/loader 地址都依赖附件反汇编或构建，不能作为跨题模板。
- 异常展开由 unwind metadata、personality 和 LSDA 共同决定；篡改返回地址不会自然“跳入任意 catch”。

### seccomp 与系统调用

- `mmap` 的 `PROT_READ|PROT_WRITE` 是 `0x3`；`MAP_PRIVATE` 是 `0x2`，Linux x86-64 上再加 `MAP_ANONYMOUS` 常得到 `0x22`。旧笔记把 prot 与 flags 混在了一起。
- `system()` 最终还是要创建或执行 shell；它不会天然绕过禁止 `execve`/`execveat` 的 seccomp 规则。一切以实际 BPF 允许列表和 libc 实现为准。
- seccomp filter 不能直接当作“只有哪些 syscall”文字清单；还需检查架构号、参数比较、默认动作、TSYNC 和进程已有状态。
- ptrace、`int3`、计时和命令过滤都只是题型相关通道，正文不承诺脱离目标规则可复用。

### C++、Kernel 与 Protobuf

- vector、string、shared_ptr 的内存布局是标准库实现细节。旧 C++ 文件中的固定布局与一段构造函数反编译仅保留作历史样本。
- 普通用户态不能直接用 `rdmsr` 读取 `IA32_LSTAR`；只有已具备相应内核读取能力或特权调试接口时，它才可作为基址线索，减去的偏移必须来自题目内核。
- protobuf-c descriptor 的字段顺序和大小应匹配目标所用的 `protobuf-c.h`；旧笔记按 dword 写死的下标不能跨 32/64 位和版本使用。

## 未迁移或降级的内容

- 旧 Markdown 引用但父目录已缺失的图片没有复制；能用文字恢复的流程已重写，无法确认的图示仅留在历史文件上下文中。
- 空白或只有标题的章节没有为了凑数扩写成伪结论，例如旧 `unordered_map` 小节只在新文中给出保守识别方法。
- 只对某题成立的 IP、端口、用户名、硬编码基址、one-gadget 和 loader 偏移没有进入通用模板。
- 不能独立验证的完整 shellcode/C 实验程序没有作为可直接利用的 PoC 收录；新文只保留可检查的生成步骤。
- 旧命令若依赖特定插件版本，改为先用 `help`/版本命令确认，再给概念上的操作目标。

## 维护规则

后续从父目录迁入内容时：

1. 先写它解决什么原语或分析问题，再写适用架构、运行库和版本。
2. 固定偏移必须绑定题目附件的 Build ID 或二进制 hash。
3. 标准、上游源码事实和题目观察分开描述；无法验证的句子留在旧文件，不提升为结论。
4. 堆手法只维护在根目录对应专题，非堆笔记通过链接引用，不复制另一份版本表。
5. 新增本地链接后运行 `./tools/audit_static.sh`，确保目标存在且文档索引没有漂移。
