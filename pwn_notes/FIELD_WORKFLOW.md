# Pwn 题现场流程

这篇把各专题串成一条可执行流程。核心做法是维护“事实表”和“原语账本”：只把已经在附件或调试器里验证的条件写成事实，利用路线从当前原语推导，不从熟悉的攻击名字反推漏洞。

## 前十分钟

```bash
mkdir -p work
cp -- chall libc.so.6 ld-linux*.so* work/ 2>/dev/null || true
sha256sum work/*

file work/chall
readelf -hW work/chall
readelf -lW work/chall
readelf -dW work/chall
readelf -nW work/chall
readelf -sW work/chall | less
```

另开一个简短记录：

```text
arch/endian/ABI:
interpreter:
libc Build ID:
PIE/NX/RELRO/canary/CET 或 BTI/PAC:
输入边界与协议 framing:
进程模型: 单进程 / fork worker / 多线程 / 每连接 exec
沙盒与权限:
已验证的读、写、释放、控制流原语:
```

不要只保存 `checksec` 一行输出。保护状态最终应能对应到 ELF header、program header、dynamic tag、symbol 或 property note；方法见 [`BINARY_RECON_AND_MITIGATIONS.md`](./BINARY_RECON_AND_MITIGATIONS.md)。

## 先复现，再逆向

1. 用附件 loader 和库启动，确认依赖解析结果。
2. 记录一轮正常菜单或协议流量，标出每个长度字段、换行和 NUL。
3. 用 `strace` 看文件、网络、signal、fork/clone 和 seccomp 安装时机。
4. 在 GDB 外、GDB 内各跑一次；GDB 在 GNU/Linux 上通常默认关闭被调试进程 ASLR，需用 `set disable-randomization off` 检查真实布局。
5. 先定位输入到达哪个 buffer、对象或 chunk，再追越界后的第一个被消费字段。

常用命令：

```bash
strace -f -s 256 -o trace.log ./work/chall
strace -f -e trace=%file,%process,%network,%signal ./work/chall

# 直接调用附件 loader；路径均用实际绝对路径替换
./work/ld-linux-x86-64.so.2 \
  --library-path ./work \
  --list ./work/chall
```

若本地和远端行为不同，优先比较 loader、libc、内核、环境变量、工作目录、时区/locale、stdin 类型和进程模型，而不是先增加 `sleep()`。

## 漏洞事实表

给每个入口写清六件事：

| 项目 | 要回答的问题 |
|---|---|
| 来源 | stdin、socket、文件、共享内存、环境变量还是 argv？ |
| 解码 | 原始 bytes、文本整数、base64、protobuf、压缩还是自定义 frame？ |
| 长度 | 谁提供长度，经过什么类型转换，单位是 byte 还是 element？ |
| 目标 | 栈数组、堆对象、全局区、映射或内核对象？ |
| 生命周期 | 分配、共享、释放、复用和析构分别在哪里？ |
| 消费点 | 被破坏值下一次在哪里用于地址、长度、分支、free 或间接调用？ |

漏洞命名不是结论。例如“off-by-one”只描述写入范围；还必须记录可写字节值、相邻字段、消费时机和是否能重复。

## 原语账本

每得到一个能力就按下面格式记录：

```text
原语: 相对越界写
地址: victim + [0x20, 0x38)
内容: 完全可控，但不能包含换行
次数: 每连接 1 次
前置: victim 必须先成功解析
副作用: 写后立即 free(victim)
稳定性: 本地 100/100，远端未知
```

常见升级关系：

```text
越界读 / 格式串读
  -> 泄漏栈、PIE、libc、heap 或对象地址
  -> 消除地址不确定性

相对写 / UAF edit / 类型混淆
  -> 改长度、指针、索引、vptr、FILE、chunk metadata
  -> 任意读、任意写或受控间接调用

PC 控制 + 可控栈
  -> ROP / SROP / 调用已有函数

任意写但控制流受保护
  -> 数据流目标、合法回调、对象状态、凭据或最终输出字段
```

堆原语的输入/输出和 chunk size 单独查 [`PRIMITIVE_REQUIREMENTS_MATRIX.md`](../PRIMITIVE_REQUIREMENTS_MATRIX.md)；不要在现场记录里把“能改一个 freed chunk 字段”直接写成“任意写”。

## 选利用路线

| 已有条件 | 优先检查 | 关键附加条件 |
|---|---|---|
| 返回地址可控、无 PIE | ret2win / 已导入函数 | ABI、栈对齐、参数与返回路径 |
| 返回地址可控、有 libc 泄漏 | ret2libc / ROP | 附件 Build ID、可写栈、调用约定 |
| 寄存器难布置但可触发 sigreturn | SROP | 精确 signal frame、syscall 入口、可控 SP |
| 没有目标符号地址但 loader 元数据可用 | ret2dlresolve | 可写区、伪 relocation/symbol/string、目标 loader 行为 |
| 有逐地址泄漏函数 | DynELF / 手工遍历 ELF | 至少一个已加载对象内指针、稳定重复读 |
| 无附件且服务崩溃后地址不变 | BROP | 可区分 crash/stop、同一映像反复尝试、足够请求预算 |
| `ret` 路线受限制 | JOP/COP/合法间接调用 | dispatcher、可控对象或函数表、目标允许集合 |
| 任意写但 SHSTK/CFI 强 | data-only / 合法回调 | 找到真正的授权、长度、路径或状态消费点 |
| 可写可执行内存或能 `mprotect`/`mmap` | shellcode | 沙盒 syscall、坏字符、缓存一致性与架构状态 |

路线细节见 [`MEMORY_CORRUPTION_AND_STRATEGY.md`](./MEMORY_CORRUPTION_AND_STRATEGY.md)、[`ABI_ROP_AND_STACK.md`](./ABI_ROP_AND_STACK.md) 和 [`ELF_LINKING_AND_RELOCATION.md`](./ELF_LINKING_AND_RELOCATION.md)。

## 分阶段构造

一条利用链尽量拆成可单独断言的阶段：

1. **到达**：输入确实进入预期对象，长度与次数正确。
2. **破坏**：第一个错误字段变成预期值，没有提前崩溃。
3. **泄漏**：输出能稳定解析，并落在预期映射。
4. **基址**：泄漏减去的偏移来自同一个附件 Build ID。
5. **写入/控制**：目标字段真正被后续代码读取。
6. **触发**：最终 syscall、函数调用或数据状态满足沙盒与权限条件。

脚本中为每个阶段保留短日志和 assert。不要把所有异常都交给无限重试；失败应能归类为同步错位、错误泄漏、布局失败、目标未消费或远端环境差异。

## 把布局与动作序列变成可搜索对象

菜单题反复做 allocate/edit/free/show 时，可以把每个操作封装成带前置和后置状态的 fragment，再让脚本搜索“目标对象相邻”“特定尺寸复用”或“最终获得 overlap/read/write”的短序列：

```text
state + action(parameters) -> new_state + observations
```

记录 request size、实际 chunk size、返回对象 id、free 状态、目标距离和崩溃原因。[SHRIKE](https://www.usenix.org/conference/usenixsecurity18/presentation/heelan)展示了按目标 heap layout 组合交互片段，[ArcHeap](https://www.usenix.org/conference/usenixsecurity20/presentation/yun)则把 allocator action、漏洞能力和输出原语建模并最小化 action sequence。

CTF 中不一定需要完整自动化框架：先把手写脚本的每一步结构化，成功后做 delta-debugging，逐项删除无关申请和等待，就能区分必要约束与偶然堆噪声。具体 chunk size 前提仍以 [`PRIMITIVE_REQUIREMENTS_MATRIX.md`](../PRIMITIVE_REQUIREMENTS_MATRIX.md)和目标版本 PoC 为准。

## 远端稳定性

- 所有 `recvuntil` 都应有明确 delimiter 和超时；超时与 EOF 分开处理。
- TCP 不保存应用层消息边界；一次 `send` 不保证对应一次 `read`，一次 `recv` 也可能只返回部分数据。
- fork worker 可能继承 canary 和地址布局；每连接 exec 则会重新建立进程映像。先用多次泄漏验证，不能从服务框架名称猜。
- 多线程下 allocator arena、signal 投递和竞争窗口与单步调试不同；必要时用条件断点、日志或 rr 类工具，避免单步本身消除竞态。
- 所有概率步骤给出最大次数、成功判据和重连成本。
- 最终动作先选择可观察、无交互的结果，例如读取 flag 后直接写回 fd；shell 只在题目环境和 seccomp 确实允许时使用。

## 结束前复核

- exploit 是否显式加载题目 ELF、libc 和 loader，而不是宿主机默认库？
- PIE/libc/heap/stack 的每个基址是否来自独立且类型正确的泄漏？
- payload 是否依赖 GDB 关闭 ASLR、调试器写过内存或插件初始化过 tcache？
- 保护机制是“ELF 标记存在”还是“运行时已启用”，是否已区分？
- 本地连续运行、容器运行和远端运行的成功率分别是多少？
- 失败时脚本是否保存最后一轮收发、关键地址和阶段编号？
- 文档中的固定值是否绑定了 hash/Build ID，版本变化后能否重新求出？

工具脚本模板见 [`EXPLOIT_SCRIPTING.md`](./EXPLOIT_SCRIPTING.md)，崩溃自动定位见 [`FUZZING_AND_CRASH_TRIAGE.md`](./FUZZING_AND_CRASH_TRIAGE.md)。
