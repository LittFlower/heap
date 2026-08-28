# 沙盒、命令过滤与侧信道

## 先还原限制，不要按黑名单猜

seccomp 题先确认：

- 架构检查是否存在，x86-64/x32 syscall number 是否分开处理；
- x86 目标是否还允许 i386 compatibility entry；数字相同不代表跨 ABI 是同一 syscall，详见 [`ARCHITECTURES_AND_SYSCALLS.md`](./ARCHITECTURES_AND_SYSCALLS.md#x86-64-long-mode-与-compat-mode-切换)；
- 默认 action 是 KILL、ERRNO、TRAP、LOG 还是 USER_NOTIF；
- 过滤的是系统调用号，还是还检查参数；
- 子进程、线程和 `execve` 后是否继承过滤器；
- 文件描述符、当前目录、环境变量和已打开文件是否可利用。

可用时通过 `seccomp-tools dump ./pwn`、`strace`、反汇编 BPF 或在 `seccomp/prctl` 处断下来恢复真实规则。Linux seccomp filter 只缩小可调用内核接口，并不会自动对系统调用参数内容做安全检查。

## 先读懂 `struct seccomp_data`

经典 seccomp BPF 判断的是 `struct seccomp_data` 中的 syscall number、架构标识、instruction pointer 和六个参数值。它不能解引用用户态指针，所以：

- 能判断 `openat` 的 `flags`，也能比较 pathname 指针的数值；
- 不能直接读取 pathname 指向的字符串，更不能据此可靠地做路径白名单；
- 指针参数所指内存可在检查后被其他线程修改，所以由外部 supervisor 读取内存的 USER_NOTIF 方案还得处理 TOCTOU；
- 多 ABI 入口必须先检查 `arch`，再解释 syscall number，尤其留意 x86-64/x32 的编号约定。

过滤器可以叠加，最终选择语义上优先级更高的 action；同优先级返回值的数据则按内核规则合并。安装 filter 通常要求调用者设置 `no_new_privs`，或者具备相应 namespace 中的 `CAP_SYS_ADMIN`。多线程程序还要检查是否使用 `SECCOMP_FILTER_FLAG_TSYNC` 同步 filter tree，否则不同线程可能处于不同过滤状态。

常见 action 的语义并不相同：

| action | 分析重点 |
|---|---|
| `KILL_PROCESS` / `KILL_THREAD` | 终止范围，以及是否留下可观察状态 |
| `TRAP` | `SIGSYS` handler 能否改变控制流或结果 |
| `ERRNO` | 返回的 errno 是否触发程序备用路径 |
| `USER_NOTIF` | listener fd、supervisor 决策和参数内存竞态 |
| `TRACE` | ptracer 能否改 syscall number/参数；不要假设修改后一定重新执行 seccomp 检查 |
| `LOG` / `ALLOW` | 是否只是审计，或者直接放行 |

`fork/clone/execve` 获准时，后代仍继承相应 filter。USER_NOTIF supervisor 如果要判断指针参数，应先复制并验证全部输入，再作决定；允许 tracer 配合 `SECCOMP_RET_TRACE` 时，也要把 ptrace 修改系统调用的能力计入攻击面。

## 多 actor 的能力矩阵

题目存在 parent/child、tracer/tracee、broker/worker 或不同线程时，不要把所有规则合成一张 seccomp allowlist。为每个 actor 单独记录：

| actor | filter/权限 | 已有 fd | 地址空间与可控数据 | 能观察或修改谁 | 执行先后 |
|---|---|---|---|---|---|
| parent/tracer | syscall、uid、capability | listener、pipe、目标文件 | fork 时复制，之后通常 COW | ptrace、wait、signal | stop/event 驱动 |
| child/tracee | 自己的 seccomp filter | 继承后又关闭哪些 fd | 自己的 stack/heap | 通过 IPC 输出 | 被 tracer 恢复 |
| broker | USER_NOTIF 决策权限 | notification fd | 未必共享目标内存 | 读取参数或注入 fd | request/response |

关键问题是“哪个 actor 能完成哪一段数据流”。例如一个进程可读 flag 但不能输出，另一个可输出却不能打开文件；若两者共享 pipe、继承的栈内容或 ptrace 访问，就可能组成完整路径。

[Balsn CTF 2021 orxw](https://ctftime.org/writeup/31420)利用 fork 两侧不同的 seccomp 能力以及复制后的栈，把读取与输出拆给不同进程。[Balsn CTF 2022 Asian Parents](https://ctftime.org/writeup/35285)则让 parent 通过 ptrace 处理 child 的 `SECCOMP_RET_TRACE` 事件。两者都依赖题目实际的进程关系；它们不是“有 fork/ptrace 就绕过 seccomp”的通用结论。

## execve 相关误区

- 只禁 `execve` 时，只有在 filter 明确允许 `execveat` 且参数检查不阻止时，`execveat` 才是候选。
- `system(command)` 通常需要启动 `/bin/sh -c command`，最后还是走进程创建/执行那条路；它不会天然绕过 `execve/execveat` 禁止。
- 即使成功启动 shell，shell 里的外部命令还会再次执行程序；若只有 shell builtin 可用，可考虑 `read VAR < /flag; echo "$VAR"`，前提是 shell 已经存在并且 `open/read/write` 路径获准。
- 已经存在可控解释器、脚本引擎或服务子进程时，应单独分析，不要把它与 `system` 混为一谈。

## ORW / openat-read-write

当不能执行新程序但允许文件 I/O 时，常见链是：

```text
openat(AT_FDCWD, "/flag", O_RDONLY, 0)
read(returned_fd, buf, size)
write(1, buf, size)
```

注意：

- `openat` 的返回 fd 不保证是 3；若缺少 `mov rdi, rax` 一类数据搬运 gadget，可以先关闭/预测 fd，但这属于环境假设。
- 绝对路径会忽略 `dirfd`，相对路径才依赖 `AT_FDCWD=-100` 或真实目录 fd。
- `read` 可能短读，`write` 也可能短写。
- filter 能检查 `openat` 的 `flags` 或 pathname 指针数值，但经典 BPF 不能读取 pathname 字符串。

不要只找字面上的 `open/read/write`。根据目标 fd 类型、offset 需求和真实 allowlist，还可以逐一核对：

| 目的 | 候选 syscall family |
|---|---|
| 打开文件 | `openat`、`openat2` |
| 从 fd 取数据 | `read`、`pread64`、`readv` |
| 输出或转移数据 | `write`、`writev`、`sendfile`、`splice` |

这些不是等价替换：参数结构、文件 offset、fd 类型和内核支持都可能不同。部分 libc API 也可能由 vDSO 在用户态完成，不一定产生 filter 能观察到的 syscall；应以 `strace`、断点和目标环境实测为准。

示意 ROP 应使用符号而不是固定地址：

```python
chain = flat(
    pop_rdi, -100 & ((1 << 64) - 1),
    pop_rsi, path_addr,
    pop_rdx, 0,
    pop_rcx, 0,
    libc.sym.openat,
    # 用数据流 gadget把 rax 搬到 rdi，再接 read/write
)
```

第四个普通函数参数在 x86-64 SysV 是 `rcx`；若直接做 `syscall`，第四个系统调用参数改用 `r10`。

### 先恢复文件描述符拓扑

程序 `close(1)` 只表示 fd 1 当前关闭，不表示没有输出通道。进入最终链前列出：

```text
fd number -> object type -> read/write direction -> inherited by whom
```

候选路线包括：

- `dup2(open_fd, 1)`/`dup3` 恢复 stdout 编号；
- 直接 `write`/`writev` 到仍打开的 socket、pipe 或 stderr；
- 修改合法 `FILE` 的 `_fileno`，前提是后续确实走这个 stream；
- allowlist 允许且网络可达时，新建 `socket`、`connect` 后输出到远端 listener。

shell 中的 `exec 1>&0` 本质是把 fd 0 duplicate 到 fd 1；只有已经获得 shell、fd 0 对应对象也允许写，并且 shell builtin/重定向未被过滤时才有用。网络框架可能把 stdin/stdout 设为同一 duplex socket，也可能用两条单向 pipe，不能只凭编号推断。

`writev(fd, iov, iovcnt)` 在缺少连续输出或 filter 只放行 vectored I/O 时很有用；每个 `struct iovec` 都是 `{base,length}`，`iovcnt`、各段可读性、总长度上限和 partial write 都要检查。[Ltfall 的关闭 stdout 与 `writev` 笔记](https://ltfa1l.top/2023/12/28/system/tricks/tricks/)提供了题型实例，但具体 fd 编号和公网反连能力不具备可移植性。

## `mmap` flags 不要与 prot 混淆

```text
prot  = PROT_READ | PROT_WRITE = 0x3
flags = MAP_PRIVATE             = 0x2
flags = MAP_PRIVATE | MAP_ANONYMOUS = 0x22
```

旧笔记把 `0x3` 推荐成 mmap flags，这是错误的：Linux 上 `0x3` 同时包含 `MAP_SHARED` 与 `MAP_PRIVATE`。映射文件时不要加 `MAP_ANONYMOUS`，否则 fd/offset 不提供文件内容；匿名 staging 区才使用 `MAP_ANONYMOUS`。

### file-backed `mmap` 可替代 `read`

沙盒允许 `mmap`、已有可读文件 fd，但禁止 `read/pread` 时，可以把文件直接映射为只读内存：

```text
mmap(addr_hint, length, PROT_READ, MAP_PRIVATE, fd, page_aligned_offset)
```

随后再用获准的 `write/writev/sendfile` 等输出。严格条件包括：fd 对应对象可映射，offset 按页对齐，length 覆盖目标范围，返回地址实际可用，filter 允许对应参数，并且文件类型/权限支持 mapping。`MAP_ANONYMOUS` 通常不会让调用失败，而是忽略 fd，给你一块不含文件内容的匿名页——指定博客的原说法就错在这里。

## 命令字符串过滤

这些只对“目标真的把字符串交给 shell”时有意义；直接 `execve` 参数匹配、应用层 AST 解析和 seccomp 不是同一层。

### 替代读取程序

```text
head  tail  tac  nl  sed  awk  grep  more  less
```

实际是否存在、是否允许参数、是否把二进制/NUL 安全输出都要检查。

### shell 展开

```sh
# 通配符隐藏文件名
cat f*
cat ./*

# 拆分关键字
c=ca; t=t; "$c$t" f*
c'a't f''lag
c/at fl/ag

# 替代空格（依 shell 与过滤发生阶段）
cat${IFS}/flag
cat</flag
```

`${IFS}` 展开后可能包含多个空白字符；`$IFS$9`、URL 编码 `%09` 是否有效取决于 shell 参数展开和上游解码顺序。

### 只有 shell builtin

```sh
read -r line < /flag
printf '%s\n' "$line"
```

这只能读取首行；多行文件需要循环。`$0` 的含义是当前 shell/脚本名，不等价于在所有环境中执行 `sh`。

### 可执行错误回显

在一次性 CTF 容器中，直接尝试执行不可执行文本文件，有时 shell/loader 的错误会包含路径或内容片段。这不是稳定的文件读取原语，并且可能受执行位、shebang、shell 和错误重定向影响。

## ptrace 题型

如果主进程通过 ptrace 检查子进程系统调用，依次确认：

- 是否只跟踪一个线程/进程；fork/clone/exec 事件选项是否完整；
- 信号停止与 syscall-stop 是否用 `PTRACE_O_TRACESYSGOOD` 区分；
- tracer 对进入/退出系统调用状态的切换是否会被额外 SIGTRAP 打乱；
- 新子进程是否继承或被自动 attach。

“触发 `int3` 反转状态机”或“让 `system` 创建未追踪子进程”只适用于实现有对应缺陷的挑战程序，不是 ptrace 通用绕过。

## 时间/存活侧信道

当只能让进程“继续运行”或“立即退出”时，可按字节比较秘密。先定义可靠判据：超时、连接关闭、响应字节或退出状态；不要用裸 `except:` 把网络抖动当成比较结果。

```python
def probe(index: int, guess: int) -> bool:
    """返回 secret[index] <= guess；具体 shellcode/ROP 由题目决定。"""
    io = start()
    try:
        io.send(build_probe(index, guess))
        marker = io.recv(timeout=0.5)
        return marker == EXPECTED_MARKER
    finally:
        io.close()
```

每个 guess 至少重复多次并用多数结果，记录超时与异常类型。远程环境中二分搜索节省请求，但错误判定会污染后续所有位。

## 特权文件替换技巧

旧笔记记录过“挑战目录中的 `/bin` 归 CTF 用户，可替换某个被高权限程序调用的工具”。只应在授权的一次性题目容器中检查：目录/文件 owner、mount namespace、调用是否使用绝对路径、签名/哈希、noexec、环境清理和真实 euid。不要在宿主机或非授权环境尝试替换系统程序。

## 上游文档

- [Linux kernel seccomp filter 文档](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html)
- [Linux `seccomp(2)`](https://man7.org/linux/man-pages/man2/seccomp.2.html)
