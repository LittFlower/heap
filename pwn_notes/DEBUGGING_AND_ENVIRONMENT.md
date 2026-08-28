# 调试与运行环境

## 首次拿到附件

先记录环境事实，再开始找 gadget：

```bash
file ./pwn
readelf -hW ./pwn
readelf -lW ./pwn | rg 'INTERP|GNU_STACK|GNU_RELRO'
readelf -nW ./pwn ./libc.so.6
objdump -p ./pwn | rg 'NEEDED|RPATH|RUNPATH'
checksec --file=./pwn
```

关键记录：架构、endianness、PIE、NX、canary、RELRO、动态解释器、依赖库、libc/ld Build ID。发行版名称和 `ldd --version` 只能帮助定位，不能代替附件 Build ID。

## GDB 常用命令

```gdb
# 搜命令与设置
apropos fork
help dprintf

# fork 后跟子进程；如需同时保留父子进程再关闭自动 detach
set follow-fork-mode child
set detach-on-fork off
info inferiors
inferior 2

# 补充源码搜索路径
directory /path/to/glibc
show directories

# 信号处理
handle SIGALRM nostop noprint pass
handle SIGPIPE nostop noprint pass

# 不停住程序地打印调用参数；下面只适用于 x86-64 SysV 的 malloc
dprintf __libc_malloc, "malloc(%#lx)\n", $rdi
dprintf __libc_free, "free(%p)\n", $rdi
```

不要用“parent PID + 1”猜 child PID。PID 分配会受系统中其他进程、线程、namespace 和并发 fork 影响；直接用 `catch fork`、`info inferiors`、`set follow-fork-mode`，或者从 `/proc/PID/task/.../children`、程序日志和 `pwntools.util.proc.children()` 解析实际关系。[指定博客](https://ltfa1l.top/2023/12/28/system/tricks/tricks/)中的 `gdb.attach(pid+1)`只能碰巧适用于当时的安静环境。

GDB 在 GNU/Linux 上通常默认关闭由它启动的进程 ASLR。调固定地址时保持默认可提高复现性；验证真实 exploit 时打开：

```gdb
show disable-randomization
set disable-randomization off
```

按事件停下比在所有 wrapper 上断点更清楚：

```gdb
catch syscall read write mmap mprotect execve
catch fork
catch exec
catch load
catch signal SIGABRT SIGSEGV
```

`dprintf` 的参数寄存器依架构和 ABI 改变。内部符号还可能被优化、内联或缺少调试符号；断不到时先用 `info functions malloc`、PLT、调用点或对应源码行。

硬件观察点适合抓元数据被谁改坏：

```gdb
watch *(unsigned long *)0xTARGET
rwatch *(unsigned long *)0xTARGET
awatch *(unsigned long *)0xTARGET
```

硬件槽位数量有限，地址对齐和监视长度也受架构限制。

## Core、快照与反向执行

```gdb
# 保存当前 inferior 快照
gcore snapshot.core

# 支持的平台记录后可反向查找第一次破坏
record full
continue
reverse-continue
reverse-stepi
```

`record full` 有指令支持、性能和外部 I/O 限制；`record btrace` 主要记录控制流，不等价于完整数据状态回滚。core 是否包含某段 mapping 还受 `coredump_filter` 和 `VM_DONTDUMP` 影响。系统化 crash triage 见 [`FUZZING_AND_CRASH_TRIAGE.md`](./FUZZING_AND_CRASH_TRIAGE.md)。

## Pwndbg / Pwngdb

插件命令变化比 GDB 本体快，先在当前环境运行 `help <command>`。常见检索入口：

| 目的 | 常见命令 |
|---|---|
| 映射、TLS、基址 | `vmmap`、`tls`、`heapbase` |
| 栈与指针 | `telescope`、`retaddr`、`p2p` |
| 堆状态 | `heap`、`bins`/`bin`、`arena`、`mp`、`top_chunk` |
| 安全字段 | `canary`、`errno` |
| 格式化字符串 | Pwngdb 的 `fmtarg`（需停在正确调用上下文） |
| FILE 链 | Pwngdb 的 `fsop` 或手动查看 `_IO_list_all` |

旧笔记里的 `try_free`、`find_fake_fast`、`leakfind`、`force` 等命令不是所有 Pwndbg/Pwngdb 版本都有；找不到不代表利用不可行，直接按源码检查约束。

## gdbserver 与远程调试

```bash
gdbserver 0.0.0.0:1234 --attach PID
gdb ./pwn -ex 'target remote HOST:1234'
```

容器中附加通常还要允许 ptrace，再确保宿主 GDB 看到与容器一致的二进制、loader 和共享库。可以在 GDB 中设置：

```gdb
set sysroot /path/to/container-root
set solib-search-path /path/to/libs
```

## QEMU 用户态调试

```bash
qemu-aarch64 -g 1234 -L /usr/aarch64-linux-gnu ./chall
gdb-multiarch ./chall -ex 'set architecture aarch64' -ex 'target remote :1234'

qemu-arm -g 1234 -L /usr/arm-linux-gnueabi ./chall
gdb-multiarch ./chall -ex 'set architecture arm' -ex 'target remote :1234'
```

QEMU user-mode 只模拟用户态 ABI，目标内核、vDSO、seccomp 和信号细节未必与真实环境一致。

## Docker 快速操作

```bash
# 明确容器名称时进入 shell
docker exec -it hackmd /bin/bash

# 查看后再选择，不默认进入“第一个”容器
docker ps --format '{{.ID}}  {{.Names}}  {{.Image}}'

# 从容器复制附件库
docker cp CONTAINER:/usr/lib/x86_64-linux-gnu/libc.so.6 ./libc.so.6

# 临时运行题目目录
docker run --rm -it --privileged \
  -v "$PWD:/chall" -w /chall IMAGE /bin/bash
```

`--privileged`、`--cap-add=SYS_PTRACE` 和关闭 seccomp 会改变题目环境，只在调试所需时使用。动态堆 PoC 的精确 glibc runner 见 [`../tools/README.md`](../tools/README.md)。

## 卡住时的排查顺序

1. 确认本地实际加载的是附件 `ld.so`/`libc.so.6`，而不是宿主库。
2. 比较本地与远程的 Build ID、页大小、环境变量、启动参数和 stdin 类型（pipe/PTY/socket）。
3. 在第一次状态分叉处断下，而不是只盯最终崩溃。
4. 检查短读、缓冲、超时、信号和 fork 后跟错进程。
5. 对 ASLR 敏感的布局记录成功率和失败地址，不用无限重试掩盖不变量错误。

## 上游文档

- [GDB fork 调试](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Forks.html)
- [GDB Dynamic Printf](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Dynamic-Printf.html)
- [GDB catchpoints](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Set-Catchpoints.html)
- [GDB watchpoints](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Set-Watchpoints.html)
- [GDB record/replay](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Process-Record-and-Replay.html)
