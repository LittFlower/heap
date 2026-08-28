# libc、动态加载器与运行时技巧

## 识别目标 libc/ld

优先级：

1. 题目附件中的 `libc.so.6` 与动态解释器；
2. ELF Build ID；
3. 符号版本、导出符号和关键字符串；
4. 最后才是发行版/版本号猜测。

```bash
readelf -nW ./libc.so.6 | rg -A2 'Build ID'
readelf -V ./libc.so.6
readelf -Ws ./libc.so.6 | rg '__libc_start_main|system|setcontext'
readelf -lW ./pwn | rg 'interpreter'
```

父目录旧 [`libc_version_diff.md`](../../libc_version_diff.md) 的 Ubuntu/Debian/CentOS 对照只描述部分发行版初始版本，安全更新不会改变大版本字符串却可能回移检查。堆题版本结论统一查 [`../SOURCE_TIMELINE.md`](../SOURCE_TIMELINE.md)。

## stdio 缓冲与标准流

- stdout 连接终端时通常行缓冲，连接 pipe/file/socket 时通常全缓冲；程序可用 `setvbuf` 改变。
- `fflush(stream)` 只对输出流/更新流的规定状态有明确意义；不要把任意 FILE 状态都当成安全刷新。
- GOT partial overwrite 把某个调用改到 `fflush` 需要目标 GOT 可写、低位距离可达、参数 ABI 合适，并且没有被 RELRO 阻止。
- FILE 利用请直接查 [`../io_file_arbitrary_read_write/README.md`](../io_file_arbitrary_read_write/README.md) 和对应 House README，不从旧笔记复制固定 `_IO_FILE` 偏移。

## exit 与 loader

进程正常退出大致会处理：

```text
exit
  → __run_exit_handlers
      → 注册的 exit/on_exit/cxa handlers
      → loader/fini 清理（具体调用链依构建）
```

利用时要分开三类目标：

- libc 的 `__exit_funcs` 等私有 handler 链；
- 动态加载器的 `link_map`/fini 数组消费路径；
- 历史 `_rtld_global` 锁回调或其他私有函数指针。

还应先确认程序走哪一种终止 API：

| 路径 | 典型行为 | 利用分析重点 |
|---|---|---|
| 从 `main` 返回 / `exit` | 正常 exit handlers、TLS destructor 与 loader fini 等实现路径 | handler 顺序、pointer mangling、重复进入退出流程 |
| `quick_exit` | 使用单独的 quick-exit handler 集合 | 别假定会消费普通 `atexit` 链 |
| `_exit` / `_Exit` | 直接请求内核结束进程 | 不运行普通用户态清理链 |
| `abort` / 致命 signal | signal 与实现定义的异常终止路径 | 普通 fini/handler 通常不是可靠触发点 |
| `pthread_exit` | 结束调用线程并处理线程清理 | 线程 TLS、cleanup handler 与进程最终退出要分开 |

`.fini_array`、`DT_FINI`、C++ destructors 和 `__cxa_atexit` 的注册/执行顺序也要以目标启动与退出路径为准。只控制其中一个数组元素不代表目标函数必会在崩溃、`_exit` 或 seccomp kill 时执行。

### TLS destructor 与 pointer guard

x86-64 glibc 会对若干私有回调指针做 pointer mangling。以 [glibc 2.35 `tls_dtor_list` 案例](https://tttang.com/archive/1749/)为检索入口时，必须区分：

- `fs:0x30` 在这个 pointer-demangle 语境里是 TLS pointer guard；
- allocator 的 tcache key 是另一套用途和状态，不能与 pointer guard 混称；
- `tls_dtor_list` 的节点布局、旋转位数、消费函数和可写性都属于目标 glibc 构建细节。

若想把 exit 路径当最终调用原语，应在附件的 `__call_tls_dtors`、`__run_exit_handlers` 与 loader fini 路径上分别断点，确认目标字段在终止方式下确实被读取。

这些私有指针与 handler 路径都不是稳定 ABI，常伴随 pointer mangling、RELRO、私有布局和版本提交变化。旧笔记给出的 `_rtld_global + 固定偏移` 及 one-gadget 只绑定当时那份 libc/ld，不能迁移。loader fini 链的已验证隔离分析见 [`../house_of_banana/README.md`](../house_of_banana/README.md)。

## hooks

`__malloc_hook`、`__free_hook` 等符号是否还能查到，不等于正常 `malloc/free` 路径还会消费它们。当前仓库以 glibc 2.33 为经典 hook 终点末版、2.34 起正常路径移除为边界；老发行版还可能回移补丁。最终以目标源码/反汇编和可执行 PoC 为准。

## 延迟绑定与 ret2dlresolve

分析 PLT/GOT 时先检查：

```bash
readelf -dW ./pwn | rg 'BIND_NOW|FLAGS'
readelf -rW ./pwn
objdump -d -j .plt -M intel ./pwn
```

典型 ret2dlresolve 需要伪造与目标架构 ABI 匹配的 relocation、symbol 和 string table 数据，再进入正确的 PLT resolver。约束包括：

- Partial RELRO/Full RELRO 与 GOT 可写性；
- PIE 基址和动态表地址；
- relocation index/offset 的计算单位；
- 符号表项对齐、`st_name` 和版本检查；
- resolver 入口前对栈布局的要求。

pwntools 的 `Ret2dlresolvePayload` 可生成常见布局，但还得核对目标 loader 和可写投递区。

完整的 load bias、dynamic symbol、relocation、IFUNC、DynELF/BROP 条件见 [`ELF_LINKING_AND_RELOCATION.md`](./ELF_LINKING_AND_RELOCATION.md)。

## loader 诊断

附件 loader 支持时，可直接查看依赖解析和运行环境：

```bash
./ld-linux-x86-64.so.2 --verify ./pwn
./ld-linux-x86-64.so.2 --library-path . --list ./pwn
./ld-linux-x86-64.so.2 --list-diagnostics ./pwn

LD_DEBUG=libs,files,reloc,symbols,bindings,versions ./pwn 2>loader.log
```

显式 loader invocation 会让 `/proc/self/exe` 指向 loader；`LD_*` 在 secure-execution 模式可能被过滤。诊断命令是用来复现的，别无脑写进最终 exploit。

## loader/PLT 槽位用作 pivot

某些 PLT0/延迟绑定 stub 形如：

```text
push qword ptr [got_slot_1]
jmp  qword ptr [got_slot_2]
```

若槽位可写，可组合 `pop rsp; ret` 做 pivot；Full RELRO 通常会阻止直接改写。必须反汇编目标 stub，不能用固定 GOT 偏移。

## `rand` 与内部状态

glibc `rand/random` 的状态表、算法和初始化属于实现细节；题目若依赖可预测随机数，应记录：

- 调用的是 `rand`、`random`、`rand_r` 还是自实现 PRNG；
- seed 来源和调用次数；
- libc Build ID/架构；
- fork 前后状态是否复制。

“值来自 `randtbl`”只适用于某些 glibc `random` 状态路径，不能作为所有 `rand()` 的统一结论。

对常见 glibc BSD random 的 degree-31/type-3 状态，核心关系可作为识别线索：

```text
state[i] = state[i-3] + state[i-31]       (mod 2^32)
out[i]   = state[i] >> 1                  (31 bits)
```

因此只观察输出时，`out[i]` 与 `out[i-3]+out[i-31]` 在模 `2^31` 下可能相等或差 1；泄漏完整状态时则还必须知道当前 front/rear pointer，而不是从静态初始 `randtbl` 的第一项重新开始。[Ltfall 的 `rand()` 笔记](https://ltfa1l.top/2023/12/28/system/tricks/tricks/)收录了两种思路，但示例索引不能替代目标 glibc 的实际状态。

`srand(time(NULL))` 只在 seed 的秒级窗口、远端时钟偏差和此前调用次数都可枚举时可预测。最稳妥的复现是用附件 libc 调同一 API，而不是用 Python 自带 PRNG；`rand_r`、其他 libc 和程序自实现算法另算。接口层可对照 [glibc BSD Random](https://sourceware.org/glibc/manual/latest/html_node/BSD-Random.html)，内部 recurrence 还得绑定目标源码。

## 按 Build ID 搜 gadget

旧笔记保存了多组 `svcudp_reply`、`swapcontext` 和数据搬运 gadget 的固定偏移。新笔记只保留指令语义，见 [`ABI_ROP_AND_STACK.md`](./ABI_ROP_AND_STACK.md)。实战流程应是：

1. 对附件 libc 搜完整指令序列；
2. 写出数据流与所有可读写要求；
3. 记录 Build ID 和偏移；
4. 换 libc 时重新搜索，别假设“版本号相同就能复用”。

IFUNC 还会让同一个 Build ID 在不同 CPU/HWCAP 环境选择不同函数实现。若泄漏来自 `memcpy`、`strlen` 一类 IFUNC 的最终入口，先用 loader diagnostics 或反汇编确认具体实现，再判断附近 gadget；详见 [`ELF_LINKING_AND_RELOCATION.md`](./ELF_LINKING_AND_RELOCATION.md#ifunc)。
