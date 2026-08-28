# Fuzzing 与崩溃归因

这篇面向题目附件、自己编译的 PoC 和获得授权的目标。fuzzer 的输出是“触发某条执行路径的输入”；从 crash 到可利用原语，还得还原根因、首次内存破坏和可控范围。

## 先选模式

| 条件 | 优先工具/方式 | 特点 |
|---|---|---|
| 有源码，目标是纯 parser/API | libFuzzer + ASan/UBSan | in-process，速度高，便于精确定位 |
| 有源码，目标是完整 CLI/daemon | AFL++ compiler instrumentation | forkserver、stdin/文件接口自然 |
| 无源码的本机 ELF | AFL++ QEMU/Frida mode 等 | 速度低于编译插桩，需要稳定入口/退出 |
| 跨架构或局部函数 | QEMU/Unicorn harness | 要自己恢复 loader、调用约定和状态 |
| 只需单个 crash 复现 | GDB/core/ASan/Valgrind | 先定位，不必为了形式强上 coverage fuzzer |

开始前固定 binary hash、依赖、命令行、环境变量、timeout、内存限制和输入通道。

## Sanitizer 构建

适合定位内存错误的常用开发构建：

```bash
clang -O1 -g -fno-omit-frame-pointer \
  -fsanitize=address,undefined \
  -o target-asan target.c
```

- ASan 擅长 OOB、UAF、double free 等内存错误；它改变内存布局和 allocator，不能用 sanitizer 地址/堆形状直接编 exploit。
- UBSan 覆盖有符号溢出、错误 shift、misaligned/null access 等未定义行为；不同检查可单独开关。
- 生产附件与 sanitizer 构建要并行保留：前者验证真实可利用性，后者帮助定位 root cause。
- 优化级别会改变漏洞表现；`-O1` 便于调试，不代表远端 `-O2/-O3/LTO` 的代码形状。
- sanitizer report 可能在首次检测处中止，反而早于无插桩附件的最终 crash，这是有价值的根因线索。

常用运行选项：

```bash
ASAN_OPTIONS=abort_on_error=1:symbolize=1:detect_leaks=0 \
UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 \
./target-asan < testcase
```

关闭 leak detection 只适用于聚焦其他 crash 的场景，不能因此就说程序没有 leak。

## libFuzzer harness

```c
#include <stddef.h>
#include <stdint.h>

int parse_packet(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 1 << 20)
        return 0;
    parse_packet(data, size);
    return 0;
}
```

```bash
clang -O1 -g -fno-omit-frame-pointer \
  -fsanitize=fuzzer,address,undefined \
  fuzz_target.c parser.c -o fuzz_parser

mkdir -p corpus artifacts
./fuzz_parser corpus -artifact_prefix=artifacts/ -timeout=2 -rss_limit_mb=2048
```

好的 harness：

- 直接调用最小目标，避免每轮 fork/exec 和大规模初始化；
- 每轮重置 global、allocator owner、locale、随机数、临时文件和线程状态；
- 不把非法输入在到达 parser 前过度过滤；
- 给结构化格式准备小而多样的有效/无效 seeds；
- timeout、最大输入和内存限制匹配业务，而不是掩盖慢路径；
- 能单独把一个 artifact 作为参数重放。

若目标有跨轮次残留、persistent thread、`dlclose` 或不可恢复的全局状态，in-process fuzz 结果可能不可靠，应重构 harness 或改用 process isolation。

## Corpus 与 dictionary

初始 corpus 应覆盖不同语法分支，而不是塞入大量同类大文件：

```text
空输入、最短合法输入
每种 message/opcode
零个/一个/多个元素
嵌套深度边界
长度字段与实际 payload 一致/不一致
校验和正确/错误
压缩、编码和 framing 的最小样本
```

dictionary 放协议 magic、关键字、分隔符和 token。比较驱动很强的 parser 可考虑 CmpLog/trace-cmp 类能力；先确认 coverage 卡在比较，而不是 harness 根本没走到目标。

libFuzzer corpus merge：

```bash
mkdir -p corpus-min
./fuzz_parser -merge=1 corpus-min corpus
```

AFL++ 保留 edge coverage 所需最小集合可用 `afl-cmin`；单个 testcase 缩减用 `afl-tmin`。缩减后必须在原始附件和 sanitizer 构建中都重放。

## AFL++ 有源码起点

```bash
CC=afl-clang-fast CXX=afl-clang-fast++ make clean all
mkdir -p seeds findings
printf 'A' > seeds/minimal
afl-fuzz -i seeds -o findings -- ./target @@
```

目标从 stdin 读取时省略 `@@`。若目标必须长期运行，可用 persistent mode，但每轮必须重置全部可观察状态；残留状态会造成不稳定 coverage、假 crash 或漏报。

## 无源码二进制

```bash
afl-fuzz -Q -i seeds -o findings -- ./chall @@
```

QEMU mode 只是入口。性能和稳定性进一步取决于：

- 能否跳过昂贵初始化，选个安全的 persistent entry；
- guest base、PIE load address 和入口地址是否匹配；
- 每轮 registers、memory、fd、signals 和 heap 状态是否恢复；
- fork/daemon/network 是否需要 harness 转成文件/共享内存输入；
- 目标架构和 QEMU mode 支持情况。

没有证明状态正确前，不要因为 exec/s 高就认为 fuzz 有效。

## Crash triage

对每个 crash 保存：

```text
input hash 与原始文件
binary/DSO hash 和 Build ID
完整 argv/env/cwd
signal/exit code/timeout
stderr 与 sanitizer report
PC、SP、fault address、registers、backtrace、maps
是否能连续复现
```

推荐顺序：

1. 用同一命令重放 10 次，区分稳定 crash、竞态、OOM 和 timeout。
2. 在 sanitizer 构建重放，找最早报告；再在原始附件重放，确认真实表现。
3. 最小化 testcase，每次缩减都保持同一根因，而不只是同一 signal。
4. 从 fault instruction 逆向追到第一个错误 pointer/length/lifetime 变化。
5. 写最小 regression harness，记录漏洞输入约束。
6. 最后才评估可控 bytes、地址范围、重复次数与保护机制。

## Core dump

```bash
ulimit -c unlimited
./chall < crash.bin

gdb -q ./chall core
```

systemd 环境可能把 core 收集到 coredump 服务：

```bash
coredumpctl list ./chall
coredumpctl debug ./chall
```

GDB 中：

```gdb
info registers
x/16i $pc-16
x/64gx $sp
bt full
info proc mappings
info auxv
```

运行中也可用 `gcore snapshot.core` 保存快照。core 是否包含所有 mapping 受 `/proc/PID/coredump_filter` 和 `VM_DONTDUMP` 影响；缺页不能自动解释成 crash 时未映射。

pwntools 可自动读取本地 process 的 `corefile`，结合 `cyclic_find` 定 stack overwrite offset；仅当输入 pattern 未被编码/截断/转换时结果才可信。

## Signal 与 fault address

| 现象 | 先检查 |
|---|---|
| `SIGSEGV` | 读/写/执行权限、canonical address、NULL/OOB/UAF、栈耗尽 |
| `SIGBUS` | 文件映射越过 EOF、未对齐访问的架构行为、硬件/映射错误 |
| `SIGILL` | 错架构/指令 state、跳入数据或半条指令、CPU feature 缺失 |
| `SIGABRT` | assert、allocator/stack protector/sanitizer 主动终止 |
| `SIGFPE` | 除零、整数除法溢出等架构异常 |
| timeout | 死循环、阻塞 IO、算法复杂度、死锁或等待另一个 frame |

最终 signal 是结果，不是 root cause。一次 heap OOB 可能很久以后在 unrelated free 中 `SIGABRT`；一次整数回绕可能先分配过小 buffer，最后才在 memcpy `SIGSEGV`。

## 用 GDB 找第一次破坏

知道目标字段地址时使用 hardware watchpoint：

```gdb
watch -l *(unsigned long *)0xTARGET
awatch -l *(unsigned int *)0xTARGET
continue
```

hardware watchpoint 数量和宽度有限；过宽表达式可能退化或失败。知道 syscall/映射/库加载时机时：

```gdb
catch syscall mmap mprotect read write
catch signal SIGABRT SIGSEGV
catch load
```

支持的平台可尝试 `record full` 后 reverse execution；它有性能、指令和外部 I/O 限制，不能当成所有目标通用能力。

## 从 crash 到可利用性

最终写一张表：

| 问题 | 结论 |
|---|---|
| 攻击者控制哪些输入 bits/bytes？ |  |
| 第一次非法 read/write/free/call 在哪里？ |  |
| 地址是相对、绝对还是数据依赖？ |  |
| 最大长度、次数和字符限制？ |  |
| crash 前后对象生命周期？ |  |
| 能否稳定泄漏地址或控制相邻字段？ |  |
| 原始附件的 PIE/NX/canary/RELRO/CET 状态？ |  |
| 远端进程模型是否保持布局和状态？ |  |

填不出的格子就是下一步实验，不要用漏洞类别名称代填。

## 上游依据

- [Clang AddressSanitizer](https://clang.llvm.org/docs/AddressSanitizer.html)
- [Clang UndefinedBehaviorSanitizer](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html)
- [LLVM libFuzzer](https://llvm.org/docs/LibFuzzer.html)
- [Clang SanitizerCoverage](https://clang.llvm.org/docs/SanitizerCoverage.html)
- [AFL++ features](https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/features.md)
- [AFL++ QEMU persistent mode](https://github.com/AFLplusplus/AFLplusplus/blob/stable/qemu_mode/README.persistent.md)
- [GDB watchpoints](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Set-Watchpoints.html)
- [GDB process record/replay](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Process-Record-and-Replay.html)
- [GDB core generation](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Core-File-Generation.html)
