# 输入、输出与 libc 隐式分配

## 先区分三类边界

分析输入函数时分别记录：

1. **最多读取多少字节**；
2. **什么字符停止本次转换**，停止字符是否被消费；
3. **目标中是否自动写入 NUL**。

不要把“遇到 EOF”“遇到换行”和“返回短读”混成同一个概念。

## 常见函数速查

| 调用 | 读取/停止规则 | 停止字符 | 自动 NUL | 实战注意 |
|---|---|---|---|---|
| `read(fd, buf, n)` | 最多 `n` 字节；管道、终端、socket 都可能短读 | 没有字符分隔符 | 否 | 返回值才是实际长度；返回 0 表示 EOF |
| `getchar()` | 从 `stdin` 取一个字节 | EOF 不是字节 | 不适用 | 返回类型是 `int`，必须先与 `EOF` 比较再转成 `char` |
| `scanf("%c", &c)` | 默认正好一个字符，不跳过空白 | 消费这个字符 | 否 | `" %c"` 前导空格才会跳过空白；可写 `%8c` 读固定宽度 |
| `scanf("%s", buf)` | 跳过前导空白，再读到下一个空白或 EOF | 第一个终止空白留在流中 | 是 | 无字段宽度会溢出；`char buf[N]` 至多用 `%N-1s` |
| `scanf("%[^;]", buf)` | 读到不属于 scanset 的字符 | 这个字符留在流中 | 是 | 匹配 0 字符时转换失败；同样必须给字段宽度 |
| `fgets(buf, n, stream)` | 最多保存 `n-1` 字节；遇到换行或 EOF | 换行若读到则保留 | 是 | EOF 前已经读到数据时还是返回 `buf` |
| `gets(buf)` | 读到换行/EOF，丢弃换行 | 换行被消费 | 是 | 无法限制长度，C11 删除；只用于识别历史题目 |
| `strcpy(dst, src)` | 复制到源 NUL | 源 NUL 被复制 | 是 | 目标容量不够就越界 |
| `strcat(dst, src)` | 从目标已有 NUL 处追加到源 NUL | 源 NUL 被复制 | 是 | 需要 `strlen(dst)+strlen(src)+1` 容量 |
| `strncat(dst, src, n)` | 最多追加源的前 `n` 字节 | 随后总会再写一个 NUL | 是 | 目标至少还需 `min(strlen(src),n)+1`，不是“总容量 n” |
| `sprintf(dst, ...)` | 写完整格式化结果 | 不适用 | 是 | 没有容量参数；返回值不含结尾 NUL，目标不够就越界 |
| `snprintf(dst, n, ...)` | 最多写 `n-1` 字节和 NUL（`n>0`） | 不适用 | 是 | 返回“本来需要写出的长度”，拿它判断截断 |

### 常见组合陷阱

- `scanf`/`fgets` 属于 stdio，`read` 是文件描述符 I/O。混用时，stdio 可能已经把后续字节预读进 `FILE` 缓冲区，直接 `read(fileno(stdin), ...)` 看不到那些字节。
- `scanf("%u", &x)` 留下分隔换行；下一次 `fgets` 可能立刻读到这一行剩余的 `\n`。
- `%c` 和 `%[` 默认不跳过空白，`%s`、整数和浮点转换默认跳过前导空白。
- 网络脚本不要假设一次 `send` 对应一次 `read`，也不要假设一次 `recv` 能收全一个逻辑消息。

### `scanf` 转换失败与未初始化目标

`scanf` 家族的返回值是成功赋值的转换项数量。若输入与第一个转换不匹配，它通常返回 `0`；若在第一次转换前遇到 EOF，则返回 `EOF`。未成功转换对应的目标不会被赋值：

```c
unsigned long value;                 // 尚未初始化
if (scanf("%lu", &value) != 1)
    return -1;                       // 必须在使用 value 前退出
```

题目若忽略返回值，随后打印、比较或作为 index 使用 `value`，实际二进制可能暴露这个栈槽之前残留的数据。[Ltfall 的技巧汇总](https://ltfa1l.top/2023/12/28/system/tricks/tricks/)记录了以 `-` 等不完整 token 触发失败后泄漏旧栈值的题型。

分析时分别记录返回值、目标栈槽原值，还有失败输入有没有被消费；不同转换和 libc 对“读到符号后才失败”的流位置处理可能不同。C 语言层读取未初始化自动变量本身不提供可移植语义，所以这是一条目标二进制原语，不是可靠输入 API。

## 数值 scanf 的隐藏 allocator trigger

无字段宽度的 `%u`、`%d`、`%i`、`%o`、`%x`、`%p` 和浮点转换需要先保存完整 token，再做数值转换。目标整数只有 4/8 字节，不会限制 token 长度。

### 上游 glibc 版本分段

| glibc | 临时缓冲区 | 超长 token 的效果 |
|---|---|---|
| 2.3～2.14 | 旧 workspace 持续使用 `alloca` | 不提供 ptmalloc trigger；可能耗尽栈 |
| 2.15 | 过渡实现的分支条件特殊 | 普通数字转换就可能从 `realloc(NULL, 0x100)` 开始使用堆 |
| 2.16～2.22 | 小缓冲先走 `alloca`，超过内部 cutoff 后转堆 | `realloc(NULL, size)`、后续 `realloc`、退出时 `free`；首次尺寸受实现状态影响 |
| 2.23～2.44 | 1 KiB 内嵌 scratch buffer | token 与结尾 NUL 放不下后 `malloc(2048)`，再按 2 倍 `realloc`，退出时 `free` |

2.23+ 的窄字符路径可概括为：

```text
约 1024 个数字 + 结尾 NUL
        ↓
malloc(2048)
        ↓
realloc(4096) → realloc(8192) → ...
        ↓
strtoul/strtol 转换
        ↓
free(最终 scratch buffer)
```

这是一条**隐式申请/释放触发路径**，不是 `%u` 堆溢出：

- scratch chunk 紧邻 top 时，`realloc` 可能原地吞并 top，最终 `free` 也可能直接并回 top。
- 不能原地扩容时，`realloc` 才可能申请新块并释放旧块；旧块进入 tcache、unsorted 或直接合并取决于版本、尺寸和邻接状态。
- 请求无法由 bins/top 满足时才会进入 `sysmalloc`；大请求还可能走 `mmap`。超长输入本身不保证发生 bin sorting。
- 首次读 `stdin` 还可能出现独立的 stdio 缓冲区申请，调试时不要把它误认成数字 scratch buffer。

[redpwnCTF 2021 Simultaneity](https://ctftime.org/writeup/29251)在 glibc 2.28 上实际利用了这条路径：长数字越过内嵌区后出现 scratch `malloc/realloc/free`。因此它并非 glibc 2.39 独有；真正的版本条件是目标 `vfscanf` 是否采用对应 scratch-buffer 实现，以及输入能否跨过当时的阈值。

在题目中使用它前，先确认：

1. 格式串确实没有字段宽度，例如 `%u` 而不是 `%10u`。
2. 能发送足够长且最后有非数字、换行或 EOF 的 token。
3. 触发尺寸的 2 倍序列符合目标堆布局；它不是任意尺寸 malloc。
4. 目标 libc/vendor 包还在用对应的源码路径。

防御或避免副作用时用合适的字段宽度，或者先 `fgets` 到有界数组，再用 `strtoul`，检查 `endptr`、`errno` 和范围。

## 历史 `printf` 大字段宽度的 allocator side effect

某些旧 glibc 的 `vfprintf` 会为远大于内部工作区的字段宽度申请临时缓冲，再在格式化结束时释放。例如 [0CTF 2017 EasiestPrintf](https://blog.dragonsector.pl/2017/03/0ctf-2017-easiestprintf-pwn-150.html)使用类似 `%100000c` 的输出触发了当时实现中的 `malloc/free`。

这条技巧必须按目标构建验证：

- width 是输出计数，不代表各版本都按相同大小申请堆缓冲；实现也可能直接分块填充或走栈上工作区。
- 大量 padding 会真的增加逻辑输出量，可能阻塞 pipe/socket、耗尽时间或被 `snprintf` 的目标长度改变效果。
- locale、宽字符路径和格式化函数族会改变内部路线。
- 即使发生了申请，也不能因此保证 chunk 会落进某个 bin 或触发 top 扩展。

在 `malloc/free` 下断点并配合目标 libc 源码确认；不要把这条旧 `vfprintf` 路线类推成所有 glibc 的固定接口。

## 文本输入承载精确 bit pattern

目标按 `float`/`double` 读取，并不表示 payload 只能按普通数值理解。[Facebook CTF 2019 Overfloat](https://ling.re/fbctf-overfloat/)把 ROP qword 拆成两个 32-bit word，再分别生成能被目标 parser 恢复成相同 IEEE-754 bits 的十进制文本。

生成器必须做本地 round-trip，而不是只调用一次 `str()`：

```python
from pwn import p32, u32
import struct

bits = 0x41424344
value = struct.unpack("<f", p32(bits))[0]
token = format(value, ".9g")
parsed_bits = u32(struct.pack("<f", float(token)))
assert parsed_bits == bits
```

目标的 C parser、locale、舍入、NaN payload、`inf` 接受规则和输入终止字符都可能与 Python 不同；最终应在附件使用的 libc 上逐项验证。

## stdio 缓冲与刷新

- 终端上的 `stdout` 通常行缓冲；重定向到文件、管道或 socket 时通常全缓冲。是否立即看到输出取决于 `FILE` 状态，别只按文件描述符判断。
- `stderr` 的具体缓冲状态和程序调用过的 `setvbuf` 都要实测。
- 调试菜单“没有输出”时，先检查是否缺少换行、是否调用 `fflush`、是否被重定向以及进程是否已经阻塞在下一次读取。
- 修改 GOT 低字节把某个调用改成 `fflush` 只属于特定二进制的 partial-overwrite 技巧；必须同时满足非 PIE/地址低位、RELRO 和目标函数 ABI，不能记成 stdio 通用规则。

### 单字节修改也可能被 refill 放大

[GlacierCTF 2023 Write Byte Where](https://ctftime.org/writeup/38299)展示过一个强环境相关的放大器：程序把 `stdin` 设为无缓冲后，一字节修改相邻 `FILE` 的 `_IO_buf_end`，后续 `getchar` refill 便把更大范围当成输入缓冲，形成连续覆盖。

复用前必须同时确认：目标 glibc 的 `_IO_FILE` 布局、标准流对象的相对位置、当前 `_flags/_IO_read_ptr/_IO_read_end/_IO_buf_base/_IO_buf_end` 状态、调用的 underflow 路线，还有写入后哪一段地址还能写。它不是“改 `_IO_buf_end` 就有任意写”的通用公式；更稳妥的描述是“污染缓冲边界后，由下一次 stdio refill 扩大线性写入范围”。

## 主动发送 EOF

管道或 socket 场景优先关闭发送方向：

```python
p.shutdown("send")
```

本地进程若使用 PTY，终端行规程中的 `VEOF` 只在特定模式和行状态下解释；需要确定 EOF 语义时优先让 pwntools 使用 pipe，或直接关闭写端，而不是固定发送某个控制字符。

## 上游阅读入口

- [glibc 数值输入转换](https://sourceware.org/glibc/manual/2.44/html_node/Numeric-Input-Conversions.html)
- [glibc 2.44 `vfscanf-internal.c`](https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=blob;f=stdio-common/vfscanf-internal.c;hb=glibc-2.44)
- [glibc 2.44 `scratch_buffer.h`](https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=blob;f=include/scratch_buffer.h;hb=glibc-2.44)
- [glibc 2.22 旧 `vfscanf.c`](https://github.com/bminor/glibc/blob/glibc-2.22/stdio-common/vfscanf.c)
