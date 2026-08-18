# IO_FILE 任意读写（标准流字段劫持）

## 结论

- 适用范围：**glibc 2.23～2.43，x86-64**。
- 前置能力：能够覆盖 libc 中已有的 `stdin`/`stdout` 对象，或让程序随后使用一份字段等价、vtable 合法的 FILE。
- 效果：控制 `_IO_buf_base/_IO_buf_end` 可把输入写入目标地址；控制 `_IO_write_base/_IO_write_ptr` 可把目标内存写到指定文件描述符。
- 这不是“伪造任意 vtable 执行函数指针”。PoC 保留标准流原有的 `_IO_file_jumps`，所以 glibc 2.24 引入的 `IO_validate_vtable` 不会直接封死它。

“2.23～latest”不能只靠结构体偏移推断。本目录分别检查了 2.23 的 `libio.h` 与 2.43 发布前源码快照的 `bits/types/struct_FILE.h`，并沿 `fileops.c` 复核了消费字段的路径；在这个版本区间内，下面列出的 x86-64 偏移和关键数据流保持一致。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 可覆盖现有 stdin/stdout，或投递字段等价且 vtable 合法的 FILE |
| 关键环境与不变量 | libc/FILE 地址；可用 fd；触发实际读写函数 |
| 最终输出原语 | fd→内存 AAW；内存→fd AAR/leak |
| 版本边界应如何理解 | 2.24 vtable 白名单不阻止“保留合法 vtable”的字段劫持；2.23～2.43 是布局/触发适配，没有已知核心删除。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## x86-64 关键偏移

| 偏移 | 字段 | 利用时的作用 |
|---:|---|---|
| `0x08` | `_IO_read_ptr` | 与 `_IO_read_end` 相等时迫使下一次读取进入 underflow |
| `0x10` | `_IO_read_end` | 同上 |
| `0x20` | `_IO_write_base` | 待输出内存区间的起点 |
| `0x28` | `_IO_write_ptr` | 待输出内存区间的终点 |
| `0x38` | `_IO_buf_base` | `_IO_file_underflow` 调用 `read` 时的目的地址 |
| `0x40` | `_IO_buf_end` | 与 base 的差决定最大读取长度 |
| `0x70` | `_fileno` | 底层 `read/write` 使用的文件描述符 |
| `0xd8` | vtable | 本手法保留对象原来的合法 `_IO_file_jumps` |

## 任意写：stdin → target

`_IO_new_file_underflow` 的主干逻辑是：

```c
if (fp->_flags & _IO_NO_READS)
    return EOF;
if (fp->_IO_read_ptr < fp->_IO_read_end)
    return *fp->_IO_read_ptr;
fp->_IO_read_base = fp->_IO_read_ptr = fp->_IO_buf_base;
fp->_IO_read_end = fp->_IO_buf_base;
count = _IO_SYSREAD(fp, fp->_IO_buf_base,
                    fp->_IO_buf_end - fp->_IO_buf_base);
```

因此需要：

1. 清除 `_IO_NO_READS` 与旧的 EOF 状态；
2. 令 `_IO_read_ptr == _IO_read_end`，保证触发 underflow；
3. 令 `_IO_buf_base = target`、`_IO_buf_end = target + length`；
4. 令 `_fileno` 指向攻击者可提供数据的 fd，随后调用 `fgetc/fgets/fread/scanf` 一类读函数。

PoC 用 pipe 自给输入，证明字节确实由底层 `read` 落进目标数组。题目中通常是覆盖 `_IO_2_1_stdin_` 的低 `0x78` 字节，然后触发菜单读取。

## 任意读：target → stdout

`fflush` 最终把 `_IO_write_base` 到 `_IO_write_ptr` 的区间交给 `_IO_new_file_write`，而该函数执行 `write(fp->_fileno, data, size)`。因此在输出缓冲区为空后，令：

```text
_IO_write_base = target
_IO_write_ptr  = target + length
_IO_write_end  = target + length
_IO_read_end   = target
_fileno        = 1
```

`_IO_read_end == _IO_write_base` 可避免 `new_do_write` 先调用 `lseek` 调整外部偏移；stdout 往往是 pipe/socket，不能省略这一条件。随后触发 `fflush(stdout)`，即可把目标内存送到标准输出。真实题目还要结合原 `_flags`、缓冲模式和触发函数调试；若使用 `puts/printf` 而不是显式 flush，它们可能先改变 write 指针。

## 版本变化与边界

| 版本 | 变化 | 对本手法的影响 |
|---|---|---|
| 2.23 | 无 vtable 白名单 | 字段劫持可用 |
| 2.24 | `IO_validate_vtable` 检查 vtable 是否位于 `__libc_IO_vtables` | 保留合法 vtable，仍可用 |
| 2.28 | `_IO_strfile` 的回调字段改成直接 `malloc/free` | 影响旧 `_IO_str_jumps` 回调 RCE，不影响这里的 file read/write |
| 2.34 | malloc/free hooks 从正常路径删除 | 不影响任意读写本身，只影响后续控制流终点 |
| 2.42～2.43 | tcache/largebin/fastbin 大改 | 会改变“怎样覆盖 FILE”，不改变 FILE 被消费时的这条数据流 |

注意：这里的范围只涵盖 **glibc 的标准 FILE 对象及默认 file vtable**。musl、32 位、宽字符路径、`fopencookie`、FORTIFY 包装和发行版私有补丁需要重新核对。

## PoC

- [`poc_stdin_arbitrary_write_2.23_2.43.c`](./poc_stdin_arbitrary_write_2.23_2.43.c)：线性 `main`，由 `fgetc` 触发 stdin 任意写。
- [`poc_stdout_arbitrary_read_2.23_2.43.c`](./poc_stdout_arbitrary_read_2.23_2.43.c)：线性 `main`，由 `fflush` 直接输出目标内存。

两份 C 文件末尾分别列出 stdin/stdout 低字段的题目补丁伪代码；不再生成绑定占位地址的二进制 payload。

运行示例：

```bash
./tools/run_in_docker.sh 2.23 io_file_arbitrary_read_write/poc_stdin_arbitrary_write_2.23_2.43.c
./tools/run_in_docker.sh 2.43 io_file_arbitrary_read_write/poc_stdout_arbitrary_read_2.23_2.43.c
```

## 源码与补充资料

- [glibc 2.23 `libio.h`](https://github.com/bminor/glibc/blob/glibc-2.23/libio/libio.h)
- [glibc 当前 `struct_FILE.h`](https://github.com/bminor/glibc/blob/master/libio/bits/types/struct_FILE.h)
- [glibc 当前 `fileops.c`](https://github.com/bminor/glibc/blob/master/libio/fileops.c)
- [ALateFall：IO_FILE 任意读写](https://github.com/ALateFall/blogs/blob/main/system/IO_FILE/IO_FILE%E4%BB%BB%E6%84%8F%E8%AF%BB%E5%86%99.md)
- [看雪《CTF 中 glibc 堆利用及 IO_FILE 总结》离线存档](/Users/flower/Zotero/storage/QPI8VQE6/thread-272098-1.html)
