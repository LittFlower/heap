# House of Illusion

## 结论

- 目标原语：劫持 `_IO_list_all` 之后，只用 glibc 自带的合法 vtable，就能构造 **fd → 任意内存** 和 **任意内存 → fd** 两个方向的真实读写能力。
- 适用范围：**x86-64 glibc 2.23～2.43**。已在 2.23、2.24、2.38、2.39、2.40、2.43 实测通过，覆盖版本区间两端和 2.40 这个结构切换点。
- 前置条件：已有 libc 基址，能把 `_IO_list_all` 指向可控的 `FILE` 结构体；伪造对象本身、`_lock` 字段和读写目标内存都可写，且手头有一个可用的文件描述符。
- 严格来说它不是堆分配器原语，而是堆题里常见的 FILE 利用链：堆漏洞负责把伪造的 FILE"投递"进 `_IO_list_all`（让全局链表指针指向这份 fake FILE），House of Illusion 再把这次投递升级成可反复使用的读写能力。

原始文章研究的是一份**经过题目定制的 glibc 2.38**：出题人给 `_wide_data` 路径额外补上了 vtable 校验，导致 House of Apple 2 一类打法失效。Illusion 的价值在于完全绕开伪造的 wide vtable，改用合法表 `_IO_file_jumps` 内部 `-0x8` 的位移达到同样效果。所以这手法是在打了补丁的 2.38 上发现的，但在没打补丁的 stock 2.38 上一样能用。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | libc leak；能挂 fake FILE 到 `_IO_list_all`；可写对象/lock；可用 fd |
| 关键环境与不变量 | 合法 `_IO_file_jumps` 或其 section 内 `-8`；2.40+ `_prevchain` |
| 最终输出原语 | fd→目标 AAW + 目标→fd AAR，可串联 |
| 版本边界应如何理解 | 2.24 白名单允许 section 内部错位；2.40 是双链字段适配。上游 2.23～2.43 的消费路径持续存在；题目私有扩大校验属于环境变化。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

<!-- CHUNK_SIZE_REQUIREMENTS:START -->
## Chunk size 要求

- **shifted `_IO_file_jumps` 消费链不绑定 heap size class。** fake FILE 和 I/O 缓冲描述可放在任意足够大、可写、对齐的区域。
- 正常读写版/shifted read 版中的长度字段是 I/O 长度，不是 malloc request；若通过 heap attack 投递 FILE 链，再按该投递原语检查 chunk size。
<!-- CHUNK_SIZE_REQUIREMENTS:END -->

## 两条数据流

### 原作者所谓的 read primitive：fd → target

`_IO_flush_all` 会对 fake FILE 调用它的 overflow 槽位。令：

```text
fake.vtable = _IO_file_jumps - 0x8
```

这样一来，同一张表内的槽位就会发生如下平移：

```text
shifted overflow -> real finish -> _IO_new_file_finish
shifted write    -> real read   -> _IO_file_read
```

完整链为：

```text
fflush(NULL)
  -> _IO_flush_all
    -> shifted overflow = _IO_new_file_finish
      -> _IO_do_write(fp, fp->_IO_write_base,
                      fp->_IO_write_ptr - fp->_IO_write_base)
        -> shifted write = _IO_file_read
          -> read(fp->_fileno, target, length)
```

所以原文说的“read”指的是底层系统调用的方向；从漏洞利用效果来看，这实际上是一个**任意地址写**原语。

### 原作者所谓的 write primitive：target → fd

保持 vtable 不变，还是 `_IO_file_jumps`，然后构造：

```text
_IO_write_base = target
_IO_write_ptr  = target + length
_fileno        = output_fd
```

这条链是 `_IO_new_file_overflow -> _IO_do_write -> _IO_file_write -> write(fd, target, length)`，从漏洞利用效果来看是**任意地址读 / 信息泄露**。

## 为什么 glibc 2.24 的 vtable 校验挡不住它

glibc 2.24 引入的 `IO_validate_vtable` 只要求 vtable 指针落在 `__libc_IO_vtables` section 里，不要求恰好等于某张表的起始地址。`_IO_file_jumps - 0x8` 还在这个 section 内，所以这道快速检查直接通过。整个 PoC 既没把 vtable 指向堆内存，也没伪造函数指针，用的全是合法表内部的偏移。

这里要和 House of Apple 2 划清界限：Apple2 的 primary vtable 本身合法，它控制的是 `fp->_wide_data->_wide_vtable` 这条 wide 路径；Illusion 完全不走 fake wide vtable。

## glibc 2.40：必须补 `_prevchain`

glibc 2.40 合入 [`2a99e239`](https://sourceware.org/git/?p=glibc.git;a=commit;h=2a99e2398d9d717c034e915f7846a49e623f5450)，把 `_IO_list_all` 从单链表改成双向链表。`FILE + 0xb8` 原先是内部 padding（旧头文件名为 `__pad5`），2.40 起在不改变 ABI 总大小的前提下复用为：

```c
struct _IO_FILE **_prevchain;
```

shifted 原语经过 `_IO_new_file_finish -> _IO_default_finish -> _IO_un_link`。版本差异是：

```text
2.23～2.39：从 _IO_list_all 开始线性寻找并摘除 fp
2.40～2.43：pr = fp->_prevchain; *pr = fp->_chain
```

所以 2.40+ 的 fake FILE 必须令 `fp->_prevchain = &_IO_list_all`（当 fake 是链表头时）。PoC 始终在 `+0xb8` 写这个值：旧版本只覆盖无语义 padding，新版本满足双链表不变量。省略它会在 2.40～2.43 摘链阶段空指针崩溃——这是"2.38 PoC 直接搬到新 libc"最容易漏掉的版本断点。

## PoC

- [`poc_shifted_read_2.23_2.39.c`](./poc_shifted_read_2.23_2.39.c)：线性展示旧单链表版本的 shifted vtable 任意写。
- [`poc_shifted_read_2.40_2.43.c`](./poc_shifted_read_2.40_2.43.c)：单独展示 2.40 起必须填写 `_prevchain` 的版本。
- [`poc_normal_write_2.23_2.43.c`](./poc_normal_write_2.23_2.43.c)：线性展示正常 vtable 的任意读/泄漏。

运行示例：

```bash
./tools/run_in_docker.sh 2.23 house_of_illusion/poc_shifted_read_2.23_2.39.c
./tools/run_in_docker.sh 2.40 house_of_illusion/poc_shifted_read_2.40_2.43.c
./tools/run_in_docker.sh 2.43 house_of_illusion/poc_normal_write_2.23_2.43.c
```

PoC 中 `dlsym` 只是替代题目里的 libc 泄露与符号偏移，直接改 `_IO_list_all` 只是替代 heap 投递原语，二者都不是攻击能力来源。

## 源码与原始资料

- [House of Illusion 原始文章](https://enllus1on.github.io/2024/01/22/new-read-write-primitive-in-glibc-2-38/)
- [Some-of-House：Illusion/Some 组合工具原仓库](https://github.com/CsomePro/Some-of-House)
- [glibc `genops.c`：`_IO_flush_all_lockp`](https://github.com/bminor/glibc/blob/master/libio/genops.c)
- [glibc `fileops.c`：`_IO_new_file_finish`、`_IO_do_write` 与底层 read/write](https://github.com/bminor/glibc/blob/master/libio/fileops.c)
- [glibc `libioP.h`：`IO_validate_vtable`](https://github.com/bminor/glibc/blob/master/libio/libioP.h)

发行版 backport 或题目自行扩大 `IO_validate_vtable` 语义时要重新实测；原题正是定制 libc，不能只看版本号。
