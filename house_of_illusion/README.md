# House of Illusion

## 结论

- 目标原语：劫持 `_IO_list_all` 后，仅借助 glibc 自带合法 vtable，构造 **fd → 任意内存** 与 **任意内存 → fd** 两个方向的真实读写。
- 适用范围：**x86-64 glibc 2.23～2.43**。2.23、2.24、2.38、2.39、2.40 与 2.43 已用对应运行时实跑；端点及 2.40 结构切换点均成功。
- 前置条件：已知 libc 地址；能让 `_IO_list_all` 指向一份可控的 `FILE`；伪造对象、`_lock` 和读入目标可写；有可用 fd。
- 它不是堆管理器原语，而是堆题常用的 FILE 消费链。堆漏洞负责把 fake FILE 投递进 `_IO_list_all`，Illusion 再把它升级成可重复读写。

原始文章研究的是一份**定制过的 glibc 2.38**：题目给 `_wide_data` 路径补了额外 vtable 校验，使 Apple2 类路径失效。House of Illusion 的价值是完全绕开 fake wide vtable，改用 `_IO_file_jumps` 与同一合法表内部的 `-0x8` 位移；不能把“发现于 patched 2.38”误写成“仅 stock 2.38 可用”。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | libc leak；能挂 fake FILE 到 `_IO_list_all`；可写对象/lock；可用 fd |
| 关键环境与不变量 | 合法 `_IO_file_jumps` 或其 section 内 `-8`；2.40+ `_prevchain` |
| 最终输出原语 | fd→目标 AAW + 目标→fd AAR，可串联 |
| 版本边界应如何理解 | 2.24 白名单允许 section 内部错位；2.40 是双链字段适配。上游 2.23～2.43 的消费路径持续存在；题目私有扩大校验属于环境变化。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 两条数据流

### 原作者所谓 read primitive：fd → target

`_IO_flush_all` 对 fake FILE 调用 overflow 槽。令：

```text
fake.vtable = _IO_file_jumps - 0x8
```

同一张表内的槽位就发生如下平移：

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

所以原文的“read”是底层系统调用方向；按漏洞效果，它是**任意地址写**。

### 原作者所谓 write primitive：target → fd

令 vtable 保持为 `_IO_file_jumps`，构造：

```text
_IO_write_base = target
_IO_write_ptr  = target + length
_fileno        = output_fd
```

链为 `_IO_new_file_overflow -> _IO_do_write -> _IO_file_write -> write(fd, target, length)`，按漏洞效果是**任意地址读/泄露**。

## 为什么 glibc 2.24 的 vtable 校验不阻止它

glibc 2.24 的 `IO_validate_vtable` 要求 vtable 位于 `__libc_IO_vtables` section；它并不要求指针恰好等于某张表的起点。`_IO_file_jumps - 0x8` 仍在该 section 内，因此快速检查通过。PoC 没有把 vtable 指向 heap，也没有伪造函数指针。

这里必须和 House of Apple 2 区分：Apple2 的 primary vtable 合法，但控制的是 `fp->_wide_data->_wide_vtable`；Illusion 不消费 fake wide vtable。

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

所以 2.40+ 的 fake FILE 必须令 `fp->_prevchain = &_IO_list_all`（当 fake 是链表头时）。PoC 始终在 `+0xb8` 写该值：旧版本只覆盖无语义 padding，新版本满足双链表不变量。省略它会在 2.40～2.43 的摘链阶段空指针崩溃，这也是“2.38 PoC 直接搬到新 libc”最容易漏掉的版本断点。

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

PoC 中 `dlsym` 只是替代题目里的 libc 泄露与符号偏移，直接改 `_IO_list_all` 只是替代 heap 投递原语；二者都不应被误解成攻击能力来源。

## 源码与原始资料

- [House of Illusion 原始文章](https://enllus1on.github.io/2024/01/22/new-read-write-primitive-in-glibc-2-38/)
- [Some-of-House：Illusion/Some 组合工具原仓库](https://github.com/CsomePro/Some-of-House)
- [glibc `genops.c`：`_IO_flush_all_lockp`](https://github.com/bminor/glibc/blob/master/libio/genops.c)
- [glibc `fileops.c`：`_IO_new_file_finish`、`_IO_do_write` 与底层 read/write](https://github.com/bminor/glibc/blob/master/libio/fileops.c)
- [glibc `libioP.h`：`IO_validate_vtable`](https://github.com/bminor/glibc/blob/master/libio/libioP.h)

发行版 backport 或题目自行扩大 `IO_validate_vtable` 的语义时要重新实测；原题正是定制 libc，不能只看版本号。
