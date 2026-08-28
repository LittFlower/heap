# House of Some

## 结论

**一句话**：全程使用合法 vtable，把 `_IO_flush_all` 的一次 overflow 变成 `read(fd, target, length)`，再用 `_chain` 串联多个读写 FILE 形成 RWRWR，把 ROP 写上栈。

- 适用范围：**x86-64 glibc 2.23～2.43**；其中 2.23、2.24、2.29、2.30、2.31、2.39、2.40、2.43 已在对应 glibc 运行时上实际跑通消费链。
- 前置能力：已知 libc 基址；有已知可写区放 fake FILE/wide data；能进行一次 libc 内指针写（典型目标是 `_IO_list_all` 或现有标准流的 `_chain`）；程序能走 `exit`/正常退出。
- 它属于 FILE/FSOP 消费链（伪造字段写好后，glibc 真正读取并触发控制转移的那条源码路径），不是堆管理器原语；fastbin/tcache/largebin 等操作在这里只负责把地址写进 `_IO_list_all` 并在堆上摆好伪造数据。

House of Some 与 House of Illusion 不是同一条底层链：

- **Some**：primary vtable 为 `_IO_wfile_jumps`，借 wide doallocate 槽平移到 `_IO_new_file_underflow`；原文发布于 2023 年。
- **Illusion**：primary vtable 直接取 `_IO_file_jumps-0x8`，借 `finish -> shifted write=read` 获得读入能力；原文发布于 2024 年。
- `Some-of-House` 工具后来默认用 Illusion 模板编排 HouseOfSome 的上层 RWRWR，所以只看当前脚本容易把两个名称误合并。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | libc leak；已知可写区；一次 libc 内指针写挂 FILE 链；退出/flush |
| 关键环境与不变量 | 合法 primary 与 section 内 shifted wide vtable；2.40+维护 prevchain |
| 最终输出原语 | W primitive，可编排 RWRWR、泄露 environ/栈并写 ROP |
| 版本边界应如何理解 | 2.30/2.31 wide ABI 和 2.40 双链是适配；消费路径到 2.43 仍在。完整 RWRWR 的交互顺序、栈偏移和 ROP 仍题目相关。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

<!-- CHUNK_SIZE_REQUIREMENTS:START -->
## Chunk size 要求

- **Some 的 FILE/RWRWR 消费链不要求特定 chunk size。** fake FILE、wide data 和分阶段 I/O 缓冲可以位于 heap、BSS 或其他足够大的已知可写区。
- FILE 中的 `read` 长度与链上缓冲长度是 I/O 尺寸，不是 `malloc` request；只有用于挂链/投递的 largebin、tcache 或 overlap 原语另有 chunk 范围要求。
<!-- CHUNK_SIZE_REQUIREMENTS:END -->

## 从源码看第一跳

`_IO_flush_all_lockp` 会遍历 `_IO_list_all`。当 fake FILE 满足：

```text
fp->_mode > 0
fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base
fp->vtable = _IO_wfile_jumps
```

overflow 槽进入 `_IO_wfile_overflow`。再令：

```text
wide->_IO_write_base = 0
wide->_IO_buf_base   = 0
wide->_wide_vtable   = _IO_file_jumps - 0x48
```

即可得到：

```text
_IO_flush_all
  -> _IO_wfile_overflow
    -> _IO_wdoallocbuf
      -> WDOALLOCATE(fp)                     // wide vtable + 0x68
        -> (_IO_file_jumps - 0x48) + 0x68
          -> _IO_file_jumps + 0x20
            -> _IO_new_file_underflow
              -> _IO_SYSREAD(fp, fp->_IO_buf_base,
                             fp->_IO_buf_end - fp->_IO_buf_base)
                -> read(fp->_fileno, target, length)
```

primary `_IO_wfile_jumps` 的 read 槽仍是 `_IO_file_read`，所以 underflow 内的 `_IO_SYSREAD` 不会因 wide doallocate 的 `-0x48` 平移而错位。这正是 Some 相比“直接平移 primary vtable”的关键设计。

glibc 2.24 起对 primary vtable 做 `IO_validate_vtable`；这里 primary 指针就是合法 `_IO_wfile_jumps`。stock glibc 在这个范围内没对 wide vtable 做同等检查。就算题目补上同样的 section 范围检查，也要先确认 `_IO_file_jumps-0x48` 还在 `__libc_IO_vtables` 里——发行版私有补丁不一定和上游语义一致，别直接假设。

## RWRWR 完整编排

原文所谓 RWRWR 不是“一份固定 FILE 自动打所有题”，而是利用 `_IO_flush_all` 按 `_chain` 继续遍历的特性，分阶段把新 fake FILE 写进受控区：

1. **W**：构造第一个 Some FILE，让读入端从输入读到一条更长的 fake FILE 链。这一步只需一次 libc 指针写把它挂到 `_IO_list_all`，后续阶段都沿这条链继续。
2. **R + W**：用一个普通 `_IO_file_jumps` FILE 读 `environ` 泄露栈地址；同时链上下一个 Some FILE 读入下一阶段要用的数据，一次 flush 同时完成泄露和准备。
3. **R + W**：拿到栈地址后算出栈窗口，定位当前 `_IO_flush_all` 或其调用者的返回地址；链上下一个 Some FILE 趁机把最终 ROP 数据写到该返回地址之后。
4. **R/W 最终写**：最后把 ROP 直接写到栈上。写入起点选在 canary 之后，前面泄露的栈窗口同时解决绕 canary 和对齐返回位置两个问题。

每次读入都会阻塞，等待下一阶段数据；远程脚本必须匹配 `_IO_flush_all` 的遍历顺序。`_chain`、fd、栈偏移、ROP gadget 和沙箱策略都要按题目确定。

## 版本变化

| glibc | `_IO_wide_data->_wide_vtable` | PoC | 说明 |
|---|---:|---|---|
| 2.23～2.29 | `+0x130` | [`poc_2.23_2.29.c`](./poc_2.23_2.29.c) | legacy codecvt ABI；2.24 才引入 primary vtable 白名单，但本链两侧均可用 |
| 2.30 | `+0xf0` | [`poc_2.30.c`](./poc_2.30.c) | `09e1b0e` 删除 legacy codecvt 函数表后的单版本过渡布局 |
| 2.31～2.43 | `+0xe0` | [`poc_2.31_2.43.c`](./poc_2.31_2.43.c) | `70c6e15` 再次缩小 `_IO_iconv_t` 后的现代布局 |

另一个独立断点是 glibc 2.40 的 [`2a99e239`](https://sourceware.org/git/?p=glibc.git;a=commit;h=2a99e2398d9d717c034e915f7846a49e623f5450)：`_IO_list_all` 改成双向链表，`FILE+0xb8` 从内部 padding 复用为 `_prevchain`。fake 是链表头就填 `&_IO_list_all`；fake B 由 fake A 的 `_chain` 指向就填 `&A->_chain`。单纯遍历不一定立刻消费它，但任何 unlink/finish 都会用到，完整链要一直维护这个不变量。

## PoC 与运行

三份 C PoC 都真实覆写 `_IO_list_all`，从 `fflush(NULL)` 进入上述完整消费链，用 pipe 配合 `memcmp` 断言 fd 数据确实写进目标数组。它们验证 RWRWR 中关键的 W 原语和各版本字段布局；完整栈上 ROP 编排还得按题目生成交互阶段。

```bash
./tools/run_in_docker.sh 2.23 house_of_some/poc_2.23_2.29.c
./tools/run_in_docker.sh 2.30 house_of_some/poc_2.30.c
./tools/run_in_docker.sh 2.43 house_of_some/poc_2.31_2.43.c
```

PoC 里的 `dlsym` 只是代替真实题目中的 libc 泄露和符号偏移计算；直接覆写 `_IO_list_all` 也只是代替把伪造 FILE 投递（写进堆或其他可控内存）到目标地址这一步。这两步都不是 House of Some 自带的攻击能力，实战中要换成题目提供的漏洞原语。

## 源码与原始资料

- [House of Some 原始文章](https://blog.csome.cc/p/house-of-some/)
- [Some-of-House 自动化工具](https://github.com/CsomePro/Some-of-House)
- [glibc `genops.c`：`_IO_flush_all_lockp`](https://github.com/bminor/glibc/blob/master/libio/genops.c)
- [glibc `wfileops.c`：`_IO_wfile_overflow`](https://github.com/bminor/glibc/blob/master/libio/wfileops.c)
- [glibc `wgenops.c`：`_IO_wdoallocbuf`](https://github.com/bminor/glibc/blob/master/libio/wgenops.c)
- [glibc 2.30 `09e1b0e`](https://sourceware.org/git/?p=glibc.git;a=commit;h=09e1b0e3f6facc1af2dbcfef204f0aaa8718772b)
- [glibc 2.31 `70c6e15`](https://sourceware.org/git/?p=glibc.git;a=commit;h=70c6e15654928c603c6d24bd01cf62e7a8e2ce9b)
