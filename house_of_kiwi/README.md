# House of Kiwi

## 结论

- 适用范围：**2.23～2.35；2.36 起专属的触发器失效**。
- 原语/效果：故意触发 malloc 的内部 assert，借助它对 stderr 做的 IO 刷新，把伪造的 FILE 结构体拉进 FSOP 触发链。
- 版本变化：2.35 及之前，`__malloc_assert` 在报错时会输出信息并刷新 stdio；2.36 重写了这部分逻辑，去掉了这次 IO 操作。此外，伪造的 wide FILE 还要按 2.23～2.29 / 2.30 / 2.31+ 这三个区间分别使用 `0x130 / 0xf0 / 0xe0` 三种不同的 `_wide_vtable` 字段偏移，不能混用。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 能伪造/覆盖 stderr FILE；能破坏 top 触发 malloc assert |
| 关键环境与不变量 | 旧 `__malloc_assert→__fxprintf/fflush(stderr)`；wide 布局正确 |
| 最终输出原语 | 借错误路径触发 FSOP/CF |
| 版本边界应如何理解 | 2.36 assert 改走 `__libc_message`，Kiwi 专属消费路径硬失效；Apple/Cat 等正常 IO 最终触发点仍在，但不是 Kiwi 触发器。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 从源码看

对比 glibc 2.35 和 2.36 版本 `malloc/malloc.c` 里的 `__malloc_assert`，再结合 `libio/libio.h` 中 `_IO_wide_data` 的定义一起看。提交 [`ac8047c`](https://sourceware.org/git/?p=glibc.git;a=commit;h=ac8047cdf326504f652f7db97ec96c0e0cee052f) 进入 2.36 之后，改用 `__libc_message` 代替了原来那套 `__fxprintf + fflush(stderr)` 的复杂逻辑，这就是 Kiwi 触发器失效的硬边界。另外，2.30 的 [`09e1b0e`](https://sourceware.org/git/?p=glibc.git;a=commit;h=09e1b0e3f6facc1af2dbcfef204f0aaa8718772b) 和 2.31 的 [`70c6e15`](https://sourceware.org/git/?p=glibc.git;a=commit;h=70c6e15654928c603c6d24bd01cf62e7a8e2ce9b) 各自带来了一次 wide-data 布局变化，也就是前面提到的两个版本边界的来源。

源码中仍能走到最终触发点，不等于旧利用链仍成立：投递方式、私有结构和控制流终点都要按附件 libc/ld 的 Build ID 复核。

源码与背景：

- [glibc 2.35 `__malloc_assert`](https://github.com/bminor/glibc/blob/glibc-2.35/malloc/malloc.c)
- [glibc 2.36 `__malloc_assert`](https://github.com/bminor/glibc/blob/glibc-2.36/malloc/malloc.c)
- [glibc 2.35 `libio/wfileops.c`](https://github.com/bminor/glibc/blob/glibc-2.35/libio/wfileops.c)
- [GNU glibc 当前开发分支](https://github.com/bminor/glibc/tree/master)
- [House of all 综述](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/)
- [高版本 heap exploitation](https://roderickchan.github.io/zh-cn/2023-03-01-analysis-of-glibc-heap-exploitation-in-high-version/)

## PoC

- [`poc_malloc_assert_trigger_2.23_2.35.c`](./poc_malloc_assert_trigger_2.23_2.35.c)：真实覆盖 top size，触发 sysmalloc 的断言，并用带缓冲的 fopencookie 严格观察源码里的那次 `fflush(stderr)`；已经在 2.23 和 2.35 上实测通过，同一份程序在 2.36 上不会进入回调，会以退出码 134 结束。

C 文件末尾列出了三段 wide-data 偏移和 stderr fake FILE 的伪代码。这个可执行主体只用来隔离验证 Kiwi 专属的触发器，最终的回调、ROP 链和投递方式仍然要按具体题目替换。

## Python 离线板子

[`kiwi.py`](./kiwi.py) 提供两个函数：

```text
build_house_of_kiwi         -> 返回 KiwiPlan
build_house_of_kiwi_payload -> 返回 top chunk size 字段的 MemoryWrite
```

### 函数用途

Kiwi 不是普通 fake FILE 最终触发点，而是：

```text
覆盖 top size
-> sysmalloc 的 top invariant 断言
-> 旧版 __malloc_assert
-> __fxprintf(NULL, ...)
-> fflush(stderr)
```

本函数只返回触发该路径所需的版本和 top size 参数，不生成 stderr/FILE。

### 最小使用示例

```python
from kiwi import build_house_of_kiwi, build_house_of_kiwi_payload

plan = build_house_of_kiwi(version="2.35", top_size=0x21)

# 返回 KiwiPlan
print(plan.version, hex(plan.top_size), hex(plan.wide_vtable_offset))
# wide_vtable_offset 用于后续 stderr wide FILE 布局

writes = build_house_of_kiwi_payload(
    version="2.35",
    top_size_addr=0x5555000,   # 相邻 top chunk 的 size 字段地址
    top_size=0x21,
)
for w in writes:
    print(w.label, hex(w.address), w.data.hex())
```

### 对应 PoC

- [`poc_malloc_assert_trigger_2.23_2.35.c`](./poc_malloc_assert_trigger_2.23_2.35.c)。

### 参数

| 参数 | 含义 |
|---|---|
| `version` | 目标 glibc 版本，支持 `2.23`～`2.35`。 |
| `top_size` | 要写入相邻 top 的 `size`，默认 `0x21`；需满足对齐并保留 `PREV_INUSE`。 |

### 返回对象 `KiwiPlan`

| 字段 | 含义 |
|---|---|
| `version` | 目标版本。 |
| `top_size` | 要写入的 top size。 |
| `wide_vtable_offset` | 2.23～2.29 为 `0x130`，2.30 为 `0xf0`，2.31～2.35 为 `0xe0`；用于后续 stderr wide FILE 布局。 |

### 返回对象 `MemoryWrite`

`build_house_of_kiwi_payload` 返回一项写入：

```text
address = top_size_addr
data    = top_size 的小端 8 字节
label   = "top chunk size"
```

### 调用者必须提供

```text
能覆盖 top size 的原语
能触发后续 malloc 进入 sysmalloc
2.36 前版本的 stderr 可覆盖能力
wide FILE 布局（Apple/其他消费链）
```

### 函数不负责

```text
不生成 stderr
不生成 fake FILE
不投递 top chunk
2.36+ 不适用（__malloc_assert 已改 __libc_message）
```

## 迁移与调试

1. 覆盖 top size，让 sysmalloc 里的 old-top 不变量检查失败；只是触发一次普通的 `malloc_printerr` 并不等价于真正进入 `__malloc_assert`。
2. 这里控制的是 `stderr` 指向的那份 FILE；`__fxprintf(NULL,...)` 会选中 stderr，随后旧版源码里会显式调用 `fflush(stderr)`。
3. 按 2.23～2.29 / 2.30 / 2.31～2.35 三个区间分别选用对应的 wide-data ABI，并确保 primary vtable 本身合法。
4. 到了 2.36 及以后，即使 Apple2/Apple3 用到的那些最终触发点依然存在，也不能再靠 Kiwi 的 malloc assert 去触发它们了。
