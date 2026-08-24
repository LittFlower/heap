# House of Apple 3

## 结论

- 适用范围：**glibc 2.23～2.43 的 codecvt 最终触发点均可到达**；经典 largebin 投递止于 2.41，2.42+ 必须另有 FILE 覆盖原语。
- 原语/效果：保留合法 `_IO_wfile_jumps`，劫持 `FILE->_codecvt`，让宽字符转换路径调用 fake codecvt/gconv step 中的函数指针。
- 关键版本：2.23～2.29 是 codecvt 直接函数表；2.30 删除该表并使用 legacy `_IO_iconv_t` union；2.31 起简化为 `step + step_data`，持续到 2.43。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 控制 FILE `_codecvt` 及 fake gconv step；触发宽字符 underflow |
| 关键环境与不变量 | codecvt/step 三代布局；合法 primary vtable |
| 最终输出原语 | codecvt 函数指针间接调用 |
| 版本边界应如何理解 | 2.30/2.31 是 ABI 适配；经典 largebin 2.42 结束只影响常见投递，不证明 codecvt 最终触发点失效。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 从源码看

本目录的可执行 C PoC 都用真实宽字符 FILE，经 `fgetwc → _IO_wfile_underflow` 触发，primary vtable 从未离开合法 `_IO_wfile_jumps`。因此 2.24 的 libio vtable validation 不会封住 codecvt 数据流。

### glibc 2.23～2.29：直接 codecvt vtable

旧 `_IO_codecvt` 以 8 个兼容 libstdc++ codecvt 的函数指针开头。`_IO_wfile_underflow` 直接调用：

```c
status = (*cd->__codecvt_do_in)(cd, state, from_start, from_end,
                                &from_stop, to_start, to_end, &to_stop);
```

x86-64 的 `__codecvt_do_in` 位于 `codecvt+0x18`，所以这一段甚至不需要再伪造 `__gconv_step`。

### glibc 2.30：单版本过渡 union

提交 [`09e1b0e`](https://sourceware.org/git/?p=glibc.git;a=commit;h=09e1b0e3f6facc1af2dbcfef204f0aaa8718772b) 删除 codecvt 直接函数表，`_IO_wfile_underflow` 改调 `__libio_codecvt_in`。此时 `_IO_iconv_t` 仍包含 `struct __gconv_info`：

```text
fake codecvt +0x00  __nsteps
             +0x08  __steps -> fake __gconv_step
             +0x10  __data[0]
fake step    +0x00  __shlib_handle
             +0x28  __fct
```

### glibc 2.31～2.43：现代 `_IO_iconv_t`

提交 [`70c6e15`](https://sourceware.org/git/?p=glibc.git;a=commit;h=70c6e15654928c603c6d24bd01cf62e7a8e2ce9b) 把 `_IO_iconv_t` 简化为：

```c
struct {
  struct __gconv_step *step;       // codecvt + 0x00
  struct __gconv_step_data data;   // codecvt + 0x08
};
```

`__gconv_step.__fct` 仍在 `step+0x28`。源码会在 `step->__shlib_handle != NULL` 时 `PTR_DEMANGLE(fct)`；常用 fake step 应令该字段为 0，才能按明文函数指针调用。

除 `codecvt_in` 外，原文还分析了 out/length、`_IO_wfile_underflow_mmap`、`_IO_wdo_write` 与 `_IO_wfile_sync` 等入口。它们的分支条件不同，不能只复制本目录 underflow 的 buffer 字段。

源码与背景：

- [glibc 2.29 `libio/wfileops.c`](https://github.com/bminor/glibc/blob/glibc-2.29/libio/wfileops.c)
- [glibc 2.30 `libio/iofwide.c`](https://github.com/bminor/glibc/blob/glibc-2.30/libio/iofwide.c)
- [glibc 2.43 `libio/iofwide.c`](https://sourceware.org/cgit/glibc/tree/libio/iofwide.c?h=release/2.43/master)
- [glibc 2.43 `iconv/gconv.h`](https://sourceware.org/cgit/glibc/tree/iconv/gconv.h?h=release/2.43/master)
- [House of Apple 3 原始文章](https://roderickchan.github.io/zh-cn/house-of-apple-%E4%B8%80%E7%A7%8D%E6%96%B0%E7%9A%84glibc%E4%B8%ADio%E6%94%BB%E5%87%BB%E6%96%B9%E6%B3%95-3/)

## PoC

- [`poc_codecvt_vtable_sink_2.23_2.29.c`](./poc_codecvt_vtable_sink_2.23_2.29.c)：覆盖 `codecvt+0x18` 的直接 `do_in`；已实测 2.23/2.29。
- [`poc_codecvt_sink_2.30.c`](./poc_codecvt_sink_2.30.c)：`codecvt+0x8 → step+0x28` 的 legacy union；已实测精确 2.30 首发包。
- [`poc_codecvt_sink_2.31_2.43.c`](./poc_codecvt_sink_2.31_2.43.c)：`codecvt+0x0 → step+0x28` 的现代布局；已实测 2.31/2.43。

三份 C PoC 自身就是三段 fake codecvt/step 布局，并以 `fgetwc == L'3'` 和回调次数作为严格成功判据；无需再生成脱离消费路径的静态字节串。

## Python 离线板子

[`apple3.py`](./apple3.py) 按三份 PoC 生成 `_codecvt`、fake step、wide buffer 和 FILE 入口字段。

```python
from apple3 import build_house_of_apple3

writes = build_house_of_apple3(
    "2.35",
    file_addr=fake_file,
    fake_codecvt_addr=fake_codecvt,
    fake_step_addr=fake_step,
    callback_addr=callback,
    wide_data_addr=wide_data,
    wide_output_addr=wide_output,
    external_input_addr=input_buffer,
    current_flags=known_flags,
)
```

| 参数 | 含义 |
|---|---|
| `version` | 目标 glibc 版本；2.23～2.29 使用 codecvt `+0x18`，2.30 使用 `+0x08 -> step`，2.31～2.43 使用 `+0x00 -> step`。 |
| `file_addr` | 被覆盖的 FILE 地址。 |
| `fake_codecvt_addr` | fake `_IO_codecvt`/`_IO_iconv_t` 地址，写入 `FILE + 0x98`。 |
| `fake_step_addr` | 2.30 及以上 fake `__gconv_step` 地址；旧 ABI 不消费该对象，但仍要求显式传入以避免隐式地址推导。 |
| `callback_addr` | codecvt `do_in` 或 `__gconv_step.__fct` 回调地址。 |
| `wide_data_addr` | 真实或 fake `_IO_wide_data` 地址，写入 `FILE + 0xa0`。 |
| `wide_output_addr` | wide buffer 起点；PoC 按 `+0x20` 生成结束地址。 |
| `external_input_addr` | 窄字符输入区起点；PoC 用一字节输入让 `fgetwc` 进入转换路径。 |
| `current_flags` | 已知 `_flags` 时传入；函数清除 `EOF_SEEN` 和 `NO_READS`，未知时省略。 |

返回 `MemoryWrite` 元组。函数只生成消费点布局，不负责 libc 投递、primary vtable、`fgetwc` 触发或 callback 后续逻辑。

## 迁移与调试

1. 先按版本选择三段 ABI，尤其不要把 2.30 的 `step@+0x8` 误套成 2.31 的 `+0x0`。
2. 保留 `_IO_wfile_jumps` 或其合法 section 内偏移；按所选 underflow/out/sync 入口设置 primary 槽和 FILE 筛选字段。
3. 若走 gconv step，令 `__shlib_handle=0`；非零时 `__fct` 需要按 pointer_guard 编码。
4. 在 `_IO_wfile_underflow`、`__libio_codecvt_in` 和 fake 回调处下断点，确认窄 read buffer 非空、wide read buffer 为空且输出区有效。
5. 2.42～2.43 不要再假设经典 largebin 能把 fake FILE 投到 `_IO_list_all`；最终触发点存在与投递存在是两件事。
