# House of Obstack

## 结论

- 适用范围：**经典 _IO_obstack_jumps 为 2.23～2.36；2.37 起旧链消失**。
- 原语/效果：从合法 obstack IO vtable 进入 _obstack_newchunk，再调用受控 chunkfun(extra_arg,size)。
- 版本变化：2.36 仍有 _IO_obstack_jumps；2.37 printf 重构删除旧 vtable 路径，改为 __printf_buffer_flush_obstack，即 House of Snake。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 可控 obstack FILE/对象，并能触发旧 printf 后端 |
| 关键环境与不变量 | 使用合法 `_IO_obstack_jumps`；`chunkfun`/`extra_arg` 字段正确 |
| 最终输出原语 | 经 `_obstack_newchunk→chunkfun` 间接调用 |
| 版本边界应如何理解 | 2.37 移除旧 libio obstack 后端，消费路径彻底消失；House of Snake 使用的是新路径，不是偏移修复。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 从源码看

libio/obprintf.c、libio/vtables.c 与 2.37 stdio-common/printf_buffer_flush.c。

源码中仍能走到最终触发点，不等于旧利用链仍成立：投递方式、私有结构和控制流终点都要按附件 libc/ld 的 Build ID 复核。

源码与背景：

- [glibc 2.36 `libio/obprintf.c`](https://github.com/bminor/glibc/blob/glibc-2.36/libio/obprintf.c)
- [glibc 2.36 `libio/vtables.c`](https://github.com/bminor/glibc/blob/glibc-2.36/libio/vtables.c)
- [glibc 2.37 `printf_buffer_flush.c`](https://github.com/bminor/glibc/blob/glibc-2.37/stdio-common/printf_buffer_flush.c)
- [提交 `5365acc`：obstack printf 改为 buffers](https://sourceware.org/git/?p=glibc.git;a=commit;h=5365acc567a49270b4341b9d325794ec554258d9)
- [GNU glibc 当前开发分支](https://github.com/bminor/glibc/tree/master)
- [House of all 综述](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/)
- [高版本 heap exploitation](https://roderickchan.github.io/zh-cn/2023-03-01-analysis-of-glibc-heap-exploitation-in-high-version/)

## PoC

- [`poc_chunkfun_sink_2.23_2.36.c`](./poc_chunkfun_sink_2.23_2.36.c)：公开 API 建立真实 obstack 并强制扩容，严格验证旧 `_IO_obstack_jumps → _obstack_newchunk → chunkfun(extra_arg,size)` 最终触发点；已实测 2.23/2.36。

C PoC 使用合法 API 设置回调，所以 API 本身不是漏洞；文件末尾的中文伪代码说明题目侧 fake FILE/obstack 布局。

## Python 离线板子

```python
from obstack import build_obstack_plan
plan = build_obstack_plan(
    object_base=chunk_base,
    next_free=chunk_end,
    chunkfun_addr=callback,
    extra_arg=callback_arg,
)
```

| 参数 | 含义 |
|---|---|
| `object_base` | 当前 obstack chunk 起点。 |
| `next_free` | 当前写指针；与 `chunk_limit` 相等时扩容立即发生。 |
| `chunk_limit` | 当前 chunk 上限，省略时取 `next_free`。 |
| `chunkfun_addr` | `_obstack_newchunk` 调用的分配回调。 |
| `extra_arg` | callback 第一个参数。 |

返回 `ObstackPlan`，只描述 `chunkfun(extra_arg, new_size)` 的参数来源，不生成旧 FILE vtable 或题目投递数据。

## 迁移与调试

1. 2.24～2.36 让 FILE vtable 指向合法 `_IO_obstack_jumps`；2.23 没有 vtable 白名单，但仍可使用同一表。
2. 让 `next_free == chunk_limit` 并保证输出还要追加数据，迫使 `_obstack_newchunk` 调用 `chunkfun(extra_arg, new_size)`。
3. `chunkfun` 的第一个参数是 `extra_arg`，不是 size；若最终接 gadget/system，必须按调用约定选择目标。
4. 2.37+ 不再寻找旧 FILE vtable，改看 House of Snake。
