# House of Mind（Fastbin 版）

## 结论

- 适用范围：**glibc 2.23～2.42；2.43 起失效**。
- 原语效果：伪造 heap_info/malloc_state，让 free 把堆指针写到任意一个 fake_arena.fastbinsY 槽里。
- 前置能力：一次堆/libc 地址泄露、能做大量对齐布局的分配、能对 NON_MAIN_ARENA 标志位和 arena 结构做单字节或元数据覆盖。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | heap/libc leak；对齐 fake heap_info/malloc_state；改 `NON_MAIN_ARENA`/arena |
| 关键环境与不变量 | fake arena 的 fastbin 槽和 system_mem 可读写；现代 size 检查满足 |
| 最终输出原语 | free 向 fake_arena.fastbinsY 写 heap 指针 |
| 版本边界应如何理解 | 2.27 后是完整 fake arena 适配，2.32 safe-linking 不影响第一写；2.43 删除 fastbin 消费路径，Fastbin 版硬失效。其他 arena 攻击不等于本版存活。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 版本变化

- 2.27 之后的 arena/size 检查变严格了，PoC 因此需要用更完整的 fake arena。
- 2.32 引入的 fastbin fd safe-linking，不影响"把 victim 写进 arena 槽"这第一步。
- 2.37 把 global_max_fast 改成了 uint8_t，但正常大小的 fastbin 依然够用。
- 2.43 删除了 fastbin 的分配/释放路径，fastbin 版本的手法到此终止。

## 从源码看

关键是 `heap_for_ptr`/`arena_for_chunk` 这两个函数，以及 `_int_free` 选择 `av->fastbinsY[idx]` 这条路径。本目录的版本结论以 GNU glibc 对应的 tag/提交为准：[2.42 malloc.c](https://github.com/bminor/glibc/blob/glibc-2.42/malloc/malloc.c)、[2.43 fastbin 删除](https://sourceware.org/git/?p=glibc.git;a=commit;h=bf1015fb2d7e4057925481960626533f8571a2fb)。

版本号只代表上游基线；发行版可能会把某些检查往回移植，实战时还是要按附件的 Build ID 对照源码确认。

## PoC

- [`poc_2.23_2.25.c`](./poc_2.23_2.25.c)：验证 2.23–2.25 分支；成功判据见源码头部。
- [`poc_2.26_2.30.c`](./poc_2.26_2.30.c)：验证 2.26–2.30 分支；成功判据见源码头部。
- [`poc_2.31_2.42.c`](./poc_2.31_2.42.c)：验证 2.31–2.42 分支；成功判据见源码头部。

下面的 PoC 都是 x86-64 教学程序，其中故意包含的 UAF、越界或 double free 都是漏洞模拟。快速验证：

```bash
# 在目录根运行；把版本和文件替换为要测的分支
./tools/run_in_docker.sh 2.39 house_of_mind/poc_2.31_2.42.c
```

迁移到具体题目时，保留堆排布和检查绕过的思路，只需要把漏洞模拟部分换成题目的 edit/UAF/overflow 原语；写死的地址和最终目标都要重新计算。

## 调试

通用的断点位置和排查顺序见 [根目录调试顺序](../README.md#调试顺序)。
