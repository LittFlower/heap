# House of Mind（Fastbin 版）

## 结论

- 适用范围：**glibc 2.23～2.42；2.43 失效**。
- 原语效果：伪造 heap_info/malloc_state，让 free 向任意 fake_arena.fastbinsY 槽写堆指针。
- 前置能力：heap/libc 泄露、大量对齐布局、单字节/元数据覆盖 NON_MAIN_ARENA 与 arena。

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

- 2.27 后 arena/size 检查要求更严，PoC 使用更完整 fake arena。
- 2.32 fastbin fd safe-linking 不影响“arena 槽写 victim”的第一步。
- 2.37 global_max_fast 变成 uint8_t，但正常 fastbin 尺寸仍够用。
- 2.43 删除 fastbin 分配/释放路径，fastbin 版本终止。

## 从源码看

`heap_for_ptr`/`arena_for_chunk` 与 `_int_free_chunk` 选择 `av->fastbinsY[idx]` 的路径。本目录判断以 GNU glibc 对应 tag/提交为准：[2.42 malloc.c](https://github.com/bminor/glibc/blob/glibc-2.42/malloc/malloc.c)、[2.43 fastbin 删除](https://sourceware.org/git/?p=glibc.git;a=commit;h=bf1015fb2d7e4057925481960626533f8571a2fb)。

版本号只代表上游基线；发行版可能回移检查。实战请按附件 Build ID 对照源码。

## PoC

- [`poc_2.23_2.25.c`](./poc_2.23_2.25.c)：验证 2.23–2.25 分支；成功判据见源码头部。
- [`poc_2.26_2.30.c`](./poc_2.26_2.30.c)：验证 2.26–2.30 分支；成功判据见源码头部。
- [`poc_2.31_2.42.c`](./poc_2.31_2.42.c)：验证 2.31–2.42 分支；成功判据见源码头部。

PoC 为 x86-64 教学程序，故意包含 UAF、越界或 double free。快速验证：

```bash
# 在目录根运行；把版本和文件替换为要测的分支
./tools/run_in_docker.sh 2.39 house_of_mind/poc_2.31_2.42.c
```

迁移时保留堆排布和检查绕过，只把漏洞模拟替换为题目的 edit/UAF/overflow；固定地址和最终目标必须重算。

## 调试

通用断点和排查顺序见 [根目录调试顺序](../README.md#调试顺序)。
