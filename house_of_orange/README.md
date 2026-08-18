# House of Orange（经典链）

## 结论

- 适用范围：**glibc 2.23～2.25；2.26 起经典端到端链失效**。
- 原语效果：无 free 地回收旧 top，再经 `_IO_list_all` FSOP 劫持执行流。
- 前置能力：top size overflow、unsorted metadata 写、可伪造 FILE。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 覆盖 top size；无 free 触发 sysmalloc 回收 old top；unsorted 写；fake FILE |
| 关键环境与不变量 | 2.23 可用任意 vtable，2.24/2.25 需合法 str vtable；malloc 报错时能 flush |
| 最终输出原语 | 无显式 free 回收 old top，并通过 FSOP 取得 CF |
| 版本边界应如何理解 | 这是多段链：2.24 只封堵任意 vtable，可换合法表；2.26 删除 malloc-error→flush 触发；2.28 删除旧 str 回调；2.29 再封堵 House of Force 式 top。old top 回收本身仍是可用的 sysmalloc 原语。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 版本变化

- 2.24/2.25 需使用落在合法 vtable 区间内的 `_IO_str_jumps` 变体。
- 2.26 的 abort/stdio 清理路径变化使经典触发链失效。
- 即使只保留 top 技巧，2.29 的 top-size 检查也会封堵。

## 从源码看

`sysmalloc` 处理旧 top、unsorted 摘链、libio vtable 验证与 abort 清理路径。本目录判断以 GNU glibc 对应 tag/提交为准：[2.25 malloc.c](https://github.com/bminor/glibc/blob/glibc-2.25/malloc/malloc.c)、[2.26 stdlib/abort.c](https://github.com/bminor/glibc/blob/glibc-2.26/stdlib/abort.c)。

版本号只代表上游基线；发行版可能回移检查。实战请按附件 Build ID 对照源码。

## PoC

- [`poc_2.23.c`](./poc_2.23.c)：验证 2.23 分支；成功判据见源码头部。

PoC 为 x86-64 教学程序，故意包含 UAF、越界或 double free。快速验证：

```bash
# 在目录根运行；把版本和文件替换为要测的分支
./tools/run_in_docker.sh 2.39 house_of_orange/poc_2.23.c
```

迁移时保留堆排布和检查绕过，只把漏洞模拟替换为题目的 edit/UAF/overflow；固定地址和最终目标必须重算。

## 调试

通用断点和排查顺序见 [根目录调试顺序](../README.md#调试顺序)。
