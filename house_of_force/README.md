# House of Force

## 结论

- 适用范围：**glibc 2.23～2.28；2.29 起失效**。
- 原语效果：靠 top chunk 的环绕距离，让下一次 malloc 落到近似任意地址。
- 前置能力：能覆盖 top->size，还能提出超大但不触发别的限制的申请。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 覆盖 top `size` 为超大值；可发出计算后的大申请 |
| 关键环境与不变量 | 目标在 top 线性地址空间；申请不能先被其他限制拒绝 |
| 最终输出原语 | 下一次 malloc 落到近似任意前向地址 |
| 版本边界应如何理解 | 2.29 `top<=system_mem` 硬封超大环绕距离。缩小合法 top 后走 sysmalloc 仍可用，但输出变成 old-top 回收，应归 Tangerine/sysmalloc，而非 Force。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

<!-- CHUNK_SIZE_REQUIREMENTS:START -->
## Chunk size 要求

- **无固定 bin 区间，但必须能提出一个按目标地址精确反算的大 request。** PoC 的 x86-64 公式为 `request = target_user - old_top - 4*SIZE_SZ`；它经 `request2size` 后要让 top split 后的下一次 user pointer 落在目标，不能只申请“任意一个很大的块”。
- 目标在 top 之前时该值会按 `size_t` 环绕成超大整数；题目菜单/解析器必须允许完整传入它，且结果不能落入当时 `REQUEST_OUT_OF_RANGE` 禁止的 SIZE_MAX 尾部。这里不能套用新版本的 `PTRDIFF_MAX` 直觉判断 2.23～2.28。
<!-- CHUNK_SIZE_REQUIREMENTS:END -->

## 版本变化

- 2.29 提交 `30a17d8` 在使用 top 前验证 `size <= av->system_mem`；把 size 改为 -1 会直接报 `corrupted top size`。

## 从源码看

`_int_malloc` 使用 top 的分支。本目录判断以 GNU glibc 对应 tag/提交为准：[2.28 malloc.c](https://github.com/bminor/glibc/blob/glibc-2.28/malloc/malloc.c)、[top-size 修复](https://sourceware.org/git/?p=glibc.git;a=commit;h=30a17d8c95fbfb15c52d1115803b63aaa73a285c)。

版本号只代表上游基线；发行版可能回移检查。实战请按附件 Build ID 对照源码。

## PoC

- [`poc_2.23_2.28.c`](./poc_2.23_2.28.c)：验证 2.23–2.28 分支；成功判据见源码头部。

PoC 为 x86-64 教学程序，故意包含 UAF、越界或 double free。快速验证：

```bash
# 在目录根运行；把版本和文件替换为要测的分支
./tools/run_in_docker.sh 2.39 house_of_force/poc_2.23_2.28.c
```

迁移时保留堆排布和检查绕过，只把漏洞模拟替换为题目的 edit/UAF/overflow；固定地址和最终目标必须重算。

## 调试

通用断点和排查顺序见 [根目录调试顺序](../README.md#调试顺序)。
