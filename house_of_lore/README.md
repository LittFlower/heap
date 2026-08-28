# House of Lore / Small Bin Attack

## 结论

- 适用范围：**glibc 2.23～2.43**。
- 原语效果：控制 smallbin 双链后在栈/全局区取得 fake chunk 分配。
- 前置能力：UAF 改 victim->bk；布置至少两组相互引用的 fake chunk；目标对齐。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | UAF 改 smallbin `bk`；布置至少两组互指 fake chunk |
| 关键环境与不变量 | 完整 fd/bk 反向关系、对齐；处理 tcache 容量 |
| 最终输出原语 | malloc 返回栈/全局 fake chunk/AAF |
| 版本边界应如何理解 | 2.26 tcache、2.43 16-slot 都只是排布适配；safe-linking 不编码 smallbin 双链。到 2.43 核心仍可用。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

<!-- CHUNK_SIZE_REQUIREMENTS:START -->
## Chunk size 要求

- victim、两层 fake chunk 和最终请求必须属于**同一个 smallbin class**：物理 `chunksize < MIN_LARGE_SIZE (0x400)`；为了直接进入 smallbin，通常选择 `chunksize > get_max_fast()`，并填满/绕过同尺寸 tcache。
- PoC 用 `malloc(0x100)`，物理 `chunksize=0x110`。这不是唯一 class，但 fake `size`、fd/bk 双链、tcache 填充和最终 request 都必须精确匹配所选 class。
<!-- CHUNK_SIZE_REQUIREMENTS:END -->

## 版本变化

- 所有版本都要求摘链一致性（现代 PoC 显式构造 `victim->fd->bk == victim`）。
- 2.26+ tcache 会截走同尺寸 free，需先填满对应 tcache。
- 2.41 smallbin→tcache stash 重构影响 TSU，但直接 smallbin 摘链的 Lore 还能用。
- 2.43 fastbin 删除与本手法无关。

## 从源码看

`_int_malloc` 的 smallbin 精确大小分支及 `unlink_chunk`。本目录判断以 GNU glibc 对应 tag/提交为准：[2.43 malloc.c](https://github.com/bminor/glibc/blob/master/malloc/malloc.c)。

版本号只代表上游基线；发行版可能回移检查。实战请按附件 Build ID 对照源码。

## PoC

- [`poc_2.23_2.25.c`](./poc_2.23_2.25.c)：验证 2.23–2.25 分支；成功判据见源码头部。
- [`poc_2.26_2.42.c`](./poc_2.26_2.42.c)：验证 2.26–2.42 分支；成功判据见源码头部。
- [`poc_2.43.c`](./poc_2.43.c)：验证 2.43 分支；成功判据见源码头部。

PoC 为 x86-64 教学程序，故意包含 UAF、越界或 double free。快速验证：

```bash
# 在目录根运行；把版本和文件替换为要测的分支
./tools/run_in_docker.sh 2.39 house_of_lore/poc_2.43.c
```

迁移时保留堆排布和检查绕过，只把漏洞模拟替换为题目的 edit/UAF/overflow；固定地址和最终目标必须重算。

## 调试

通用断点和排查顺序见 [根目录调试顺序](../README.md#调试顺序)。
