# Large Bin Attack

## 结论

- 适用范围：**glibc 2.23～2.41；2.42 起经典 `bk_nextsize` 写失效**。
- 原语效果：把新插入 victim 的堆地址写到目标。
- 前置能力：UAF 改写 largebin 节点的 `bk_nextsize`；两个属于同一 largebin 且大小有序的 chunk。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | UAF 改 largebin 节点的 nextsize 指针 |
| 关键环境与不变量 | 两个同 bin、有序 chunk；目标可写 |
| 最终输出原语 | 把 victim heap 指针写到目标 |
| 版本边界应如何理解 | 2.30 是同一家族的新插入分支，属于换实现；2.42 检查 nextsize 反向环，经典“只改一个 `bk_nextsize`、任意初值目标”被封堵。若能预构造整套 fake ring，赋值仍可能发生，但那是**强前置残余**。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 版本变化

- 2.30 以前可同时改 `bk` 与 `bk_nextsize`，写条件更宽松。
- 2.30～2.41 使用“比当前最小节点更小”的插入分支，只需劫持最小节点的 `bk_nextsize`。
- 2.42 提交 `4cf2d86` 增加 `fwd->fd->bk_nextsize->fd_nextsize == fwd->fd`，目标不再能只是任意可写地址。

## 从源码看

`_int_malloc` 将 unsorted victim 排入 largebin 时维护 `fd_nextsize/bk_nextsize` 的分支。本目录判断以 GNU glibc 对应 tag/提交为准：[2.41 malloc.c](https://github.com/bminor/glibc/blob/glibc-2.41/malloc/malloc.c)、[2.42 nextsize 检查](https://sourceware.org/git/?p=glibc.git;a=commit;h=4cf2d869367e3813c6c8f662915dedb1f3830c53)。

版本号只代表上游基线；发行版可能回移检查。实战请按附件 Build ID 对照源码。

## PoC

- [`poc_2.23_2.29.c`](./poc_2.23_2.29.c)：验证 2.23–2.29 分支；成功判据见源码头部。
- [`poc_2.30_2.41.c`](./poc_2.30_2.41.c)：验证 2.30–2.41 分支；成功判据见源码头部。

PoC 为 x86-64 教学程序，故意包含 UAF、越界或 double free。快速验证：

```bash
# 在目录根运行；把版本和文件替换为要测的分支
./tools/run_in_docker.sh 2.39 large_bin_attack/poc_2.30_2.41.c
```

迁移时保留堆排布和检查绕过，只把漏洞模拟替换为题目的 edit/UAF/overflow；固定地址和最终目标必须重算。

## 调试

通用断点和排查顺序见 [根目录调试顺序](../README.md#调试顺序)。
