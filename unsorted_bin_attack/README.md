# Unsorted Bin Attack

## 结论

- 适用范围：**glibc 2.23～2.27；2.28 起经典形式失效**。
- 原语效果：向目标写入 `unsorted_chunks(av)`；2.23～2.27 target 初值任意，2.28+ 要求 target 预置 victim。
- 前置能力：UAF 改写 unsorted victim 的 `bk`；2.28+ 另需建立 `target == victim_chunk`。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | UAF 改 victim `bk` |
| 关键环境与不变量 | 经典版目标任意初值；2.28+ 目标必须预先等于 victim |
| 最终输出原语 | 向目标写 unsorted head/libc 指针 |
| 版本边界应如何理解 | 2.28 硬封“只改 `bk`、目标任意初值”的弱前置；赋值语句仍在，预置 `target==victim` 可到 2.43，但这应标**强约束残余**，不能冒充经典 AAW。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

<!-- CHUNK_SIZE_REQUIREMENTS:START -->
## Chunk size 要求

- victim 必须真正进入 unsorted bin：尺寸不能停在 fastbin/tcache；最稳妥是物理 `chunksize` 高于当前 small-tcache 上限，或填满 tcache 后使用高于 `get_max_fast()` 的 class。
- PoC 用 `malloc(0x410) -> chunksize 0x420`。触发摘链的请求需能消费/处理该 victim；2.28+ 的受约束版还要求 target 预置 victim，但没有额外固定数值。
<!-- CHUNK_SIZE_REQUIREMENTS:END -->

## 版本变化

- 2.23～2.27 摘链时信任 `victim->bk`，能让 `bck->fd` 指向任意初值 target。
- 2.28 提交 `bdc3009` 检查 `bck->fd == victim`，经典无条件单指针写结束；2.29 再加入 next-size 等检查。

## 从源码看

unsorted 遍历中的 `bck = victim->bk; if (bck->fd != victim) ...; bck->fd = unsorted_chunks(av)`。本目录判断以 GNU glibc 对应 tag/提交为准：[2.28 首次 harden removal](https://sourceware.org/git/?p=glibc.git;a=commit;h=bdc3009b8ff0effdbbfb05eb6b10966753cbf9b8)、[2.29 后续加固](https://sourceware.org/git/?p=glibc.git;a=commit;h=b90ddd08f6dd688e651df9ee89ca3a69ff88cd0c)。

版本号只代表上游基线；发行版可能回移检查。实战请按附件 Build ID 对照源码。

## PoC

- [`poc_2.23_2.27.c`](./poc_2.23_2.27.c)：验证 2.23–2.27 分支；成功判据见源码头部。
- [`poc_constrained_2.28_2.43.c`](./poc_constrained_2.28_2.43.c)：验证 constrained–2.28–2.43 分支；成功判据见源码头部。

PoC 为 x86-64 教学程序，故意包含 UAF、越界或 double free。快速验证：

```bash
# 在目录根运行；把版本和文件替换为要测的分支
./tools/run_in_docker.sh 2.39 unsorted_bin_attack/poc_constrained_2.28_2.43.c
```

迁移时保留堆排布和检查绕过，只把漏洞模拟替换为题目的 edit/UAF/overflow；固定地址和最终目标必须重算。

## 调试

通用断点和排查顺序见 [根目录调试顺序](../README.md#调试顺序)。
