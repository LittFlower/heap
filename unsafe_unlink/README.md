# Unsafe Unlink（现代约束版）

## 结论

- 适用范围：**glibc 2.23～2.43**。
- 原语效果：借助向后合并改写一个受害者指针，进而形成一次可控写。
- 前置能力：能溢出伪造出一个 free chunk、清除 PREV_INUSE，并满足 `fd->bk == P && bk->fd == P`。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | heap overflow 伪造 free chunk 并清 `PREV_INUSE` |
| 关键环境与不变量 | `fd->bk==P && bk->fd==P`；2.26+/2.29+ size/prev_size 一致 |
| 最终输出原语 | 改写受害者指针，升级为受约束 AAW |
| 版本边界应如何理解 | 本范围没有删除 unlink 消费路径；2.26、2.29 是必须补齐的不变量，属于适配。若题目只有单字段写而不能建双链，则从一开始就不满足前置。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 版本变化

- 现代 glibc 都有双向链表检查，所以不再是早期那种对任意 `FD/BK` 的无条件两次写。
- 2.29：增加了 `chunksize(p) == prev_size(next_chunk(p))` 检查，off-by-null 这条链路需要额外的伪造/合并步骤。
- 这个双链 unlink 本身不使用 safe-linking，所以 2.32 不会直接封堵它。

## 从源码看

关键在于 `unlink_chunk` 里 size/prev_size 与 fd/bk 这两组一致性检查。本目录的版本结论以 GNU glibc 对应 tag/提交为准，参考：[2.43 开发分支 unlink_chunk](https://github.com/bminor/glibc/blob/master/malloc/malloc.c)、[2.29 null-byte 加固](https://sourceware.org/git/?p=glibc.git;a=commit;h=d6db68e66dff25d12c3bc5641b60cbd7fb6ab44f)。

版本号只代表上游基线；发行版可能回移检查，实战时请按附件的 Build ID 对照源码确认。

## PoC

- [`poc_2.23_2.25.c`](./poc_2.23_2.25.c)：验证 2.23–2.25 分支，成功判据见源码头部。
- [`poc_2.26_2.28.c`](./poc_2.26_2.28.c)：验证 2.26–2.28 分支，成功判据见源码头部。
- [`poc_2.29_2.43.c`](./poc_2.29_2.43.c)：验证 2.29–2.43 分支，成功判据见源码头部。

下面的 PoC 都是 x86-64 教学程序，其中的 UAF、越界或 double free 都是特意模拟出来的漏洞行为。快速验证：

```bash
# 在目录根运行；把版本和文件替换为要测的分支
./tools/run_in_docker.sh 2.39 unsafe_unlink/poc_2.29_2.43.c
```

迁移到具体题目时，堆排布和检查绕过的思路不用改，只需要把漏洞模拟部分换成题目实际提供的 edit/UAF/overflow 原语；写死的地址和最终目标都要按题目重新计算。

## 调试

通用的断点位置和排查顺序见[根目录调试顺序](../README.md#调试顺序)。
