# House of Lore / Small Bin Attack

## 结论

- 适用范围：**glibc 2.23～2.43**。
- 原语效果：控制 smallbin 的双向链表后，让 malloc 在栈上或全局区分配到一个伪造的 fake chunk。
- 前置能力：一次 UAF，用来改写 victim 的 bk 指针；布置至少两组相互引用的 fake chunk；目标地址要满足对齐要求。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | UAF 改 smallbin `bk`；布置至少两组互指 fake chunk |
| 关键环境与不变量 | 完整 fd/bk 反向关系、对齐；处理 tcache 容量 |
| 最终输出原语 | malloc 返回栈/全局 fake chunk/AAF |
| 版本边界应如何理解 | 2.26 tcache、2.43 16-slot 都只是排布适配；safe-linking 不编码 smallbin 双链。到 2.43 核心仍可用。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 版本变化

- 所有版本都要求摘链一致性成立（现代 PoC 会显式构造出 `victim->fd->bk == victim` 这个条件）。
- 2.26 起有了 tcache，它会先截走同尺寸的 free 块，所以要先填满对应的 tcache，才能让 victim 真正进入 smallbin。
- 2.41 把 smallbin→tcache 的 stash 逻辑重构了，这会影响 TSU 那一类手法；但直接走 smallbin 摘链的 Lore 本身不受影响，仍然可用。
- 2.43 删除了 fastbin，跟本手法没有关系。

## 从源码看

关键代码是 `_int_malloc` 里精确匹配 smallbin size 的分支，以及执行摘链的 `unlink_chunk`。本目录的版本结论以 GNU glibc 对应 tag/提交为准，参考：[2.43 malloc.c](https://github.com/bminor/glibc/blob/master/malloc/malloc.c)。

版本号只代表上游基线；发行版可能会回移检查，实战时请按附件的 Build ID 对照源码确认。

## PoC

- [`poc_2.23_2.25.c`](./poc_2.23_2.25.c)：验证 2.23–2.25 分支，成功判据见源码头部。
- [`poc_2.26_2.42.c`](./poc_2.26_2.42.c)：验证 2.26–2.42 分支，成功判据见源码头部。
- [`poc_2.43.c`](./poc_2.43.c)：验证 2.43 分支，成功判据见源码头部。

下面的 PoC 都是 x86-64 教学程序，其中的 UAF、越界或 double free 都是特意模拟出来的漏洞行为。快速验证：

```bash
# 在目录根运行；把版本和文件替换为要测的分支
./tools/run_in_docker.sh 2.39 house_of_lore/poc_2.43.c
```

迁移到具体题目时，堆排布和检查绕过的思路不用改，只需要把漏洞模拟部分换成题目实际提供的 edit/UAF/overflow 原语；写死的地址和最终目标都要按题目重新计算。

## 调试

通用的断点位置和排查顺序见[根目录调试顺序](../README.md#调试顺序)。
