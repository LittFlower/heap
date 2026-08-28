# House of Roman

## 结论

- 适用范围：**glibc 2.23～2.27；2.28 起经典链失效**。
- 原语效果：在无完整地址泄露时，用相对覆盖把 fake fastbin 导向 hook。
- 前置能力：UAF/溢出、fastbin attack、unsorted-bin attack、若干低位地址猜测。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 无完整泄露；fastbin/tcache 相对覆盖 + unsorted 写 + 低位猜测 |
| 关键环境与不变量 | hook 仍消费；经典 unsorted 目标无需预置；ASLR 低位命中 |
| 最终输出原语 | 无完整 libc 地址下把分配导向 hook 并低字节 CF |
| 版本边界应如何理解 | 2.26/2.27 可通过 tcache 重排，属适配；2.28 硬封经典 unsorted 中段，所以完整 Roman 止于 2.27。额外预置 target/AAW 会破坏其“弱泄露”前提。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

<!-- CHUNK_SIZE_REQUIREMENTS:START -->
## Chunk size 要求

- 原链至少需要两个精确 class：request `0x60` 对应物理 `0x70`，用于把 fastbin/tcache 链相对改到 `__malloc_hook` 附近；request `0x80` 对应物理 `0x90`，用于 unsorted 写入 main_arena 指针。
- 这两个 class 的相邻布局和低字节关系是爆破模型的一部分；2.26～2.27 还要分别处理对应 tcache。题目若只允许一个固定 size，不能直接复现 Roman 完整链。
<!-- CHUNK_SIZE_REQUIREMENTS:END -->

## 版本变化

- 2.23～2.25 走原来的 fastbin 路径。
- 2.26～2.27 改成 count=3 tcache 链，再用 calloc 处理 exact-size unsorted victim。
- 2.28 的 bdc3009 `bck->fd==victim` 检查切断了 hook 投递。
- 2.34 又删掉了 malloc/free hooks。

## 从源码看

fastbin freelist、unsorted `bck->fd` 写和 `__malloc_hook` 调用点的组合。本目录判断以 GNU glibc 对应 tag/提交为准：[2.26 tcache](https://sourceware.org/git/?p=glibc.git;a=commit;h=d5c3fafc4307c9b7a4c7d5cb381fcdbfad340bcc)、[2.28 unsorted 加固](https://sourceware.org/git/?p=glibc.git;a=commit;h=bdc3009b8ff0effdbbfb05eb6b10966753cbf9b8)、[2.34 hooks 删除](https://github.com/bminor/glibc/blob/glibc-2.34/malloc/malloc.c)。

版本号只代表上游基线；发行版可能回移检查。实战按附件 Build ID 对照源码。

## PoC

- [`poc_2.23_2.27.c`](./poc_2.23_2.27.c)：验证 2.23–2.27 分支；成功判据见源码头部。

PoC 为 x86-64 教学程序，故意包含 UAF、越界或 double free。快速验证：

```bash
# 在目录根运行；把版本和文件替换为要测的分支
./tools/run_in_docker.sh 2.39 house_of_roman/poc_2.23_2.27.c
```

迁移时保留堆排布和检查绕过，只把漏洞模拟换成题目的 edit/UAF/overflow；固定地址和最终目标得重算。

## 调试

通用断点和排查顺序见 [根目录调试顺序](../README.md#调试顺序)。
