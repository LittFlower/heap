# House of IO

## 结论

- 适用范围：**glibc 原始 PoC 2.31～2.33；2.34 起失效**。
- 原语效果：控制 `tcache_perthread_struct` 中未编码的 `entries`，无需堆地址泄露即可任意分配。
- 前置能力：能把 tcache 管理结构当作 free chunk（特定 underflow/UAF/错误 free）。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 能把 `tcache_perthread_struct` 当作 free chunk，或制造下溢；无需堆地址泄露 |
| 关键环境与不变量 | 区分 2.29/2.30 的元数据布局；依赖 UAF 读取 `key` 泄露 tcache 地址 |
| 最终输出原语 | 控制明文 `entries`，取得无堆地址泄露的 AAF |
| 版本边界应如何理解 | 2.34 将 `key` 改为随机值，原“`key` 就是元数据地址”的信息通道硬失效。若另有元数据地址泄露/AAW，仍可通过普通 metadata poisoning 取得相同输出，但那已不是原始 House of IO。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 版本变化

- 2.32 safe-linking 只保护 chunk 内 next，不保护当时的 tcache entries 头，因此形成旁路。
- 2.34 tcache key 改为随机进程值并调整相关初始化/检查；how2heap 的原始链范围止于 2.33。
- 2.42 后出现的是不同的 metadata hijacking，不应继续称原始 House of IO。

## 从源码看

2.31～2.33 `tcache_entry.key=tcache` 与明文 `tcache->entries[idx]`。本目录判断以 GNU glibc 对应 tag/提交为准：[2.33 malloc.c](https://github.com/bminor/glibc/blob/glibc-2.33/malloc/malloc.c)、[2.34 malloc.c](https://github.com/bminor/glibc/blob/glibc-2.34/malloc/malloc.c)。

版本号只代表上游基线；发行版可能回移检查。实战请按附件 Build ID 对照源码。

## PoC

- [`poc_2.29.c`](./poc_2.29.c)：验证 2.29 分支；成功判据见源码头部。
- [`poc_2.30_2.33.c`](./poc_2.30_2.33.c)：验证 2.30–2.33 分支；成功判据见源码头部。

PoC 为 x86-64 教学程序，故意包含 UAF、越界或 double free。快速验证：

```bash
# 在目录根运行；把版本和文件替换为要测的分支
./tools/run_in_docker.sh 2.39 house_of_io/poc_2.30_2.33.c
```

迁移时保留堆排布和检查绕过，只把漏洞模拟替换为题目的 edit/UAF/overflow；固定地址和最终目标必须重算。

## 调试

通用断点和排查顺序见 [根目录调试顺序](../README.md#调试顺序)。
