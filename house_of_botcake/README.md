# House of Botcake

## 结论

- 适用范围：**glibc 2.26～2.43**。
- 原语效果：绕过 tcache double-free 检测并制造可反复利用的 chunk overlap/poisoning。
- 前置能力：UAF；约 8～10 个同尺寸 chunk；能让 victim 与前块在 unsorted 合并。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | tcache UAF；能让 victim 与前块在 unsorted 合并 |
| 关键环境与不变量 | 足够同尺寸块；绕 key；按 2.43 的 16-slot 重排 |
| 最终输出原语 | overlap、重复引用，继续做 tcache poisoning |
| 版本边界应如何理解 | 2.26～2.43 是堆排布适配；key/full-bin 扫描没有删除“合并后再次 free 同一物理块”这条身份变化。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 版本变化

- 2.26～2.31 使用明文 tcache next。
- 2.32 起覆盖 victim->next 时必须 safe-linking 编码。
- 2.34 tcache key 改随机值不封堵本法，因为第二次 free 前 victim 已随合并离开原 tcache 语义。
- 2.42/2.43 tcache 元数据变化后仍有对应 PoC。

## 从源码看

tcache key 检查只搜索当前 bin；unsorted 后向合并改变覆盖范围。本目录判断以 GNU glibc 对应 tag/提交为准：[2.43 malloc.c](https://github.com/bminor/glibc/blob/master/malloc/malloc.c)、[2.29 tcache double-free 检查](https://sourceware.org/git/?p=glibc.git;a=commit;h=bcdaad21d4635931d1bd3b54a7894276925d081d)。

版本号只代表上游基线；发行版可能回移检查。实战请按附件 Build ID 对照源码。

## PoC

- [`poc_2.26_2.31.c`](./poc_2.26_2.31.c)：验证 2.26–2.31 分支；成功判据见源码头部。
- [`poc_2.32_2.42.c`](./poc_2.32_2.42.c)：验证 2.32–2.42 分支；成功判据见源码头部。
- [`poc_2.43.c`](./poc_2.43.c)：验证 2.43 分支；成功判据见源码头部。

PoC 为 x86-64 教学程序，故意包含 UAF、越界或 double free。快速验证：

```bash
# 在目录根运行；把版本和文件替换为要测的分支
./tools/run_in_docker.sh 2.39 house_of_botcake/poc_2.43.c
```

迁移时保留堆排布和检查绕过，只把漏洞模拟替换为题目的 edit/UAF/overflow；固定地址和最终目标必须重算。

## 调试

通用断点和排查顺序见 [根目录调试顺序](../README.md#调试顺序)。
