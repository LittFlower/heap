# House of Rust

## 先说结论

优先阅读汇总 PoC；需要单步调试时，再看每个只讲一个子原语的 C 文件：

| 文件 | 实际验证内容 | 版本 |
|---|---|---|
| [`poc_summary_2.32.c`](./poc_summary_2.32.c) | 一次运行依次验证 TSU+、TSU、largebin、stdout 泄漏和 `__free_hook`；文件末尾给出共享堆衔接伪代码 | 2.32 |
| [`poc_component_tsu_plus_2.32_2.40.c`](./poc_component_tsu_plus_2.32_2.40.c) | TSU+：修改 smallbin `bk`，让 malloc 返回目标地址 | 2.32～2.40 |
| [`poc_component_tsu_2.32_2.40.c`](./poc_component_tsu_2.32_2.40.c) | 标准 TSU：触发 smallbin stashing 并取回伪节点 | 2.32～2.40 |
| [`poc_component_largebin_2.32_2.40.c`](./poc_component_largebin_2.32_2.40.c) | post-2.30 largebin：通过 `bk_nextsize` 写目标 | 2.32～2.40 |
| [`poc_stage4_stdout_leak_2.32_2.40.c`](./poc_stage4_stdout_leak_2.32_2.40.c) | 直接覆盖 stdout 字段，由 `fflush` 输出目标内存 | 2.32～2.40 |
| [`poc_stage5_free_hook_2.32_2.33.c`](./poc_stage5_free_hook_2.32_2.33.c) | 直接写 `__free_hook`，由 `free` 触发回调 | 2.32～2.33 |

原作者公开仓库只有阶段说明，没有公开完整 exploit。汇总文件真实执行五个消费阶段，但各阶段使用独立子进程隔离被故意破坏的 bin 状态；它不会冒充约 65 次分配的题目级共享堆完整链。端到端 exploit 仍必须按题目的 add/edit/free 菜单、slot 生命周期、WAF overlap 和附件 Build ID 落地。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | TSU+、TSU、两次现代 largebin、stdout FSOP；原版无需堆地址泄露 |
| 关键环境与不变量 | 绕过 safe-linking；精确控制堆布局；使用匹配 2.32 的构建与终点 |
| 最终输出原语 | 无泄露地控制 libc/heap，并取得 RCE |
| 版本边界应如何理解 | 原版完整链只验证到 2.32。2.34 起 hook 终点失效，但可研究替代终点；2.41 删除 TSU 消费路径后，组合链的核心失效。组件仍可用，不等于完整 Rust 仍可用。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 三分钟运行

在 cheatsheet 根目录执行：

```bash
./tools/run_in_docker.sh 2.32 house_of_rust/poc_summary_2.32.c
./tools/run_in_docker.sh 2.32 house_of_rust/poc_component_tsu_plus_2.32_2.40.c
./tools/run_in_docker.sh 2.32 house_of_rust/poc_component_tsu_2.32_2.40.c
./tools/run_in_docker.sh 2.32 house_of_rust/poc_component_largebin_2.32_2.40.c
./tools/run_in_docker.sh 2.32 house_of_rust/poc_stage4_stdout_leak_2.32_2.40.c
./tools/run_in_docker.sh 2.32 house_of_rust/poc_stage5_free_hook_2.32_2.33.c
```

检查窗口末端和 hook 断点：

```bash
./tools/run_in_docker.sh 2.40 house_of_rust/poc_component_tsu_plus_2.32_2.40.c
./tools/run_in_docker.sh 2.40 house_of_rust/poc_component_tsu_2.32_2.40.c
./tools/run_in_docker.sh 2.40 house_of_rust/poc_component_largebin_2.32_2.40.c
./tools/run_in_docker.sh 2.40 house_of_rust/poc_stage4_stdout_leak_2.32_2.40.c
./tools/run_in_docker.sh 2.33 house_of_rust/poc_stage5_free_hook_2.32_2.33.c
```

汇总文件最后应输出 `汇总演示完成`；五个拆分文件分别输出一个直接判据：

```text
[+] TSU+ 返回目标
[+] TSU 返回目标
[+] largebin 写入目标
[+] stdout 泄漏成功
[+] free_hook 回调命中
```

`free_hook` 文件只标 2.32～2.33。2.34 起主路径已经不再消费 hook，因此不加入动态查符号、解析版本号之类的兼容代码；边界直接写在文件名和版本表中。

## 每个 C 文件怎么读

### 堆管理器子原语

前三个文件都从 `main` 第一行顺序向下真实调用目标 libc 的 `malloc/calloc/free`：

1. TSU+ 修改 smallbin victim 的 `bk`，最终要求 `malloc` 精确返回栈上 `target`；
2. 标准 TSU 走 smallbin stashing 的 `bck->fd` 写和伪节点暂存；
3. largebin 文件使用 0x430/0x420 物理 chunk，精确断言写入值是新 victim 的 chunk 头。

原版 Rust 会在第二阶段和第三阶段使用两组不同 largebin；第二组只是换到另一个 largebin 尺寸，写原语本身相同。迁移题目时要把三个子原语重新放回同一条共享堆时间线。

### stdout 泄漏最终触发点

输入原语是“已经获得 `_IO_2_1_stdout_` 字段覆盖”。程序直接把 `_IO_write_base/_IO_write_ptr` 指到 `secret`，再调用一次 `fflush`。终端出现 `stdout 泄漏成功` 就是消费成功。

它验证的是消费端，不验证 Rust 的 1/16 libc 低位猜测，也不验证 tcache head 已经被导向 stdout。实际题目必须在第一次真实 stdout 活动处下断点；“FILE 字段看起来改了”不等于已经泄漏。

### `__free_hook` 边界

glibc 2.34 的关键不是兼容符号是否还能解析，而是 `free` 主路径不再调用 hook。本目录只保留 2.32～2.33 的最短正向 PoC：赋值 `__free_hook=win`，然后 `free(chunk)`，最后断言回调命中。

| 版本 | `__free_hook` 符号 | `free` 是否消费 | 原版阶段五 |
|---|---|---:|---|
| 2.32～2.33 | 可用 | 是 | 仍可验证原终点 |
| 2.34～2.40 | 可能仍有兼容符号 | 否 | 本文件不适用，必须换最终触发点|

## 汇总 PoC 怎么读

[`poc_summary_2.32.c`](./poc_summary_2.32.c) 仍保持线性阅读：`main` 中依次出现五个阶段，父进程逐段等待子进程成功。前三段真实执行对应 bin 操作；第四段真实覆盖并消费 stdout；第五段真实写入并消费 `__free_hook`。子进程只用于隔离上一段留下的伪 bin 状态，不封装利用步骤。

文件末尾的注释保存了原先条件检查器承担的内容：约 65 次分配、0x1b00 最大 request、两组尺寸类、低四位猜测、stdout 触发点，以及 2.34/2.41 两个关键边界。它们明确标为题目迁移伪代码，不会被误认为运行一次就能自动满足的前置条件。

## 从源码看版本边界

原版阶段可拆成：

1. 约 65 次分配，准备 14 个 0x90 class、15 个 0xa0 class、两组 largebin 与 WAF overlap；
2. TSU+ 的双重归属破坏 smallbin `fd/bk`，第一次 largebin 写修复 `fd`，取得 tcache metadata 内 chunk；
3. TSU 与第二次 largebin 在 metadata 邻近位置留下 libc 指针；
4. 猜 libc 低四位，把后续写导向 stdout，覆盖 FILE 字段并触发真实泄漏；
5. 原版把泄漏后的写投递到 `__free_hook`，写入 `system` 后 `free("/bin/sh")`。

版本审计必须把“投递”与“终点”拆开：

- 2.32：原作者完整链的目标版本；safe-linking 已存在；
- 2.33：三个堆管理器组件仍成立，hook 仍消费，但原作者未发布该版本完整迁移；
- 2.34～2.40：TSU+/TSU/largebin 与 stdout 最终触发点仍可分别验证，原版 hook 终点已结束；
- 2.41：smallbin 到 tcache 的 stashing 代码重构，当前 TSU/TSU+ 形式结束；
- 2.42：largebin nextsize 增加反向完整性检查，是另一条更晚的边界。

因此“House of Rust 在 2.34 不可用”只对原版完整链成立：前半思想并未同时消失，失效的是第五阶段最终触发点；换终点可以研究迁移，但必须重新给出端到端成功判据。“2.41 不可用”则是前半堆管理器组合本身先断了一环，不是改一个偏移就能恢复同一条 TSU 链。

## 原语表

| 阶段 | 需要的输入原语 | 得到的输出原语 | 当前 C 验证 |
|---|---|---|---|
| 堆风水 | 约 65 次可控分配；request 至少约 0x1b00 | 两组 smallbin/largebin 与预置 overlap | 汇总文件末尾给出题目迁移伪代码 |
| TSU+ + largebin | 可反复编辑 freed chunk；能改 `bk/bk_nextsize` | 返回 tcache metadata 内地址 | 三个线性子原语分别验证 |
| TSU + largebin | 同上；第二尺寸类与独立 largebin | metadata 邻近 libc 指针 | 三个线性子原语分别验证 |
| stdout | libc 低位猜测；可覆盖 FILE 字段；有输出触发 | libc/内存泄漏 | 汇总与拆分 PoC 都真实验证 |
| 最终控制 | 已知 libc；可把分配投递到目标 | 2.32/2.33 为 hook 控制流 | hook 消费边界真实验证 |

## 资料

- [House of Rust / Crust 原始说明](https://github.com/c4ebt/House-of-Rust)
- [本项目 TSU+ 独立 PoC](../tcache_stashing_unlink_attack_plus/README.md)
- [本项目标准 TSU 独立 PoC](../tcache_stashing_unlink_attack/README.md)
- [glibc 2.40 malloc.c](https://github.com/bminor/glibc/blob/glibc-2.40/malloc/malloc.c)
- [glibc 2.41 smallbin/stashing 重构](https://sourceware.org/git/?p=glibc.git;a=commit;h=e2436d6f5aa47ce8da80c2ba0f59dfb9ffde08f3)
- [House of all 综述](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/)
- [高版本 heap exploitation](https://roderickchan.github.io/zh-cn/2023-03-01-analysis-of-glibc-heap-exploitation-in-high-version/)
