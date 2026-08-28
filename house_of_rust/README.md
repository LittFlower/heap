# House of Rust

## 先说结论

先看汇总 PoC；要单步调试，再看每个只讲一个子原语的 C 文件：

| 文件 | 实际验证内容 | 版本 |
|---|---|---|
| [`poc_summary_2.32.c`](./poc_summary_2.32.c) | 一次运行依次验证 TSU+、TSU、largebin、stdout 泄漏和 `__free_hook`；文件末尾给出共享堆衔接伪代码 | 2.32 |
| [`poc_component_tsu_plus_2.32_2.40.c`](./poc_component_tsu_plus_2.32_2.40.c) | TSU+：修改 smallbin `bk`，让 malloc 返回目标地址 | 2.32～2.40 |
| [`poc_component_tsu_2.32_2.40.c`](./poc_component_tsu_2.32_2.40.c) | 标准 TSU：触发 smallbin stashing 并取回伪节点 | 2.32～2.40 |
| [`poc_component_largebin_2.32_2.40.c`](./poc_component_largebin_2.32_2.40.c) | post-2.30 largebin：通过 `bk_nextsize` 写目标 | 2.32～2.40 |
| [`poc_stage4_stdout_leak_2.32_2.40.c`](./poc_stage4_stdout_leak_2.32_2.40.c) | 直接覆盖 stdout 字段，由 `fflush` 输出目标内存 | 2.32～2.40 |
| [`poc_stage5_free_hook_2.32_2.33.c`](./poc_stage5_free_hook_2.32_2.33.c) | 直接写 `__free_hook`，由 `free` 触发回调 | 2.32～2.33 |

原作者公开的仓库只有阶段说明，没有公开完整 exploit。汇总文件的五个阶段都真实执行，但每段用独立子进程隔离，避免上一段故意破坏的 bin 状态污染下一段。这只是为了方便逐段验证，冒充不了题目里约 65 次分配、共享同一条堆时间线的完整链；真正的端到端 exploit 还得按题目的 add/edit/free 菜单、slot 生命周期、WAF overlap 和附件 Build ID 落地。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | TSU+、TSU、两次现代 largebin、stdout FSOP；原版无需堆地址泄露 |
| 关键环境与不变量 | 绕过 safe-linking；精确控制堆布局；使用匹配 2.32 的构建与终点 |
| 最终输出原语 | 无泄露地控制 libc/heap，并取得 RCE |
| 版本边界应如何理解 | 原版完整链只验证到 2.32。2.34 起 hook 终点失效，但可研究替代终点；2.41 删除 TSU 消费路径后，组合链的核心失效。组件仍可用，不等于完整 Rust 仍可用。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

<!-- CHUNK_SIZE_REQUIREMENTS:START -->
## Chunk size 要求

- **完整 Rust 要求多尺寸菜单。** 原链约 65 次分配，至少能使用两组 smallbin/tcache class；本目录组件用 request `0x90`（物理 `0xa0`）和 `0x100`（物理 `0x110`）。
- 两轮写入还需 largebin 对；组件 PoC 用 request `0x418/0x428`，对应物理 `0x420/0x430`。原始堆风水的单次最大 request 约 `0x1b00`，所以“只能申请 small chunk”不满足完整链。
- 拆分 PoC 的常量只证明各组件；迁移时两组 smallbin、两组 largebin、guard/触发请求都必须在同一堆时间线里重新核对。
<!-- CHUNK_SIZE_REQUIREMENTS:END -->

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

`free_hook` 文件只标注 2.32～2.33，因为 2.34 起主路径不再消费这个 hook。这里不加动态查符号、解析版本号之类的兼容代码，版本边界直接体现在文件名和版本表里。

## 每个 C 文件怎么读

### 堆管理器子原语

前三个文件都从 `main` 第一行顺序向下真实调用目标 libc 的 `malloc/calloc/free`：

1. TSU+ 文件改写 smallbin victim 的 `bk`，把伪节点塞进 stashing 流程，最终要求 `malloc` 精确返回栈上的 `target`；
2. 标准 TSU 文件走 smallbin stashing 原本的 `bck->fd` 写和伪节点暂存流程，验证的是这条路径本身，不是 TSU+ 的加强用法；
3. largebin 文件用 0x430/0x420 这对物理 chunk 构造插入场景，精确断言写入值就是新 victim 的 chunk 头地址，而不是随便一个可写地址。

原版 Rust 在第二、第三阶段各用一组不同的 largebin，第二组只是换了一个 largebin 尺寸，写入原语本身没有变化。迁移到题目时，要把这三个子原语重新拼回同一条共享堆时间线，而不是各自独立运行。

### stdout 泄漏这个最终触发点

这个文件的输入原语是"已经拿到对 `_IO_2_1_stdout_` 字段的覆盖能力"。程序直接把 `_IO_write_base/_IO_write_ptr` 指向 `secret`，再调用一次 `fflush`，终端打印出 `stdout 泄漏成功` 就说明这条消费路径走通了。

它只验证消费端本身，不验证原版 Rust 那套 1/16 概率的 libc 低位猜测，也不验证 tcache 头是否已导向 stdout。实战中必须在第一次真实 stdout 活动处下断点确认；只看到"FILE 字段好像被改了"不等于泄漏已完成。

### `__free_hook` 这条边界

glibc 2.34 的关键变化不是兼容符号能否解析，而是 `free` 的主路径不再调用这个 hook。所以这里只保留 2.32～2.33 窗口内最直接的 PoC：把 `__free_hook` 赋值成 `win`，调用一次 `free(chunk)`，断言回调确实被命中。

| 版本 | `__free_hook` 符号 | `free` 是否消费 | 原版阶段五 |
|---|---|---:|---|
| 2.32～2.33 | 可用 | 是 | 还能验证原终点 |
| 2.34～2.40 | 可能仍有兼容符号 | 否 | 本文件不适用，必须换最终触发点|

## 汇总 PoC 怎么读

[`poc_summary_2.32.c`](./poc_summary_2.32.c) 照样能从上到下线性地读：`main` 里依次出现五个阶段，父进程逐段等待子进程执行成功再往下走。前三段真实执行对应的 bin 操作；第四段真实覆盖并消费 stdout；第五段真实写入并消费 `__free_hook`。子进程隔离只是为了不让上一段故意破坏的伪 bin 状态影响下一段，不是在封装利用步骤。

文件末尾注释保留了原先由条件检查器负责的内容：约 65 次分配、0x1b00 的最大 request、两组尺寸类、低四位猜测、stdout 触发点，以及 2.34/2.41 两个关键版本边界。这些都标明了是题目迁移用的伪代码，不是运行一次就自动满足的前置条件。

## 从源码看版本边界

原版的完整链可以拆成这几步：

1. 用约 65 次分配，准备好 14 个 0x90 尺寸类、15 个 0xa0 尺寸类、两组 largebin，再做出 WAF（释放后写）造成的 overlap；
2. TSU+ 借助这种双重归属破坏 smallbin 的 `fd/bk`，再用第一次 largebin 写修复 `fd`，拿到 tcache 元数据内部的一个 chunk；
3. TSU 配合第二次 largebin 写，在元数据附近留下一个 libc 指针；
4. 猜出 libc 地址的低四位，把后续写操作导向 stdout，覆盖 FILE 字段并触发一次真实的内存泄漏；
5. 原版拿到泄漏后，把写操作投递到 `__free_hook`，写入 `system` 地址，再 `free("/bin/sh")` 完成利用。

审计版本边界时，要把"投递方式"和"最终触发点"这两件事分开看：

- 2.32：这是原作者完整链验证过的目标版本，safe-linking 在这个版本已经存在；
- 2.33：三个堆管理器组件还成立，hook 也会被消费，只是原作者没有针对这个版本发布完整的迁移；
- 2.34～2.40：TSU+、TSU、largebin 这几个组件以及 stdout 这个最终触发点还能分别验证，但原版依赖的 hook 终点已经失效；
- 2.41：smallbin 到 tcache 的 stashing 代码被重构，目前这种形式的 TSU/TSU+ 也就跟着失效；
- 2.42：largebin 的 nextsize 检查加上了反向完整性校验，这是比 2.41 更晚的另一道边界。

“House of Rust 在 2.34 上不可用”只对原版完整链成立。真正失效的是第五阶段的最终触发点，前半段思路并没有跟着失效；换个终点还能研究迁移，但必须重新给出一套端到端成功判据。“2.41 上不可用”则是另一回事：前半段的堆管理器组合本身先断了一环，不是改个偏移就能修回同一条 TSU 链。

## 原语表

| 阶段 | 需要的输入原语 | 得到的输出原语 | 当前 C 验证 |
|---|---|---|---|
| 堆风水 | 约 65 次可控分配；单次 request 至少约 0x1b00 | 两组 smallbin/largebin，并预先构造好 overlap | 汇总文件末尾给出了题目迁移用的伪代码 |
| TSU+ 加 largebin | 能反复编辑已释放的 chunk；能改写 `bk/bk_nextsize` | 返回 tcache 元数据内部的地址 | 三个线性子原语分别验证过 |
| TSU 加 largebin | 前提同上；使用第二个尺寸类和另一组独立的 largebin | 在元数据附近留下一个 libc 指针 | 三个线性子原语分别验证过 |
| stdout | 需要猜出 libc 地址低位；能覆盖 FILE 字段；能触发一次输出 | 得到 libc 或内存中的泄漏内容 | 汇总文件和拆分出来的 PoC 都真实验证过 |
| 最终控制 | 已经拿到 libc 地址；能把分配投递到目标位置 | 2.32/2.33 上表现为 hook 劫持控制流 | hook 这条消费边界经过真实验证 |

## 资料

- [House of Rust / Crust 原始说明](https://github.com/c4ebt/House-of-Rust)
- [本项目 TSU+ 独立 PoC](../tcache_stashing_unlink_attack_plus/README.md)
- [本项目标准 TSU 独立 PoC](../tcache_stashing_unlink_attack/README.md)
- [glibc 2.40 malloc.c](https://github.com/bminor/glibc/blob/glibc-2.40/malloc/malloc.c)
- [glibc 2.41 smallbin/stashing 重构](https://sourceware.org/git/?p=glibc.git;a=commit;h=e2436d6f5aa47ce8da80c2ba0f59dfb9ffde08f3)
- [House of all 综述](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/)
- [高版本 heap exploitation](https://roderickchan.github.io/zh-cn/2023-03-01-analysis-of-glibc-heap-exploitation-in-high-version/)
