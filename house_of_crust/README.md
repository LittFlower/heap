# House of Crust

## 先说结论

这个目录只保留可以直接运行的 C 文件。地址公式、六阶段链的说明，以及构建检查表，都放在 C 文件末尾的中文注释里：

| 文件 | 类型 | 用途 |
|---|---|---|
| [`poc_fastbin_pointer_move_2.32_2.36.c`](./poc_fastbin_pointer_move_2.32_2.36.c) | 可执行的 C 源码模型 | 逐句验证 fastbin size 的反算方式、safe-linking 编码，以及两段式的指针搬运 |
| [`check_build_mapping_2.32.c`](./check_build_mapping_2.32.c) | C 语言运行时检查器，不是 PoC | 查询 `_IO_file_jumps` 的实际地址和对应映射的权限 |

这里并不是要声称存在一个“适用于所有 glibc 2.32 构建的完整 Crust C exploit”。原版手法最终的 FSOP 明确依赖自编译构建的链接布局、可写映射、精确的 gadget 以及寄存器状态约束；原作者在六个自编译的 2.32 构建上做过测试，其中最终能跑通的链只有一个。既然没有给定那份具体的 libc/ld Build ID，硬写一个固定偏移的版本反而会误导读者。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | House of Rust 的 TSU/largebin 原语 + House of Corrosion 的 fastbin 指针搬运 + stderr FSOP |
| 关键环境与不变量 | 特定自编译 2.32 的布局、gadget 和调用约定 |
| 最终输出原语 | 无泄露组合链，最终取得 CF/RCE |
| 版本边界应如何理解 | 它不是一条独立的消费路径。2.37 先封堵 House of Corrosion 的超大尺寸 fastbin 指针搬运，2.41 再删除 TSU；2.34 起还要替换 hook 终点。组件仍可用，不等于完整 Crust 仍可用。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 三分钟运行

在 cheatsheet 根目录执行：

```bash
./tools/run_in_docker.sh 2.32 house_of_crust/poc_fastbin_pointer_move_2.32_2.36.c
./tools/run_in_docker.sh 2.32 house_of_crust/check_build_mapping_2.32.c
```

第一条应输出：

```text
[+] 两段指针搬运完成
```

## C 指针搬运模型验证了什么

glibc 2.32 起 fastbin 的 `fd` 字段开始使用 safe-linking 编码。这个模型只有一个 `main` 函数，用真实的 `malloc` 地址来充当 victim，然后按源码里的实际顺序直接写出核心赋值：

```text
free:   victim->fd = PROTECT_PTR(&victim->fd, *fastbin_head)
        *fastbin_head = victim

malloc: *fastbin_head = REVEAL_PTR(victim->fd)
```

随后严格断言：

```text
源槽 -> libc 可编辑中转区 -> 修改指针值 -> 目标槽
```

它验证的是 fastbin 指针搬运这个算法本身，不是真实场景下 `_int_free` 的完整利用过程。模型把“victim 已经被重复挂入另一个远端 fastbin 头槽”当作既定输入；而在真实的 Crust 利用中，还需要靠 WAF、重叠 chunk、用来通过检查的安全值区域，以及已经被放大的 `global_max_fast` 才能建立起这个状态。

这个区分很重要：模型跑成功只说明公式和搬运顺序是对的；只有在目标 libc 中真的命中了 `main_arena.fastbinsY[index]`，才能说明堆管理器这一步投递成功了。前置的 TSU+/TSU/largebin 步骤，请分别去运行 [House of Rust 的线性 C PoC](../house_of_rust/README.md)。

## 地址怎么计算

先从附件 libc 的调试符号、对应源码偏移或反汇编中得到：

- `fastbinsY`：`main_arena.fastbinsY[0]` 的运行时地址；
- `editable-zone`：已经通过 Rust 阶段取得、可编辑的 libc 中转区 qword；
- `source`：待搬运指针所在的源槽 qword；
- `destination`：最终要改写的目标槽 qword；
- `fd-storage`：搬运用 victim 的 `fd` 字段地址，用于观察 safe-linking key。

把真实地址代入 [`poc_fastbin_pointer_move_2.32_2.36.c`](./poc_fastbin_pointer_move_2.32_2.36.c) 末尾列出的公式。对每个目标计算相对 `fastbinsY` 的 `delta`、带 `PREV_INUSE` 的物理 chunk size，以及应传给 `malloc` 的 request：

```text
chunk size = 2 * (target - fastbinsY) + 0x20
request    = (chunk size & ~7) - 0x10
```

## 构建审计怎么用

运行：

```bash
./tools/run_in_docker.sh 2.32 house_of_crust/check_build_mapping_2.32.c
```

程序用 `dlsym/dlvsym` 找到真实的 `_IO_file_jumps`，再去查询 `/proc/self/maps`。当前验证用的 Ubuntu glibc 2.32 显示的权限是 `rw-p`，说明“jump table 可写”这一项条件成立；但这仍然不代表原作者的最终链就能跑通，因为 gadget、相对跳转、寄存器状态和 one_gadget 约束这几项都还没有审计过。

接下来还要按 C 文件末尾的检查表逐项人工确认：映射确实可写、libc 地址低四位猜测命中、gadget 已经按附件反汇编重新核对、寄存器状态和最终调用约束全部匹配。光记录一个布尔值,是没办法代替这些审计工作的。

## 从源码看 2.37 为什么是硬边界

Crust 前半复用 Rust 的两轮 TSU/largebin，随后覆盖 `global_max_fast`，把远超正常 fastbin 的 chunk 按 `fastbin_index` 投递到 libc 中远离 `fastbinsY` 的 qword。

glibc 2.36 中 `global_max_fast` 是 `INTERNAL_SIZE_T`，一次内存破坏可以写入很大的 size；glibc 2.37 将它缩为 `uint8_t`。即使攻击者把这个字节写成 `0xff`，x86-64 对齐后的最大物理 chunk size 也只有 `0xf0`：

```text
fastbin_index(0xf0) = (0xf0 >> 4) - 2 = 13
13 * 8 = 0x68
```

所以写入 qword 最远只覆盖 `fastbinsY+0x68` 到 `fastbinsY+0x6f`。Crust 所需的可编辑中转区、IO 对象或链接器对象通常相隔数百到数千字节，不能靠调整 request 偏移恢复；这封堵的是“用超大尺寸 fastbin 越界索引访问远端槽位”的思想本身，而不只是一个版本偏移变化。

## 原语表

| 阶段 | 需要的输入原语 | 得到的输出原语 | 当前验证状态 |
|---|---|---|---|
| Rust 前半 | 大量可控分配；可反复编辑 freed chunk | tcache metadata chunk 与 libc 邻近指针 | 链接到 Rust 三个堆管理器子原语 |
| 放大 max_fast | libc 低位猜测；能把写投到 `global_max_fast` | 超大尺寸 fastbin 越界索引生效 | 必须按附件真实验证 |
| victim 准备 | WAF 改 size/fd；约 0x4000 用于通过检查的安全值区域 | 可复用的指针搬运 victim | 构建与题目相关 |
| 两段搬运 | 源槽、中转区、目标槽地址；同一 fd 存储位置 | 可修改后搬运的 libc qword | C 源码模型严格断言 |
| 原版终点 | 可写 jump table；精确 gadget/寄存器条件 | stderr FSOP 控制流 | C 只审映射，反汇编需人工完成 |

## 版本表

| 版本 | TSU/largebin 前置 | 超大尺寸 fastbin 指针搬运 | 原版最终 FSOP |
|---|---:|---:|---:|
| 2.32 | 是 | 算法成立，safe-linking 要两段搬运 | 仅特定 Build ID/构建条件 |
| 2.33～2.36 | 组件仍在 | 理论窗口仍在 | 没有原作者端到端证明，必须重新适配 |
| 2.37～2.40 | 前置组件仍可分别存在 | **硬失效**：`uint8_t global_max_fast` | 无法再组成原 Crust |
| 2.41+ | TSU 旧 stashing 也发生变化 | 已在 2.37 先失效 | 无法组成原 Crust |

## 资料

- [House of Rust / Crust 原始说明](https://github.com/c4ebt/House-of-Rust)
- [House of Corrosion 原始说明](https://github.com/CptGibbon/House-of-Corrosion)
- [glibc 2.36 malloc.c](https://github.com/bminor/glibc/blob/glibc-2.36/malloc/malloc.c)
- [glibc 2.37 malloc.c](https://github.com/bminor/glibc/blob/glibc-2.37/malloc/malloc.c)
- [global_max_fast 改为 uint8_t 的提交](https://sourceware.org/git/?p=glibc.git;a=commit;h=6f360366f7f76b158a0f4bf20d42f2854ad56264)
- [高版本 heap exploitation](https://roderickchan.github.io/zh-cn/2023-03-01-analysis-of-glibc-heap-exploitation-in-high-version/)
