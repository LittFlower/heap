# CTF glibc Heap Ultimate Cheatsheet（2.23～2.43）

这份目录面向 x86-64 CTF pwn：共 **60 种手法、141 份 C PoC**。版本结论以 GNU glibc 上游源码为基线，并分别说明发行版回移、附件 Build ID、堆原语投递和最终触发点。

## 怎么读

1. 先在下表按题目 libc 版本筛手法。
2. 打开手法目录的 README，确认漏洞前置、源码分支和失效原因。
3. 选择文件名覆盖目标版本的 `poc_*.c`。
4. 用对应 glibc 运行 C PoC；复杂布局和题目迁移步骤写在相关 C 文件末尾的中文注释与伪代码中。
5. 将 PoC 中故意制造的 UAF/overflow/double free 替换为题目的 add/edit/show/delete 原语。

`malloc(req)`、物理 chunk size、各 bin index 和 2.42/2.43 tcache 上限容易混淆时，先查 [MALLOC_SIZE_BIN_MAP.md](./MALLOC_SIZE_BIN_MAP.md)。

本文用三个词拆开一条利用链：**投递**是把伪造 chunk、FILE 或指针送到目标位置；**消费路径**是 glibc 真正读取这些字段的源码分支；**最终触发点**是把控制转成泄漏、任意写或控制流的函数调用。

判断版本变化只是调偏移，还是已经删掉消费路径时，先查 [PRIMITIVE_REQUIREMENTS_MATRIX.md](./PRIMITIVE_REQUIREMENTS_MATRIX.md)。该表列出全部 60 种手法的输入原语、结构条件、输出原语和真实失效原因。

版本范围表示上游 tag 的堆管理器行为，不保证 Ubuntu/Debian 安全更新包没有回移补丁。例如旧 Ubuntu 18.04 的“glibc 2.27”安全包可能已经回移 tcache double-free key；验证历史边界时要使用首发包或从源码构建。

标记约定：

- **可执行 C PoC**：直接调用 malloc/free，带 assert/成功判据。
- **题目级 exploit**：绑定公开 challenge 菜单与附件构建，主要用来读完整阶段。
- **布局说明**：复杂 FILE/link_map/组合 House 的布局数据与条件检查，放在 C PoC 末尾；不能脱离题目原语承诺通用 RCE。

版本表中的“失效”只针对 README 声明的最小输入和消费路径。另一条链能得到相同输出，不代表旧手法仍可用；投递或最终触发点失效，也不代表中间堆原语已经消失。证据不足时只写“公开 PoC/原始链未迁移”，不写成绝对不可用。

## 教学 PoC 的代码风格

- 一个 C 文件只讲一个利用原语或一个明确阶段，执行顺序从 `main` 顶部线性读到底。
- 版本变化会改变利用步骤时拆成不同文件，不在一个 PoC 中加入版本解析和兼容分支。
- 除非函数地址本身就是被消费的回调、hook 或最终控制流目标，否则不写辅助函数。
- 不为释放测试内存、恢复标准流、隔离进程状态或复用代码增加与利用无关的封装。
- 每个关键元数据写前放中文注释；成功判据只保留直接的 `assert`、泄漏输出或回调命中。

## 关键版本时间线

| glibc | 对 CTF heap 最重要的变化 |
|---|---|
| 2.23 | 旧时代基线：无 tcache，hooks 在，经典 unsorted/fastbin/Orange 链可见。 |
| 2.24 | libio 加入 vtable 白名单；heap fake vtable 形式的 Orange 终止；cookie 回调同时开始 PTR_MANGLE。 |
| 2.26 | 引入 tcache；malloc_printerr/abort 不再沿经典路径 flush IO。 |
| 2.27 | malloc_consolidate 加强 fastbin size/index 检查，经典 Rabbit 终止。 |
| 2.28 | `bdc3009` 为 unsorted removal 增加 `bck->fd==victim`，经典无条件 unsorted 写/into-stack/Roman/Storm 已结束；House of Force 仍是末版；`_IO_str_overflow` 改为直接 malloc/free，现代 Pig 最终触发点从此开始。 |
| 2.29 | top size、unsorted 双链、向后合并 size/prev_size、tcache double-free key 集中加固。 |
| 2.30 | tcache counts 改为 uint16_t，malloc 快路径改查 count，Atum 原链终止；现代“更小 victim”largebin attack 分支成为主流。 |
| 2.31 | House of IO 处于其 2.29～2.33 原版窗口。 |
| 2.32 | safe-linking：tcache/fastbin 单链指针变为 `(pos>>12)^ptr` 并检查对齐。 |
| 2.33 | hooks 仍可作为终点的最后一个发行版。 |
| 2.34 | `__malloc_hook/__free_hook` 从正常 malloc/free 路径移除。 |
| 2.35 | Kiwi 旧 assert→IO 触发链的最后一个版本。 |
| 2.36 | `__malloc_assert` 不再刷新 stdio；经典 obstack FILE vtable 的最后版。 |
| 2.37 | `global_max_fast` 缩为 uint8_t；obstack printf 改用新 printf_buffer 链；Apple1 的 `_IO_wstrn_overflow` 被删除。 |
| 2.38～2.40 | safe-linking 时代相对稳定；2.40 是经典 TSU/TSU+ PoC 的末版；`_IO_list_all` 从单链改双链，fake FILE 链需补 `_prevchain`。 |
| 2.41 | calloc 也优先取 tcache；smallbin→tcache stashing 重构；经典 largebin attack 末版。 |
| 2.42 | 引入默认关闭的 large tcache 与新元数据；double-free 改为全 bin 扫描；largebin nextsize 再加固。 |
| 2.43 | 2026-01-23 正式发布；删除 fastbin；large tcache 改精确尺寸匹配，默认 tcache count 变 16，mmap chunk 布局重写。 |

更完整的源码提交与阅读入口见 [SOURCE_TIMELINE.md](./SOURCE_TIMELINE.md)。

## Bin attack 与堆管理器原语

| 手法 | 上游版本结论 |
|---|---|
| [Fastbin Dup Consolidate](./fastbin_dup_consolidate/README.md) | glibc 2.23～2.42；2.43 失效 |
| [Fastbin Dup Into Stack](./fastbin_dup_into_stack/README.md) | glibc 2.23～2.42；2.43 失效 |
| [Fastbin Dup](./fastbin_dup/README.md) | glibc 2.23～2.42；含“fastbin double free→tcache refill/stash”变体；2.43 失效 |
| [Fastbin Reverse Into Tcache](./fastbin_reverse_into_tcache/README.md) | glibc 2.26～2.42；2.43 失效 |
| [Chunk Overlap（freed/in-use size overwrite）](./chunk_overlap/README.md) | freed-unsorted 变体 2.23～2.28；in-use→top 变体 2.23～2.43 |
| [IO_FILE 标准流任意读写](./io_file_arbitrary_read_write/README.md) | x86-64 glibc 2.23～2.43；保留合法 vtable |
| [Large Bin Attack](./large_bin_attack/README.md) | glibc 2.23～2.41；2.42 起经典 `bk_nextsize` 写失效 |
| [Large Tcache Attack](./large_tcache_attack/README.md) | glibc 2.42～2.43；默认需显式提高 `glibc.malloc.tcache_max`；2.43 改精确尺寸匹配 |
| [Poison Null Byte](./poison_null_byte/README.md) | glibc 2.23～2.43；2.26、2.29、2.43 三个边界需换 PoC |
| [Safe-Linking 配套原语](./safe_linking/README.md) | glibc 2.32～2.43 |
| [Small Bin Attack（命名消歧汇总）](./small_bin_attack/README.md) | direct/Lore 2.23～2.43（2.43 需 16-slot 排布）；tcache stashing 2.26～2.40 |
| [Sysmalloc Free Old Top](./sysmalloc_free_old_top/README.md) | glibc 2.23～2.43；是 Orange/Tangerine 的底层制造原语 |
| [Tcache Dup](./tcache_dup/README.md) | glibc 2.26～2.28；2.29 起直接 double free 失效 |
| [Tcache Metadata Hijacking（延迟初始化）](./tcache_metadata_hijacking/README.md) | glibc 2.42～2.43 |
| [Tcache Metadata Poisoning](./tcache_metadata_poisoning/README.md) | glibc 2.26～2.43；偏移随版本变化 |
| [Tcache Poisoning](./tcache_poisoning/README.md) | glibc 2.26～2.43 |
| [Tcache Relative Write](./tcache_relative_write/README.md) | glibc 2.30～2.41；2.42 元数据重构后失效 |
| [Tcache Stashing Unlink Attack（Smallbin Attack）](./tcache_stashing_unlink_attack/README.md) | glibc 2.26～2.40；2.41 起该 PoC 失效 |
| [Tcache Stashing Unlink Attack Plus（TSU+）](./tcache_stashing_unlink_attack_plus/README.md) | glibc 2.26～2.40；2.41 起失效 |
| [Tcache Stashing Unlink Attack Plus Plus（TSU++）](./tcache_stashing_unlink_attack_plus_plus/README.md) | glibc 2.26～2.40；同时取得任意 chunk 与 libc 地址写 |
| [Unsafe Unlink（现代约束版）](./unsafe_unlink/README.md) | glibc 2.23～2.43 |
| [Unsorted Bin Attack](./unsorted_bin_attack/README.md) | 经典任意初值形式 2.23～2.27；`target==victim` 受约束写 2.28～2.43 |
| [Unsorted Bin Into Stack](./unsorted_bin_into_stack/README.md) | 经典单 fake-node 形式 2.23～2.27；2.28 起失效 |

## House of 系列

| 手法 | 上游版本结论 |
|---|---|
| [House of Apple 1](./house_of_apple1/README.md) | `_IO_wstrn_overflow` 已知值写为 2.23～2.36；2.37 删除该函数/jump table |
| [House of Apple 2](./house_of_apple2/README.md) | 2.24～2.43（最终触发点）；三套 wide-data ABI 均有可执行 C PoC |
| [House of Apple 3](./house_of_apple3/README.md) | codecvt 最终触发点：2.23～2.43；2.23～2.29、2.30、2.31+ 三段 ABI 均有 C PoC |
| [House of Atum](./house_of_atum/README.md) | 2.26～2.29；2.30 起原始 count/entry 错位链失效 |
| [House of Banana](./house_of_banana/README.md) | `_dl_fini` 最终触发点：2.23～2.43；原始 exploit 为 2.30，经典 largebin 投递到 2.41 |
| [House of Botcake](./house_of_botcake/README.md) | glibc 2.26～2.43 |
| [House of Cat](./house_of_cat/README.md) | `_IO_wfile_seekoff`→未检查的 wide vtable 最终触发点：2.24～2.43；原题完整链绑定 2.35 |
| [House of Corrosion](./house_of_corrosion/README.md) | 完整公开链为特定 2.27/2.29 构建；超大尺寸 fastbin 指针搬运到 2.36，2.37 起失效 |
| [House of Crust](./house_of_crust/README.md) | 完整原版仅特定自编译 2.32；组件共同窗口 2.32～2.36，2.37 起失效 |
| [House of Einherjar](./house_of_einherjar/README.md) | glibc 2.23～2.43 |
| [House of Emma](./house_of_emma/README.md) | IO cookie 最终触发点：2.23～2.43；2.23 回调为明文，2.24 起 PTR_MANGLE；原始 largebin 投递止于 2.41 |
| [House of Error](./house_of_error/README.md) | 合法偏移 vtable 可触发 `_IO_mem_sync` 双写：2.24～2.43；原始完整链绑定 2.35 |
| [House of Force](./house_of_force/README.md) | glibc 2.23～2.28；2.29 起失效 |
| [House of Fun](./house_of_fun/README.md) | 2.23～2.29；2.30 起原始四指针 largebin 写失效 |
| [House of Gods](./house_of_gods/README.md) | 原版最小链实跑 2.23～2.25；2.26 是 tcache/隐藏-offset 迁移问题；2.27 起原版 main_arena fake-size 不变量硬失效 |
| [House of Husk](./house_of_husk/README.md) | printf handler 最终触发点在 2.23～2.43 仍存在；本目录 largebin 投递 PoC 到 2.41 |
| [House of Illusion](./house_of_illusion/README.md) | 合法 `_IO_file_jumps` 内部错位可形成任意读写：2.23～2.43；2.40+ fake 链须维护 `_prevchain` |
| [House of IO](./house_of_io/README.md) | glibc 2.29～2.33；2.29 与 2.30+ 的 counts 布局不同，2.34 起 key-leak 形式失效 |
| [House of Kauri](./house_of_kauri/README.md) | 2.26～2.41；2.42 起失效 |
| [House of Kiwi](./house_of_kiwi/README.md) | 2.23～2.35；2.36 起专属触发器失效 |
| [House of Lemon](./house_of_lemon/README.md) | 原版 stdout-vtable 完整链仅 2.23；2.24 起终点失效，2.37 起超大尺寸 fastbin 越界投递也失效 |
| [House of Lore / Small Bin Attack](./house_of_lore/README.md) | glibc 2.23～2.43；2.43 默认 count=16，单独 PoC |
| [House of Lys](./house_of_lys/README.md) | 2.23～2.36；2.37 起 exit→_IO_obstack_xsputn 链消失 |
| [House of Mind（Fastbin 版）](./house_of_mind/README.md) | glibc 2.23～2.42；2.43 失效 |
| [House of Muney / Mmap Overlap](./house_of_muney/README.md) | glibc mmap overlap 原语 2.23～2.43 |
| [House of Obstack](./house_of_obstack/README.md) | 经典 _IO_obstack_jumps 为 2.23～2.36；2.37 起旧链消失 |
| [House of Orange（经典链）](./house_of_orange/README.md) | 原始任意 vtable PoC 仅 glibc 2.23；2.24～2.25 需合法 `_IO_str_jumps` 变体；2.26 起经典端到端链失效 |
| [House of Pig](./house_of_pig/README.md) | 旧回调最终触发点：2.23～2.27；现代 malloc/memcpy/free 最终触发点：2.28～2.43；原题链 2.31，PLUS 2.34～2.41 强构建相关 |
| [House of Rabbit](./house_of_rabbit/README.md) | 2.23～2.26；2.27 起经典跨尺寸链失效 |
| [House of Roman](./house_of_roman/README.md) | 2.23～2.25 fastbin 路径；2.26～2.27 tcache 重排路径；2.28 起失效 |
| [House of Rust](./house_of_rust/README.md) | 原版完整链仅 2.32；组件窗口 2.32～2.40，2.34+ 须替换 hook 终点 |
| [House of Snake](./house_of_snake/README.md) | 2.37～2.43 |
| [House of Some](./house_of_some/README.md) | wide FILE 驱动合法 jump table，形成任意写最终触发点；2.23～2.43 可用，2.30/2.31 和 2.40 有布局变化 |
| [House of Spirit](./house_of_spirit/README.md) | glibc 整体 2.23～2.43；fastbin 子型止于 2.42，tcache 子型始于 2.26 |
| [House of Storm](./house_of_storm/README.md) | glibc 2.23～2.27；2.28 的 unsorted `bck->fd` 检查起失效 |
| [House of Tangerine](./house_of_tangerine/README.md) | glibc 2.26～2.43 |
| [House of Water](./house_of_water/README.md) | glibc 2.32～2.43 |

## 调试顺序

1. 在漏洞写入前后观察 chunk header 和目标 bin 链。
2. 在关键 `free/malloc` 前断到 `_int_free`、`_int_malloc` 或手法 README 指出的函数。
3. 先确认走进预期分支，再检查 fd/bk、size、对齐和 safe-linking；不要只盯最终崩溃位置。

## 编译与验证

仓库自带的 runner 在 `~/ctf-pwn-docker` 所用的 Colima x86-64 Docker 环境工作：

```bash
cd heap_ultimate_cheatsheet

# 例：glibc 2.39 的现代 largebin attack
./tools/run_in_docker.sh 2.39 large_bin_attack/poc_2.30_2.41.c

# 跑代表性版本矩阵；对 ASLR 敏感的 PoC 会有限重试
./tools/check_all.sh
```

Runner 使用老 GCC 构建，再放到对应 Ubuntu/glibc 运行。2.23、2.26～2.30 若在 `build/glibc-exact/<package-id>/` 找到精确 loader，会优先使用 glibc-all-in-one 首发包，避免安全更新 backport 改写历史边界。具体准备方法见 [tools/README.md](./tools/README.md)。

本次 x86-64 实测版本、198 项动态矩阵、负测试和 Build-ID 条件说明见 [VALIDATION.md](./VALIDATION.md)。141 个 C PoC 均至少有一个对应 glibc 运行项。

## 资料与口径

主要参考：

- [House of all about glibc heap exploitation](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/)
- [高版本 glibc heap exploitation 分析](https://roderickchan.github.io/zh-cn/2023-03-01-analysis-of-glibc-heap-exploitation-in-high-version/)
- [GNU glibc 官方源码与 release branches](https://sourceware.org/glibc/sources.html)
- [shellphish/how2heap](https://github.com/shellphish/how2heap)
- [FSOPAgain / House of Error 原始仓库](https://github.com/un1c0rn-the-pwnie/FSOPAgain)
- [Some-of-House / House of Some 与 Illusion](https://github.com/CsomePro/Some-of-House)
- [ALateFall/blogs：system 笔记](https://github.com/ALateFall/blogs/tree/main/system)
- [看雪《CTF 中 glibc 堆利用及 IO_FILE 总结》离线存档](/Users/flower/Zotero/storage/QPI8VQE6/thread-272098-1.html)

参考文章发表于 2023 年，故其中“至今”不能自动延伸到 2.43。本整理按 2.41～2.43 新源码重新收窄了 Kauri、Rust/Crust、Corrosion、Husk 与多个 largebin 投递型 FSOP House 的结论。

指定资料、how2heap 与本地笔记中的全部名称如何映射到目录，见 [TECHNIQUE_COVERAGE_MAP.md](./TECHNIQUE_COVERAGE_MAP.md)；逐手法的输入/输出原语与真实失效性质见 [PRIMITIVE_REQUIREMENTS_MATRIX.md](./PRIMITIVE_REQUIREMENTS_MATRIX.md)；新增资料具体补进了什么、哪些旧说法被源码收窄，见 [ADDITIONAL_REFERENCES.md](./ADDITIONAL_REFERENCES.md)。

Malloc Maleficarum 中 Prime/Chaos 为何没有硬造一个 2.23+ PoC，见 [HISTORICAL_NAME_BOUNDARIES.md](./HISTORICAL_NAME_BOUNDARIES.md)。

仅用于 CTF、教学与授权研究。PoC 故意触发未定义行为和堆管理器完整性错误，不应链接到生产程序。
