# 上游致谢与使用说明

本目录中的基础分配器 PoC 以 [shellphish/how2heap](https://github.com/shellphish/how2heap) 当前主分支为基线，按手法和真实源码断点重新分组，再补上中文说明、版本矩阵和验证脚本。复合 House 链会在各自 README 与源码头部注明原作者或上游仓库。

本轮新增的 Poison Null Byte 四个历史分支来自 how2heap 对应版本基线；House of Error 的命名、完整 2.35 exploit 和 `_IO_mem_sync` 双写分析来自 [un1c0rn-the-pwnie/FSOPAgain](https://github.com/un1c0rn-the-pwnie/FSOPAgain)。本项目新增的 C 微型 PoC 只验证合法偏移 vtable 与双写效果，没有把题目级 exploit 改写成虚假的跨版本通用 RCE。

House of Cat 以 2022 强网杯同名题的公开链为命名语境；本项目的 C PoC 是依据 GNU glibc `wfileops.c/wgenops.c/libioP.h` 独立编写的最终触发点隔离测试，并额外按 2.24～2.29、2.30、2.31～2.43 三种 wide-data ABI 分开验证。

House of Corrosion 的版本结论与阶段来自 [CptGibbon 原始说明](https://github.com/CptGibbon/House-of-Corrosion)（2.27 原版及 2.29 Addendum A）和 [ptr-yudai sample exploit](https://github.com/ptr-yudai/House-of-Corrosion)。House of Rust/Crust 来自 [c4ebt 原始仓库](https://github.com/c4ebt/House-of-Rust)。本项目保留它们的 Build ID/菜单约束，并没有把组合原语改写成虚构的跨版本端到端 RCE。

House of Banana 的命名、2.30 原始链与私有 `link_map` 条件来自 [Ha1vk 原文](https://www.anquanke.com/post/id/222948)。本项目新增的 C 程序只隔离验证真实 `exit→_dl_fini→DT_FINI_ARRAY` 最终触发点；fake map 布局还是要用目标 `ld.so` 的私有偏移。

House of Some 来自 [Csome 原始文章](https://blog.csome.cc/p/house-of-some/)，House of Illusion 来自 [enllus1on 原始文章](https://enllus1on.github.io/2024/01/22/new-read-write-primitive-in-glibc-2-38/)，配套代码由 [Some-of-House](https://github.com/CsomePro/Some-of-House) 汇总。本项目没有复制它们的题目 exploit；新增 C PoC 按上游 glibc 源码隔离验证合法 jump table 的真实调用链，另外补进了 2.30/2.31 wide ABI 与 2.40 `_prevchain` 断点。

补充资料还包括 [ALateFall/blogs 的 system 笔记](https://github.com/ALateFall/blogs/tree/main/system) 与用户提供的[看雪文章离线存档](/Users/flower/Zotero/storage/QPI8VQE6/thread-272098-1.html)。本项目对这些内容做了源码交叉验证，没有把原文的固定偏移、`latest` 或特定发行版构建结论直接扩展到 glibc 2.43。逐项吸收与修正见 [ADDITIONAL_REFERENCES.md](./ADDITIONAL_REFERENCES.md)。

[`pwn_notes`](./pwn_notes/README.md) 整理自本仓库父目录长期积累的个人 Markdown，包括输入、调试、ROP、shellcode、C++、Kernel 与 protobuf-c 片段。原文件没有被删除或覆盖；迁移去向、缺失图片、实现相关片段和已纠正旧结论见 [`pwn_notes/SOURCE_MAP.md`](./pwn_notes/SOURCE_MAP.md)。

非堆专题的横向扩充依据 GNU、Linux、Arm、RISC-V、LLVM、pwntools、AFL++ 等项目的一手规范/文档，以及 BROP、SROP、COOP、JOP 的原始研究。正文只做归纳和条件化表达，没有复制大段原文；完整链接、适用主题与检索日期见 [`pwn_notes/UPSTREAM_REFERENCES.md`](./pwn_notes/UPSTREAM_REFERENCES.md)。

这些程序只用于 CTF、教学和获得明确授权的安全研究。它们故意制造 UAF、double free、越界写等未定义行为；不要把其中的写法用于生产代码，也不要对未授权目标使用。

版本范围指上游 GNU glibc 的默认 ptmalloc 行为。Ubuntu/Debian 可能把安全补丁回移到旧版本包，所以比赛附件中的 `libc.so.6` 源码/Build ID 比版本号字符串更可靠。
