# Kernel Pwn 环境与 initramfs 速查

这篇整理的是比赛中拆包、放入静态 exp、重打包和复现环境的流程，不替代具体内核漏洞利用。对来源不可信的镜像，始终在一次性目录、容器或虚拟机中操作。

## 先保存题目事实

```bash
file bzImage vmlinux rootfs.cpio.gz 2>/dev/null
sha256sum bzImage vmlinux rootfs.cpio.gz 2>/dev/null
strings bzImage | rg -m1 'Linux version'
```

同时记录：

- QEMU 完整启动参数、kernel cmdline 和 init 脚本；
- `vmlinux`、`System.map`、`.config`、模块和调试符号是否存在；
- KASLR、SMEP、SMAP、KPTI、PAN 等缓解是否开启；
- 漏洞设备节点、权限、ioctl 编号和结构体 ABI；
- exp 最终以哪个用户、目录和 initramfs 路径运行。

没有 `.config` 时，可以检查内核是否包含 `/proc/config.gz`，或从题目启动参数、反汇编和运行状态逐项恢复条件。

## 模块与攻击面体检

```bash
file vuln.ko
modinfo vuln.ko
readelf -hSWs vuln.ko
readelf -rW vuln.ko
objdump -drwC -Mintel vuln.ko > vuln.disasm
strings -a vuln.ko | rg '/dev/|ioctl|copy_(from|to)_user|kmalloc|kfree'
```

先恢复用户/内核 ABI：

- device name、major/minor、open/release/read/write/ioctl/mmap handler；
- ioctl command 的 direction/type/number/size，以及 compat ioctl 是否存在；
- 用户结构体的 pointer、整数宽度、padding 和 flexible array；
- `copy_from_user`/`copy_to_user` 的长度、返回值处理和错误路径；
- 每个 kernel object 的分配 API、实际大小、cache、引用计数、锁、RCU 与释放点；
- fd、mapping、workqueue、timer、tasklet、signal 和线程之间如何共享对象。

`kmalloc(0x80)` 不保证利用时一定进入名为 `kmalloc-128` 的相同 cache：内核版本、allocator、debug/hardening 配置、cgroup/accounting 和专用 cache 都会影响。以题目运行内核的实际 slab 状态和源码为准。

## Kernel 原语账本

沿用用户态的事实表，但增加执行上下文：

```text
对象/分配: struct note，kmalloc(size, GFP_KERNEL)
生命周期: fd open 分配，ioctl delete 释放，close 还会再次 put
并发: ioctl 无锁；workqueue 持有裸指针
首次破坏: stale pointer 可读写前 0x40 bytes
上下文: process context，可睡眠
CPU/cache: 是否绑定 CPU，是否经过 per-CPU freelist
副作用: show 后引用计数减一
```

特别区分：

- kernel address leak、物理地址、用户虚拟地址、内核虚拟地址和 handle；
- 任意 kernel read/write 与只能访问 direct-map/slab object 的相对原语；
- object UAF 与 page UAF；
- 跨 cache 复用、同 cache 不同类型复用和相同对象重新分配；
- process context、softirq、hardirq、NMI 下可调用接口；
- RCU grace period、refcount 到零和真正 free 的时间差。

## 缓解项与利用影响

| 缓解 | 直接影响 | 分析方式 |
|---|---|---|
| KASLR | kernel text/data/module 地址随机化 | 同一 `vmlinux`/module 求 offset；泄漏归属到具体 mapping |
| SMEP / PXN | kernel 不能执行用户页 | 不能简单把 RIP/PC 指向用户 shellcode；考虑 kernel code reuse 或 data-only |
| SMAP / PAN | kernel 不能随意访问用户页 | 合法 uaccess 窗口、copy helper 和架构状态需核对 |
| KPTI | 用户态页表不保持完整 kernel mapping | return-to-user、trampoline、CR3/异常 frame 都绑定架构和构建 |
| stack canary / shadow call stack | kernel 栈返回路径 | 是否覆盖到返回地址、能否泄漏、异常/中断返回路径如何 |
| CFI | 间接调用目标集合 | 函数类型、合法 callsite、module 与 kernel 是否同一 CFI 方案 |
| strict RWX / rodata | kernel text/rodata/module 权限 | 不能把任意写等价成 patch code；看真正可写数据目标 |
| slab freelist hardening/random | freelist 编码与分配顺序 | 绑定 `.config`、boot 参数和 allocator 源码，不套用户态 safe-linking |

`.config` 表示构建能力，boot cmdline/sysctl 表示部分运行时选择，CPU flags 表示硬件能力；三者共同决定实际状态。QEMU 的 `-cpu` 也会改变 SMEP/SMAP 等条件。

Linux kernel self-protection 文档明确把“禁止 kernel 执行/无意访问 userspace”作为目标，分别对应 x86 SMEP/SMAP、Arm PXN/PAN。利用路线应从这些真实边界出发，不只看启动脚本有没有写 `smep=off`。

## 地址与符号

优先用题目提供的 `vmlinux`/`System.map`/module，分别记录 hash。运行时 `/proc/kallsyms`、dmesg、procfs/sysfs 和 module address 可能受权限及 `kptr_restrict`、`dmesg_restrict` 等策略限制。

```bash
nm -n vmlinux | less
readelf -nW vmlinux
readelf -Ws vmlinux | rg ' commit_creds| prepare_kernel_cred| modprobe_path'
```

搜到 symbol 不代表它适合作为终点：导出状态、函数签名、CFI 类型、内联、rodata、namespace、LSM 和构建配置都会改变可达性。固定 gadget 与结构偏移必须从同一内核构建重新求出。

## 竞态控制与 userfaultfd

userfaultfd 可把注册内存的 page fault 通知给用户态，历史上常用来暂停某些 kernel uaccess 窗口。但当前 Linux 对能捕获 kernel page fault 的 unprivileged userfaultfd 有明确限制：通常需要 `CAP_SYS_PTRACE`、允许的 `vm.unprivileged_userfaultfd`，或有权限访问 `/dev/userfaultfd`。

因此竞态方案按可用性选择：

- userfaultfd feature probe；
- FUSE/文件或 pipe/socket backpressure；
- 多线程 barrier、CPU affinity 和可控阻塞点；
- 重复触发，记录对象状态；
- 题目提供的 ioctl/read/write 同步原语。

调试环境打开某个 sysctl 不代表远端可用。即使能暂停 `copy_from_user`，也要确认目标内核具体 helper 会触发可捕获 fault，且另一线程不会被锁挡在目标路径之外。

## KASAN、KFENCE、KMSAN 与 KCSAN

能重编题目 kernel 时，按 bug 类型选择 instrumentation：

| 工具 | 主要发现 |
|---|---|
| KASAN | heap/stack/global OOB、UAF 等非法内存访问，适合精确归因 |
| KFENCE | 低开销抽样检测 heap OOB、UAF、invalid free，触发并非每次分配 |
| KMSAN | 未初始化值传播，内存/性能开销大，架构支持有限 |
| KCSAN | 基于抽样 watchpoint 的 data race 检测 |

instrumented kernel 的对象布局、timing 和 allocator 行为可能与题目 kernel 不同。用它定位首次错误后，还要回到原始 kernel 验证生命周期和可利用性。

```text
KASAN report: 关注 invalid access 栈、allocation 栈、free 栈和 object cache
KCSAN report: 关注两个竞争 access、锁与 value change，不只看最终 crash
KMSAN report: 沿 origin chain 找未初始化来源
```

## 提权终点不要写死

经典资料常把终点简化成修改 `cred`、覆盖 helper path、劫持函数表或 ROP 返回用户态。实际都必须逐项验证：

- 当前 task、namespace、user namespace、LSM 与 capability 状态；
- 目标数据是否只读、是否有完整性/CFI/refcount 检查；
- symbol 是否存在、导出、可调用且函数签名匹配；
- 题目真正目标是 root、读取 mount namespace 内的 flag，还是逃离容器；
- return-to-user frame、swapgs/KPTI trampoline 和寄存器是否匹配构建。

先选择能直接完成题目目标的数据/文件原语，再考虑更长的控制流链。不要把某篇旧文章的 `commit_creds`、`modprobe_path`、`tty_operations` 或 gadget offset 提升成跨版本接口。

## 安全查看与解包 initramfs

先列目录，不要直接在当前源码目录展开：

```bash
gzip -dc rootfs.cpio.gz | cpio -it

work_dir=$(mktemp -d)
mkdir "$work_dir/rootfs"
cd "$work_dir/rootfs"
gzip -dc /absolute/path/rootfs.cpio.gz | cpio -idm --no-absolute-filenames
```

`--no-absolute-filenames` 不能替代隔离：恶意归档还是值得在一次性容器/虚拟机里处理。若输入本来是不压缩的 newc cpio，去掉 `gzip -dc`，改成 `cpio -it < rootfs.cpio` 或 `cpio -idm < rootfs.cpio`。

解包后优先读：

```bash
sed -n '1,240p' init
find . -maxdepth 3 -type f -o -type l
find dev -maxdepth 2 -ls 2>/dev/null
```

特别注意 init 是否修改 sysctl、挂载 proc/sysfs、创建设备、`chmod` flag、降权，或设置自动关机。

## 编译并放入 exp

若环境允许静态程序：

```bash
musl-gcc -static -Os -Wall -Wextra -o exp exp.c
file exp
readelf -l exp | rg 'interpreter|GNU_STACK'
```

也可以用题目匹配的静态交叉工具链。`-masm=intel` 只影响内联汇编语法，不是所有 exp 都需要。先在本地相同架构运行到参数解析阶段，再复制：

```bash
cp /absolute/path/exp "$work_dir/rootfs/exp"
chmod 0755 "$work_dir/rootfs/exp"
```

重打包时必须站在 rootfs 根目录，避免把外层临时目录名字带进去：

```bash
cd "$work_dir/rootfs"
find . -print0 | cpio --null -o --format=newc | gzip -9 > /absolute/path/rootfs-patched.cpio.gz
```

在替换题目文件前先把输出作为新文件启动验证；不要覆盖唯一的原始附件。

## 不能共享目录时上传

base64 分块上传前先截断远端目标，避免重跑脚本时把第二份内容追加到后面：

```python
from base64 import b64encode

blob = open("exp", "rb").read()
encoded = b64encode(blob)

io.sendlineafter(b"$ ", b": > /tmp/exp.b64")
for off in range(0, len(encoded), 0x300):
    part = encoded[off:off + 0x300]
    io.sendlineafter(b"$ ", b"echo " + part + b" >> /tmp/exp.b64")

io.sendlineafter(b"$ ", b"base64 -d /tmp/exp.b64 > /tmp/exp")
io.sendlineafter(b"$ ", b"chmod +x /tmp/exp")
```

远端 shell 的行长、回显、超时和可用命令都可能不同。上传后比较 `sha256sum`；缺少 base64 时可考虑十六进制、压缩后传输或题目提供的共享目录。

## 调试

- QEMU 有 `-s -S` 时，`-S` 让 CPU 开机暂停，`-s` 等价于在 TCP 1234 开 gdbstub。
- GDB 加载带符号的 `vmlinux`，`target remote :1234` 后再在目标函数或漏洞驱动下断点。
- KASLR 开启时，先从允许的泄漏或调试接口求运行基址，再用 `add-symbol-file`/脚本修正符号；不要把一次启动的地址写死。
- 模块加载地址可从受控调试环境的 `/proc/modules` 或 sysfs 获取；正式题目可能限制这些接口。
- 先验证用户态 exp 的架构、静态依赖、设备路径和 ioctl 结构体，再调内核利用链。

## `IA32_LSTAR` 说明

x86-64 的 `IA32_LSTAR` MSR 编号是 `0xc0000082`，保存 64 位 `syscall` 的内核入口地址。它可用于已具备内核读取能力后的基址推导，但：

- 普通用户态不能直接执行 `rdmsr`；必须已经有相应内核原语、驱动接口或特权调试环境。
- 从入口地址减去哪个符号偏移，完全取决于题目内核构建；必须用对应 `vmlinux`/`System.map` 求值。
- KPTI 与入口 trampoline 会影响你看到的入口与后续控制流，不能套用旧笔记的固定偏移。

## 交付前检查

- 原始附件和改包后的附件 hash 是否分别保存？
- initramfs 的 `init`、设备权限和 exp 可执行位是否正确？
- 编译架构、内核结构体宽度和用户/内核 ABI 是否一致？
- QEMU CPU 选项与远端是否接近，缓解项是否真的按预期启用？
- exp 是否在重启后还能运行，而不是依赖上一次 shell 留下的文件？
- 泄漏与符号偏移是否来自同一个内核 Build ID/构建产物？

## 上游依据

- [Linux Kernel Self-Protection](https://www.kernel.org/doc/html/latest/security/self-protection.html)
- [Linux userfaultfd](https://www.kernel.org/doc/html/latest/admin-guide/mm/userfaultfd.html)
- [Linux kernel development tools](https://www.kernel.org/doc/html/latest/dev-tools/index.html)
- [KASAN](https://www.kernel.org/doc/html/latest/dev-tools/kasan.html)
- [KFENCE](https://www.kernel.org/doc/html/latest/dev-tools/kfence.html)
- [KMSAN](https://www.kernel.org/doc/html/latest/dev-tools/kmsan.html)
- [KCSAN](https://www.kernel.org/doc/html/latest/dev-tools/kcsan.html)

旧文件与本篇的迁移关系见 [`SOURCE_MAP.md`](./SOURCE_MAP.md)。
