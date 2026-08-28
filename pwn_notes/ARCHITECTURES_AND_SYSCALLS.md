# 架构、ABI 与 syscall 速查

跨架构题首先分清三套约定：C 函数调用 ABI、Linux 原始 syscall ABI、目标二进制实际采用的 ABI 变体。寄存器名字相似不代表三者参数位置相同；最典型的是 x86-64 的第 4 个 C 参数在 `rcx`，第 4 个 syscall 参数在 `r10`。

## 先识别

```bash
file ./chall
readelf -hW ./chall
readelf -AW ./chall
readelf -nW ./chall
objdump -f ./chall
```

记录：

```text
ISA: x86 / AArch32 / AArch64 / MIPS / RISC-V ...
ELF class: 32 / 64
endianness: little / big
ABI: SysV amd64, ARM EABI, MIPS o32/n32/n64, RISC-V LP64D ...
instruction state/extensions: Thumb, MIPS delay slot, RVC, PAC/BTI/CET ...
libc: glibc / musl / uClibc / static runtime ...
```

`file` 的一句话只是起点。MIPS ABI flags、RISC-V attributes、Arm build attributes 和 GNU property notes 都可能改变反汇编和调用约定。

## 常见用户态函数调用

| ABI | 整数/指针参数 | 返回值 | 返回地址 | 关键栈规则 |
|---|---|---|---|---|
| i386 SysV | 栈上传参 | `eax` | 栈 | caller 清理常见；4-byte 对齐只是最低理解，编译器可提高对齐 |
| x86-64 SysV | `rdi,rsi,rdx,rcx,r8,r9`，其余上栈 | `rax`/`rdx:rax` | 栈 | call 前按 ABI 保持 16-byte 对齐；有 128-byte red zone |
| AArch32 AAPCS | `r0-r3`，其余上栈 | `r0`/`r1:r0` | `lr`/`r14` | 公共接口通常要求 8-byte 栈对齐；需区分 ARM/Thumb |
| AArch64 AAPCS64 | `x0-x7`，其余上栈 | `x0`/`x1:x0` | `x30` | `sp` 在公共接口保持 16-byte 对齐；`x29` 常作 frame pointer |
| MIPS o32 | `a0-a3`，其余在参数区/栈 | `v0`/`v1:v0` | `ra` | 有 delay slot；调用方通常预留 argument build area |
| RISC-V psABI | `a0-a7` | `a0`/`a1:a0` | `ra`/`x1` | 标准 ABI 下 `sp` 16-byte 对齐；`s0-s11` callee-saved |

聚合类型、浮点、向量、variadic 和 ABI variant 的规则更复杂。逆向 CTF 整数参数时表格够作起点，伪造完整调用 frame 或 FFI 时必须读对应 psABI。

## Linux 原始 syscall

下表是常见 Linux ABI 的快速起点，syscall number 必须从目标架构 headers/内核表获取，不能用宿主机号码。

| 架构/ABI | 进入指令 | syscall nr | 参数寄存器 | 结果 |
|---|---|---|---|---|
| i386 | `int 0x80` | `eax` | `ebx,ecx,edx,esi,edi,ebp` | `eax` |
| x86-64 | `syscall` | `rax` | `rdi,rsi,rdx,r10,r8,r9` | `rax`；`rcx,r11` 被硬件路径改写 |
| AArch32 EABI | `svc 0` | `r7` | 通常从 `r0` 起 | `r0` |
| AArch64 | `svc 0` | `x8` | `x0-x5` | `x0` |
| MIPS o32 | `syscall` | `v0` | `a0-a3`，更多参数从用户栈取 | `v0`，`a3` 表示错误状态 |
| RISC-V | `ecall` | `a7` | `a0-a5` | `a0` |

glibc wrapper 与 raw syscall 还不同：wrapper 会把 kernel error 转成 `-1`、设置 `errno`，也可能把旧 API 映射到 `openat`/`dup3` 等新 syscall，或加入线程取消逻辑。seccomp 过滤看到的是实际进入内核的 syscall 和参数，不是 C 源码函数名。

最可靠核对方法：

```bash
# 在匹配架构 sysroot 中
rg '__NR_(read|write|openat|execve)' sysroot/usr/include

# 动态观察 wrapper 最终调用
strace -f -e trace=read,write,open,openat,execve,execveat ./chall
```

## x86-64 易错点

- C ABI 第 4 参数是 `rcx`；syscall 第 4 参数是 `r10`。
- `syscall` 会把返回 RIP 放入 `rcx`，flags 放入 `r11`，不能指望它们保持参数值。
- 函数入口附近的 `endbr64` 是 IBT landing pad；它不是 NOP 语义之外的“万能 gadget 标记”，运行时是否启用 IBT 另行确认。
- red zone 位于当前 `rsp` 以下 128 bytes，只允许 leaf code 在 signal 语义约束下使用；ROP 读入第二阶段时不能默认其中数据跨函数调用保持。
- 变参函数调用还涉及 `al` 中的向量寄存器使用计数等 ABI 细节；直接跳进 printf 家族中间时尤其要核对。
- 地址 canonical 规则随启用的虚拟地址宽度变化；不要把所有高位非零地址用固定 48-bit mask 截断。

## x86-64 long mode 与 compat mode 切换

部分 x86-64 Linux CTF 环境允许用户态通过 far control transfer 把 `CS` 切到 32-bit compatibility code segment，再使用 i386 的 `int 0x80` syscall ABI。它可能让“同一个 syscall number”获得另一套含义，例如 x86-64 number 5 与 i386 number 5 不是同一个调用。

这条路线条件很严：

- kernel 必须启用 IA32 emulation、暴露可用的用户 code/data selector；常见 `0x23/0x33` 只是特定 Linux GDT 布局，不是 x86 ISA 常量。
- compat mode 的有效指针和栈通常必须落在低 4 GiB；高地址 `rsp`、代码或参数会被截断或 fault。
- far return 会从栈取 offset 和 selector并按架构规则加载 `CS:RIP`；它不等价于“`jmp rsp; mov cs,...`”。operand size、frame 宽度和返回 64-bit 的另一侧都要逐条反汇编。
- `int 0x80` 使用 i386 syscall number/寄存器约定，进入 seccomp 时也必须按实际 `seccomp_data.arch` 与目标 kernel 验证。
- CET、signal、vDSO、调试器和容器 kernel 可能改变可用性或观察结果。

[Ltfall 的技巧汇总](https://ltfa1l.top/2023/12/28/system/tricks/tricks/)把它概括为 `retf/retfq` 切换 32/64 位；可迁移的部分是“检查多 ABI 入口”，不是固定两次 `push` 模板。seccomp 正确先拒绝非预期 arch 时，这条路线不会绕过过滤器。

## AArch32 / Thumb

- AArch32 函数指针低位常编码 Thumb state；实际指令地址需清低位，但通过 `bx`/`blx` 调用时低位影响状态切换。
- ARM state 常见 4-byte 指令，Thumb/Thumb-2 包含 16/32-bit 指令；从错误半字开始反汇编会得到完全不同 gadgets。
- PC 读取语义、conditional execution 和 literal pool 会让“当前指令地址”与反编译器显示不同。
- `pop {..., pc}`、`bx lr`、`ldm` 等都可结束 gadget，但寄存器集合和栈增长量必须逐条计算。
- ARM EABI syscall number 不应套用旧 OABI immediate 编码。

```bash
arm-linux-gnueabihf-objdump -drwC ./chall
arm-linux-gnueabihf-objdump -drwC -M force-thumb ./chall
```

工具链前缀按目标 hard/soft-float ABI 调整。

## AArch64

- 普通指令固定 4 bytes，无 Thumb state；`x30` 保存 link register。
- 写 `wN` 会把对应 `xN` 高 32 位清零，这既可构造常量，也会意外截断指针。
- 常见函数序言保存 `x29,x30`，但优化后不保证存在 frame pointer。
- `ret` 默认使用 `x30`，也可指定其他寄存器；ROP 不能只搜索栈上的连续返回地址。
- `paciasp`/`autiasp`、`retab`、BTI 和 tagged pointer 影响返回地址/间接调用与指针解释，先看 [`BINARY_RECON_AND_MITIGATIONS.md`](./BINARY_RECON_AND_MITIGATIONS.md)。
- 立即数常通过 `movz/movk`、`adrp+add/ldr` 分段形成；逆向时把 relocation 与指令对照。

[Perfect Blue 的 AArch64 ROP 实例](https://blog.perfect.blue/ROPing-on-Aarch64)强调了最实用的筛选标准：优先找能从栈恢复 `x30` 的函数尾声，完整记录它同时恢复的寄存器、`sp` 增量和下一次 `ret`。调用链所需的 `x0`～`x7` 常要借助多寄存器 epilogue 分阶段布置，而不是照搬 x86 的“每个参数一个 pop”。

## MIPS

- 先确认 big/little endian 和 o32/n32/n64；指针宽度、ELF class 与寄存器宽度不能凭“MIPS64 CPU”猜。
- 传统 MIPS branch/jump 后有 delay slot；gadget 的最后一条跳转之后还可能执行一条指令。
- PIC 代码常依赖 `$gp` 和 `$t9`；直接跳入函数但不设置它们，可能在第一次 GOT 访问崩溃。
- o32 的第 5 个及后续 syscall 参数从用户栈取，伪造 syscall 时要按内核 ABI 布置。
- `$a3` 常用于 raw syscall error 标记，不能只看 `$v0` 是否负数。

```bash
mips-linux-gnu-objdump -drwC -M no-aliases ./chall
mipsel-linux-gnu-objdump -drwC -M no-aliases ./chall
```

## RISC-V

- `ra=x1`、`sp=x2`、`a0-a7=x10-x17`；`a0/a1` 也承担返回值。
- `jal`/`jalr` 写返回地址；伪指令 `ret` 通常是 `jalr x0, 0(ra)`。
- RVC 压缩扩展允许 16-bit 指令，gadget 搜索和地址对齐要按 ELF attributes/实际 code 判断。
- `gp`/`tp` 是不可随意分配的 ABI 固定寄存器；信号和 TLS 路径可能依赖。
- linker relaxation 会把汇编/relocation 序列改写，源码级 `call`/`la` 与最终机器码未必一一对应。

## Endianness 与打包

“地址看起来反了”通常是把整数显示和内存 byte order 混淆。以整数 `0x11223344` 为例：

```text
little endian memory: 44 33 22 11
big endian memory:    11 22 33 44
```

pwntools：

```python
context.clear(arch="mips", bits=32, endian="big", os="linux")
word = p32(0x11223344)
assert u32(word) == 0x11223344
```

协议字段端序可以与 CPU 不同，`htons`/`ntohl` 表示 network byte order。分别记录 CPU endian、ELF endian、协议 endian 和文件格式 endian。

## QEMU 用户态复现

```bash
qemu-aarch64 -L ./sysroot ./chall
qemu-arm     -L ./sysroot ./chall
qemu-mipsel -L ./sysroot ./chall
qemu-riscv64 -L ./sysroot ./chall

# 等待 GDB，端口按需更换
qemu-aarch64 -g 1234 -L ./sysroot ./chall
```

```gdb
set architecture aarch64
set sysroot /absolute/path/sysroot
file ./chall
target remote :1234
```

QEMU user emulation 与宿主共享 kernel，不等价于完整目标系统：seccomp、procfs、signal、auxv、vDSO、线程和边缘 syscall 行为可能不同。内核题用 system emulation 和题目 kernel/rootfs。

## 上游依据

- [Linux `syscall(2)` 的架构表](https://man7.org/linux/man-pages/man2/syscall.2.html)
- [AMD64 psABI](https://refspecs.linuxfoundation.org/elf/x86_64-abi-0.98.pdf)
- [Arm ABI 规范](https://github.com/ARM-software/abi-aa)
- [RISC-V ELF psABI](https://github.com/riscv-non-isa/riscv-elf-psabi-doc)
- [GNU objdump 架构与反汇编选项](https://sourceware.org/binutils/docs/binutils/objdump.html)
- [glibc System Calls](https://sourceware.org/glibc/manual/latest/html_node/System-Calls.html)
