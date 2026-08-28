# ABI、ROP 与栈迁移

## x86 条件跳转

条件跳转只解释前一条会更新 EFLAGS/RFLAGS 的指令；先确认比较操作数的顺序。

| 无符号关系 | 指令 | 关键 flags |
|---|---|---|
| `>` | `ja` / `jnbe` | `CF=0 && ZF=0` |
| `>=` | `jae` / `jnb` / `jnc` | `CF=0` |
| `<` | `jb` / `jnae` / `jc` | `CF=1` |
| `<=` | `jbe` / `jna` | `CF=1 || ZF=1` |

| 有符号关系 | 指令 | 关键 flags |
|---|---|---|
| `>` | `jg` / `jnle` | `ZF=0 && SF=OF` |
| `>=` | `jge` / `jnl` | `SF=OF` |
| `<` | `jl` / `jnge` | `SF!=OF` |
| `<=` | `jle` / `jng` | `ZF=1 || SF!=OF` |

旧笔记中的 `JBNE` 不是这里需要的标准别名；“无符号大于”对应 `JA/JNBE`。

## Linux 调用约定：ROP 视角

i386/x86-64 及其他架构的完整参数寄存器表、syscall 寄存器表见 [`ARCHITECTURES_AND_SYSCALLS.md`](./ARCHITECTURES_AND_SYSCALLS.md#常见用户态函数调用)。这里只记 ROP 时容易踩的坑：

- x86-64 `syscall` 会破坏 `rcx` 和 `r11`，这两个寄存器不能跨 `syscall` 保留参数或返回地址。
- 调用普通函数前必须满足 ABI 的 16 字节栈对齐。ROP 中若 `system`、`printf` 等在 `movaps` 附近崩溃，常见修复是加入一个单独的 `ret`，但应先计算当前 `rsp` 而不是盲加。
- i386 `cdecl` 由调用者负责回收参数栈空间，跳板函数返回后若没有对应清理，栈指针会与预期偏移不一致。

## ROP gadget 检索

优先使用附件本身和准确 Build ID 的 libc：

```bash
ROPgadget --binary ./pwn --only 'pop|ret'
ROPgadget --binary ./libc.so.6 --string '/bin/sh'
ropper --file ./libc.so.6 --search 'syscall; ret'
rp-lin -f ./libc.so.6 -r 5 | rg 'xchg|mov rdx'
```

pwntools 中先用内置 ROP 搜索：

```python
rop = ROP(libc)
pop_rdi = rop.find_gadget(["pop rdi", "ret"]).address
ret = rop.find_gadget(["ret"]).address
```

缓存 gadget 时必须把 ELF Build ID 或文件哈希写入缓存键。只用固定文件名 `gadgets`，换 libc 后很容易静默复用错误偏移。

## 栈迁移

常见入口：

```text
pop rsp ; ret
leave ; ret
add rsp, imm ; ret
xchg reg, rsp ; ret
```

### `leave ; ret`

`leave` 等价于：

```text
mov rsp, rbp
pop rbp
```

因此 fake stack 开头先放新的 `rbp`，下一项才是 `ret` 取出的 RIP：

```text
fake_stack + 0x00: next_rbp
fake_stack + 0x08: first_gadget
fake_stack + 0x10: ...
```

“迁到 `.bss+0x800`”不是硬规则。真实要求是新区域可写、地址对齐，还得给 ROP 链、被调用函数的栈帧、red zone/信号帧和后续输入留下足够空间。

### 只有一次受控 read 时

典型两阶段：

1. 第一次覆盖 saved `rbp`，让函数尾声把栈切到可写区，再调用一次 `read`。
2. 第二次写入泄漏链或最终 ROP，再次 pivot。

所有偏移都由目标函数真实 frame 计算；不要直接复制旧笔记中的 `0x80`、`.bss+0x300` 等示例常量。

若重新进入 `main` 会重复复杂状态机，可以在第一条 ROP 内连续完成“泄漏→`read` 第二阶段到 `.bss`→pivot”，不必让程序重新走菜单。前提是第一阶段已经能调用输出和输入函数，leak 返回后还有足够栈空间执行 pivot；远端脚本要按顺序先收泄漏再发第二阶段，避免 stdio 预读把两阶段粘在一起。

### 利用间接跳转槽位 pivot

如果存在：

```text
push qword ptr [slot_a]
jmp  qword ptr [slot_b]
```

而且两个槽位都可写，就可以让 `slot_b` 指向 `pop rsp; ret`，让 `slot_a` 提供新栈地址。这属于二进制特定的 JOP/pivot 组合，必须确认 push 后的栈效果和 RELRO。

## ret2csu

经典 x86-64 `__libc_csu_init` 常有两段 gadget：

```text
# 调用段
mov rdx, r14
mov rsi, r13
mov edi, r12d
call qword ptr [r15 + rbx*8]
add rbx, 1
cmp rbp, rbx
jne ...

# 收尾段
add rsp, 8
pop rbx
pop rbp
pop r12
pop r13
pop r14
pop r15
ret
```

最常见的一次调用设置为：

```text
rbx = 0
rbp = 1                 # 调用后 rbx++，与 rbp 相等才退出循环
r12 = arg1_low32        # mov edi,r12d 会把高 32 位清零
r13 = arg2
r14 = arg3
r15 = address_of_table  # [r15] 中存放真正被 call 的函数地址
```

注意：

- 间接调用地址是 `[r15 + rbx*8]`，不是旧笔记误写的 `[r12 + rbx*8]`。
- 初始 `rbp` 和 `rbx` 不是简单设置成相同值；经典单次循环是 `rbp=rbx+1`。
- 调用结束还要为 `add rsp,8` 和六个 pop 提供 7 个 qword，再放下一段 RIP。
- 第一参数经过 `edi`，只能自然控制低 32 位；需要完整 64 位 `rdi` 时另找 gadget 或做第二阶段。
- 新工具链生成的二进制可能没有这组经典 CSU gadget，必须先反汇编确认。

这类序列的原始系统化讨论见 [Black Hat Asia 2018 return-to-csu](https://i.blackhat.com/briefings/asia/2018/asia-18-Marco-return-to-csu-a-new-method-to-bypass-the-64-bit-Linux-ASLR.pdf)。论文给的是 gadget 搜索与寄存器约束方法，不保证所有 x86-64 ELF 都有固定的 `__libc_csu_init` 模板。

### 只借 CSU 设置寄存器时选择低副作用 callee

经典调用段无法跳过 `call [table+index*8]`。如果暂时只想把 `rdx/rsi` 等值带到收尾后的下一段，可以找一个返回后几乎不改这些寄存器的短函数，再找到**内存中指向它的 qword**作为间接调用表项。旧 ELF 的 `_fini` 有时只是调整栈后返回，`DT_FINI` dynamic entry 的 value 位置又可能提供这个指针。

必须反汇编目标 `_fini`，检查 dynamic entry 的运行时值、地址权限和 PIE relocation；传给 CSU 的是“存放函数地址的槽位”，不是 `_fini` 代码地址本身。新工具链可能没有合适的 `_fini`，callee 也可能经过 instrumentation、CET 或其他初始化。这个候选来自 [Ltfall 的 ret2csu 技巧](https://ltfa1l.top/2023/12/28/system/tricks/tricks/)，这里只借鉴它的间接调用选择方法。

## saved return address 的低字节覆盖

只能改返回地址最低 1～2 bytes 时，先把所有可达目标限制在“保留高位后的地址集合”中：

```text
new_rip = (old_rip & ~mask) | controlled_low_bits
```

逐项核对：

- 覆盖宽度和自动 NUL 是否恰好落在 saved RIP；
- 原 RIP 与目标是否处于同一可保留高位的范围；
- PIE 的页内 offset 是否固定，重启后更高位是否变化；
- 目标入口是否需要正常函数序言、栈对齐或额外寄存器状态；
- ASLR 未控制位造成的单次成功率，以及服务是 fork 继承还是重新 exec。

[DUCTF 2023 onebyte](https://halcyondream.org/2023/09/19/onebyte-writeup.html)可作为这种思路的实例。它说明单字节也能选择附近 basic block 或重新进入输入路径，但具体低字节和成功概率只属于目标二进制。

## 数据搬运与间接调用 gadget

找不到 `pop rdx` 等简单 gadget 时，可搜索：

```text
mov rdx, [rdi + off] ; ... ; call [rdx + off2]
mov rax, [rdi]       ; mov rdi, ... ; jmp rax
mov rbp, [rdi + off] ; ... ; call [rax + off2]
```

分析方法：

1. 把每条指令写成“输入字段 → 寄存器/内存”的等式。
2. 标出调用前必须可读、可写、对齐的所有地址。
3. 检查中途 clobber、隐式栈写和函数序言。
4. 用目标 libc 搜到 gadget 后记录 Build ID；旧笔记中的绝对偏移只可作为搜索特征。

## wrapper 中间入口

“`read+16` 恰好是 `syscall; ret`”只可能成立于特定 libc 的特定机器码。使用前必须：

```bash
objdump -d -M intel ./libc.so.6 | rg -n '<(__libc_)?read@@|syscall'
```

从函数中间进入会跳过取消点、错误处理或栈调整，必须逐条确认入口前置；有独立 `syscall; ret` 时优先使用独立 gadget。

## SROP

Sigreturn-oriented programming 至少需要：

- 控制 `rax` 为对应架构的 `rt_sigreturn` 系统调用号；
- 执行 `syscall`/等价入口；
- `rsp` 指向内核接受的信号帧布局；
- 恢复后的 `rip/rsp/cs/ss/eflags` 和目标系统调用参数合法。

用 pwntools 的 `SigreturnFrame` 生成帧，还得指定正确架构和 kernel ABI。旧笔记中的“frame +0 必须可执行”“某寄存器必须为 0”不是跨架构通用规则，按目标帧定义和内核恢复路径来核对。

## 固定 vsyscall 地址

`0xffffffffff600000` 一带是历史 x86-64 vsyscall 区域。是否可执行、是原生映射还是内核模拟、能否作为固定地址 gadget 取决于内核启动参数和发行版配置。它可作为老题的 partial-overwrite 思路，但不能当作当前 Linux 必有的 `ret` 滑道。
