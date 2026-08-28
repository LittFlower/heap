# ELF 动态链接与 relocation

动态链接题最容易把“文件里的表”“loader 内存状态”和“利用时能控制的数据”混在一起。本篇从启动流程出发，说明 GOT/PLT、dynamic tags、symbol version、IFUNC、ret2dlresolve 和 DynELF 各自需要什么事实。

## 从 `execve` 到 `main`

动态 ELF 的简化启动链：

```text
kernel 解析 ELF 与 PT_INTERP
  -> 映射主程序和 interpreter
  -> 在初始栈放 argc/argv/envp/auxv
  -> 跳到 loader 入口
  -> loader 搜索并映射 DT_NEEDED
  -> 处理 relocation、TLS、IFUNC、RELRO、constructors
  -> 跳到程序入口，再经 libc startup 到 main
```

实际利用前先采集：

```bash
readelf -lW ./chall | rg 'INTERP|LOAD|DYNAMIC|TLS|GNU_RELRO|GNU_EH_FRAME'
readelf -dW ./chall
readelf -rW ./chall
readelf -sW ./chall
readelf -VW ./chall
readelf -nW ./chall
```

`PT_DYNAMIC` 指向运行时 dynamic array；`.dynamic` 是它在 section 视角下的名字。运行时遍历要从已映射对象和 program header/dynamic tag 出发，不能假设 section headers 还在。

## 地址、文件偏移和 load bias

对一个映射对象：

```text
runtime address = ELF virtual address + load bias
```

但求 load bias 时要用匹配的 `PT_LOAD`、页对齐后的文件 offset 与映射起点。不能笼统地把 `/proc/PID/maps` 第一行减去 ELF entry；首个映射可能从非零 offset 开始，不同 segment 权限也会产生多行。

文件偏移与虚拟地址换算：

```text
file_offset = p_offset + (vaddr - p_vaddr)
```

只在 `vaddr` 落进这个 file-backed segment 的 `[p_vaddr, p_vaddr+p_filesz)` 时才成立；BSS 式尾部只有内存大小，没有对应文件字节。

pwntools 的 `ELF.address` 可以应用 load bias，但设置前还得确认泄漏属于哪个 ELF 对象。

## 动态符号与字符串

`.dynsym`/`DT_SYMTAB` 保存动态符号，`.dynstr`/`DT_STRTAB` 保存名字。关键字段：

- `st_name`：进入 string table 的偏移；
- `st_info`：binding 与 type；
- `st_shndx`：定义所在 section index，未定义外部符号通常是 `SHN_UNDEF`；
- `st_value`：对可重定位对象通常还需加 load bias；
- `st_size`：可能为零，不能作为函数边界的唯一依据。

```bash
readelf --dyn-syms -W ./chall
objdump -T ./chall
nm -D --with-symbol-versions ./chall
```

去除 `.symtab` 后，导入/导出所需的 `.dynsym` 可能还在。相反，静态链接或隐藏符号会让基于 dynamic symbol 的查找失效。

## relocation 速查

relocation 告诉 linker/loader：把哪个 symbol/addend 按哪种公式写到哪个 offset。ELF64 常见 `Rela` 带显式 addend；部分 ABI 主要用 `Rel`，addend 在目标位置中。

在 x86-64 动态 ELF 中常遇到：

| 类型 | 常见用途 |
|---|---|
| `R_X86_64_RELATIVE` | 不查 symbol，按 load bias 修正对象内部指针 |
| `R_X86_64_GLOB_DAT` | GOT 中的数据或函数地址 |
| `R_X86_64_JUMP_SLOT` | PLT 调用槽位 |
| `R_X86_64_COPY` | 可执行文件为外部数据保留副本，启动时复制 |
| `R_X86_64_IRELATIVE` | 调用 resolver 得到最终地址，常与 IFUNC 相关 |

其他架构的编号、结构和计算公式不同，必须查对应 psABI。不要从 relocation 名字直接推断目标页可写；还要结合 program header 和 RELRO 生效时机。

```bash
readelf -rW ./chall
objdump -R ./chall
objdump -drwC ./chall
```

## PLT/GOT 与 lazy binding

以常见 ELF 流程概括：

```text
call foo@plt
  -> 读取 foo 对应 GOT/PLT slot
  -> 未解析时进入 PLT resolver 路线
  -> loader 查 symbol/version，写回 slot
  -> 跳到最终函数
```

- `LD_BIND_NOW`、`DT_BIND_NOW` 或 `DF_1_NOW` 会要求启动时解析，而不是第一次调用时解析。
- Full RELRO 通常在 relocation 后把相关 GOT 页改成只读。
- 编译器可能使用 `-fno-plt`、直接 GOT 间接调用、linker relaxation 或重写后的 PLT，不能只凭经典 PLT0 模板定位。
- 已解析 slot 与未解析 slot 的内容不同；调试 ret2dlresolve 或 GOT 调用前要确认当前状态。

```bash
LD_DEBUG=bindings,reloc ./chall 2>ld-debug.log
LD_BIND_NOW=1 ./chall
```

这些环境变量在 secure-execution 模式可能被忽略或过滤；题目是 SUID/AT_SECURE 时不要依赖它们作为利用能力。

### 未绑定 GOT slot 重定向到另一条 PLT 解析路径

经典 lazy PLT 中，尚未解析的 `foo@got.plt` 往往指回 `foo@plt` 内部的 `push relocation-index` 路线。若 `.got.plt` 可写且两个 PLT stub 地址低位接近，部分写有时能让 `foo@got.plt` 改指向另一个 `bar@plt` 的解析入口：下一次调用 `foo@plt`，实际让 loader 解析的是 `bar`、调用的也是 `bar`。

硬条件包括：

- 原 slot 尚未解析，目标也存在可进入的 resolver stub；
- 没有 NOW/Full RELRO 阻止写入或提前绑定；
- partial overwrite 后精确落到目标 stub 的指令边界；
- `foo` 调用点当前寄存器/栈参数对 `bar` 有意义；
- resolver 写回哪个 GOT slot、后续调用是否重复解析，都按目标 PLT/relocation index 验证。

[Ltfall 的 GOT 未绑定表项技巧](https://ltfa1l.top/2023/12/28/system/tricks/tricks/)以 `atoi`→`printf` 为题目实例。不能把“改最低字节”或两个函数名当作固定配对；先同时查看 `objdump -d -j .plt`、`readelf -rW` 和调用前的 GOT 实值。

## symbol version

GNU symbol versioning 会使用 `.gnu.version`、`.gnu.version_r`、`.gnu.version_d` 等表把 symbol 与版本要求关联。

```bash
readelf -VW ./chall
readelf -sW ./libc.so.6 | rg ' system@| memcpy@'
objdump -T ./libc.so.6 | rg 'GLIBC_'
```

- `foo@@VER` 通常表示这个 DSO 里供无版本引用使用的默认版本；`foo@VER` 是指定版本。
- 同名符号在不同版本可指向不同实现或 ABI。只按名字找第一个 offset 可能错误。
- 题目加载失败报 `version 'GLIBC_X.Y' not found` 时，要恢复匹配的 loader/libc/依赖，别靠重命名文件掩盖。

## IFUNC

GNU indirect function 会在 relocation 期间调用 resolver，根据硬件能力或运行环境选择最终实现。因此：

- 符号表中的 IFUNC value 可能是 resolver，而 GOT 中最终地址是选中实现；
- `memcpy`/`strlen` 等实际地址可能因 CPU feature 不同而变；
- resolver 运行阶段很早，可调用接口受到限制；
- 泄漏某个 IFUNC 最终地址后减固定偏移识别 libc，必须绑定附件与选择结果，不能只绑定 symbol 名。

可用 loader 的 `--list-diagnostics` 查看 auxv、HWCAP 和部分 CPU feature 选择信息：

```bash
./ld-linux-x86-64.so.2 --list-diagnostics ./chall
```

这也会影响 gadget 稳定性：同一 libc 文件中的公共符号在不同 CPU/HWCAP 下可能绑定到不同内部实现。若 exploit 从泄漏到的 `memcpy`、`memmove` 等最终地址继续加减常量找 gadget，必须记录实际选中的实现；QEMU、宿主 CPU 与远端虚拟机可能给出不同结果。更稳妥的是从 ELF base 和 Build ID 重新搜索 gadget，而不是把 IFUNC 解析结果当作固定 symbol offset。

## ret2dlresolve

目标是让 loader 把攻击者布置的数据解释成 relocation、symbol 和 string，再解析一个原本不可直接调用的符号。最小条件通常包括：

1. 能控制返回路径或等价调用路径到 PLT resolver；
2. 有足够可写内存放伪表和参数；
3. 能把第二阶段数据送进这块内存；
4. 伪结构的对齐、索引、symbol version 处理满足目标 ABI/loader；
5. 解析结果写入的地址可写，随后能到达结果；
6. 目标符号实际存在于 loader 的搜索 scope，最终行为不被 seccomp/权限阻断。

Partial/Full RELRO 会改变可写位置和 lazy binding 状态，但不能用一句“Full RELRO 必然阻止 ret2dlresolve”代替目标验证。不同 loader 版本的边界检查也会改变伪表约束。

pwntools 提供 `Ret2dlresolvePayload`，用之前还是要检查它的 `.payload`、`.data_addr`、ROP dump 和 `unreliable` 状态：

```python
elf = context.binary = ELF("./chall", checksec=False)
rop = ROP(elf)
dlresolve = Ret2dlresolvePayload(elf, symbol="system", args=["/bin/sh"])
rop.read(0, dlresolve.data_addr, len(dlresolve.payload))
rop.ret2dlresolve(dlresolve)
log.info("\n%s", rop.dump())
```

在 seccomp 题中把 symbol/args 换成允许的目标；自动生成 payload 不会替你检查沙盒。

### `VERSYM` 会跟着伪 symbol index 一起移动

GNU loader 不只使用 `DT_SYMTAB + symidx * sizeof(Elf_Sym)`。对象存在 `DT_VERSYM` 时，它还可能读取：

```text
versym_addr = DT_VERSYM + symidx * sizeof(Elf_Half)
version_idx = *versym_addr & 0x7fff
```

因此把 fake `Elf_Sym` 放到离原 `.dynsym` 很远的 `.bss`，虽然能让 `symidx` 指到伪表，却可能使派生的 `versym_addr` 落到不可读页，或读出非零版本号后索引错误的 version table。[redpwnCTF 2021 devnull-as-a-service](https://www.tjcsec.club/writeups/redpwnctf-2021-devnull/)展示了这一约束；[UMassCTF zip_parser](https://acad.garywei.dev/blog/2022/ctf-zip-parser/)比较了 pwntools 布局与 fake `link_map` 路线。

调试时在 `_dl_fixup`/目标 loader 等价函数里同时记录 `symidx`、`symtab`、`strtab`、`versym` 和最终写回地址。常见解法是让派生读取落到已映射的零值区域、重定向相关 dynamic tag，或构造满足 loader 检查的 `link_map`；选择取决于目标 loader，不能只移动 fake symbol 后继续复用旧 relocation index。

## 低带宽写与 dynamic tags

当原语只有一次一字节写或极少次数的部分写时，loader 元数据有时能提供放大器：`DT_JMPREL`、`DT_STRTAB`、`DT_SYMTAB`、`DT_FINI_ARRAY` 等字段会在解析或退出路径被再次读取。可达目标必须同时满足：

1. 保留的指针高位让新值还落在目标 mapping 里；
2. relocation/symbol/string 的派生索引都可读且对齐；
3. loader 下一次确实会进入相应消费路径；
4. RELRO、版本检查和目标页权限允许所需读写；
5. 修改不会先破坏进程退出或解析所需的其他状态。

[DiceCTF 2022 Nightmare 替代解](https://github.com/LMS57/Nightmare-Writeup)组合了一字节写、退出循环、部分 dynamic tag 与 fake `link_map`。这个案例也说明，能否复现目标环境本身就是利用条件：`patchelf` 改 loader/RPATH 后可能改变对象相对布局，CPU feature 又可能改变 IFUNC 选择；本地补丁后的“相同 libc”不一定还保留原链。

## DynELF 与任意地址泄漏

DynELF 的核心不是猜 libc 版本，而是从一个已加载对象内指针和稳定的任意地址泄漏，定位 ELF base、dynamic array、link map 和 symbol table，再解析目标符号。

必要条件：

- 泄漏函数能读任意地址的至少部分连续 bytes；
- 读取失败可识别，不会永久破坏进程状态；
- 有一个确认属于目标 binary/DSO 的指针；
- 服务允许足够多次查询，地址布局在查询期间稳定。

```python
def leak(addr):
    # 每次必须返回从 addr 开始的 bytes；失败策略按协议实现
    return read_at(addr, 8)

resolver = DynELF(leak, pointer=known_libc_pointer)
system_addr = resolver.lookup("system", "libc")
```

泄漏跨页时常出现短读或 fault；分块读取、缓存已读页。如果附件 ELF 可用，传给 DynELF 能减少查询，但还要确保它与远端对象一致。

## BROP 中的 ELF 恢复

BROP 适用于无附件、可重复 crash 且新 worker 地址布局不变的特定服务模型。路线是先区分 crash/正常停顿，逐步得到 stop gadget、寄存器控制和 write 类输出，再把内存中的 ELF 导出。若每次 crash 后 exec/re-randomize、负载均衡到不同映像或响应不可区分，前提就不成立。

BROP 是条件严格的远程分析方法，不是“没有 libc 时爆破地址”的泛称。原始研究入口见 [Stanford BROP 页面](https://www.scs.stanford.edu/brop/)。

## loader 复现与诊断

```bash
# 验证 loader 能否处理目标，并列出解析结果
./ld-linux-x86-64.so.2 --verify ./chall
./ld-linux-x86-64.so.2 --library-path ./libs --list ./chall

# 只影响这一轮显式启动
./ld-linux-x86-64.so.2 --library-path ./libs --preload ./hook.so ./chall

# 查看搜索、relocation、symbol、version
LD_DEBUG=libs,files,reloc,symbols,versions ./chall 2>loader.log
```

显式启动 loader 时，`/proc/self/exe` 指向 loader 而不是目标程序，这会影响依赖这个路径的题目逻辑。直接修改 PT_INTERP/RPATH 也会改变附件 hash；保留原件、记录补丁。

对不可信二进制，静态 `readelf`/`objdump` 优先；不要为看依赖就直接在宿主机执行附件。

## 上游依据

- [AMD64 psABI](https://refspecs.linuxfoundation.org/elf/x86_64-abi-0.98.pdf)
- [GNU readelf/objdump 文档](https://sourceware.org/binutils/docs/binutils.html)
- [GNU ld 选项](https://sourceware.org/binutils/docs/ld/Options.html)
- [glibc Dynamic Linker](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker.html)
- [glibc Dynamic Linker Environment Variables](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Environment-Variables.html)
- [glibc Auxiliary Vector](https://sourceware.org/glibc/manual/latest/html_node/Auxiliary-Vector.html)
- [pwntools ret2dlresolve](https://docs.pwntools.com/en/stable/rop/ret2dlresolve.html)
- [pwntools DynELF](https://docs.pwntools.com/en/stable/dynelf.html)
