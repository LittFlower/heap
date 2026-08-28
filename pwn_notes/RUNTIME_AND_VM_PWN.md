# Rust、语言运行时与自定义 VM Pwn

CTF 题把实现语言换成 Rust，或在 C/C++ 上再套一层 bytecode VM、对象系统和 GC，并不会让底层分析方法失效。关键是先分清 guest 逻辑错误、runtime 内存破坏和 host 原生代码利用三层。

## 三层事实表

```text
Guest 层：opcode、寄存器/operand stack、linear memory、对象 id、类型 tag
Runtime 层：decoder、bounds check、对象表、GC、JIT/interpreter、allocator
Host 层：C ABI、native pointer、libc/ld、FILE、回调、syscall 与 sandbox
```

每个值都标出在哪一层解释。例如 guest 的 `index=0xffff` 可能先截断成 16 位，再在 runtime 中乘 element size，最后作为 host pointer offset。只写“VM 有 OOB”无法判断影响。

## 自定义 VM 先恢复这些状态

| 组件 | 要回答的问题 |
|---|---|
| instruction format | opcode/operand 各占几位，端序和变长编码如何处理？ |
| PC | byte offset 还是 instruction index，jump target 在何时校验？ |
| operand stack | 元素宽度、增长方向、push/pop 边界和 underflow 行为？ |
| registers | 是整数数组、tagged value，还是可容纳 host pointer？ |
| linear memory | base、size、扩容、load/store 宽度和 wraparound？ |
| object table | id→pointer 如何映射，free 后 id 是否失效或复用？ |
| type system | tag 在哪里，cast/opcode 是否验证 tag 与 payload 一致？ |
| GC | roots、mark、move/compact、forwarding pointer 和 finalizer？ |
| native bridge | 哪些 opcode 调用 libc、host callback、文件或 syscall？ |

建议先写一个只实现 decode 和状态变化的 Python model，用一组极短 bytecode 与真实程序逐步对照。反编译器里复杂的 switch、computed goto 或 handler table 先恢复成 opcode 表，不要一开始就追最终间接调用。

## 常见漏洞形状

### 栈 underflow/overflow

- `pop` 只移动 SP，未检查空栈，下一次读到相邻 runtime 字段；
- `push` 的容量比较发生在递增之后，留下 off-by-one；
- SP 为 unsigned，减一后回绕到很大 index；
- guest stack 增长方向与 host heap object 字段相邻，可改 base/limit。

第一次目标通常是 guest stack 的 base、limit 或 object-table pointer。修改它们后再把受限 OOB 放大为 host arbitrary read/write。

### 长度、单位和截断

```text
guest element count
  -> 窄 width header
  -> count * element_size
  -> host allocation/copy
```

检查 allocation 与 access 是否使用同一宽度；序列化长度是 byte 还是 element；扩容后的旧 pointer 是不是还留在对象或 opcode cache 里。

### 类型混淆

- 修改 type tag，让整数 bits 被解释成 pointer/ref；
- 数组 element kind 与 load/store opcode 不匹配；
- tagged pointer 的低位被 arithmetic 改坏，但 runtime 只检查部分 tag；
- object id 释放后复用成另一类对象，旧引用仍可调用方法。

目标不是停在“绕过类型检查”这句话，而是明确混淆后哪个字段会变成 host address、length、callback 或 free pointer。

### GC 与移动对象

GC 题至少画一次完整周期：

```text
root enumeration
  -> mark/reachability
  -> forwarding address
  -> move/compact
  -> reference fixup
  -> sweep/finalizer
```

重点检查 null/object-id 0、重复引用、cycle、weak reference、对象 size、alignment、forwarding pointer，以及 compaction `memmove` 的源/目标重叠。一次错误 mark 可能先损坏对象 header，再在移动阶段形成级联 OOB。

## 从 guest OOB 到 host 原语

按这个顺序找目标：

1. guest linear-memory base/size；
2. object table 的 host pointer 与 count；
3. 相邻 native object 的 data pointer/length/capacity；
4. runtime callback、vptr 或 interpreter dispatch table；
5. libc/loader/FILE 等最终目标。

如果能先把 guest buffer 指向任意 host address，就应建立稳定的 `read_host(addr,n)`/`write_host(addr,data)`，再按普通用户态 Pwn 分析。不要在 guest OOB 仍有复杂步长和副作用时直接写最终控制流目标。

## Rust 题目的边界

Safe Rust 能约束语言层的一大类内存错误，但 CTF 漏洞经常位于：

- `unsafe` block、raw pointer、`from_raw_parts` 或手工 allocator；
- C/assembly FFI 的长度、ownership 和 unwind 边界；
- 错误实现的 safe abstraction，把不满足前置的内部 unsafe 暴露给安全调用者；
- `Vec`/`VecDeque`/`String` 的 UAF、double drop 或伪造 raw parts；
- `#[repr(C)]`、union、transmute 和整数↔指针转换；
- 纯逻辑问题，例如索引授权、整数 wrap、状态机和文件能力泄漏。

分析 Rust binary 时先找 `panic_bounds_check`、drop glue、allocation symbols、trait object 的 data/vtable 双指针，以及 `core::ptr`/`alloc::vec` 附近的调用。优化和 monomorphization 会生成大量相似函数，函数名只是入口，真实 bounds check 以控制流为准。

不要把某一版 `Vec`、`VecDeque` 或 trait-object 私有布局写死。只有 `repr(C)` 和文档承诺的 FFI layout 才能按对应规范使用；标准库容器仍要绑定 rustc/stdlib 构建。

## Panic、Drop 与 unwind

- panic 是 abort 还是 unwind 由构建选项决定；两者消费路径完全不同。
- unwind 会执行已初始化局部对象的 Drop，半构造状态可能让同一资源被多条路径释放。
- `ManuallyDrop`、`mem::forget` 和 raw ownership transfer 会改变谁负责释放。
- FFI 边界是否允许 unwind、C++ exception 与 Rust panic 是否相遇，都要看目标 ABI 和构建。

调试 double free/UAF 时记录“哪个 owner 认为自己拥有资源”，不要只盯最后一次 allocator 报错。

## Dispatch table 与 host callback

Interpreter 常见：

```text
handler = table[opcode]
handler(vm, operands)
```

即使 table 本身只读，也可能通过：

- OOB opcode 取到表外指针；
- 改 VM context 中的 secondary method table；
- 伪造包含 callback 的 host object；
- 改 native-function index 或 import table；
- 让合法 handler 读写被污染的 base/length。

IBT/BTI/CFI 存在时，优先寻找合法 handler 与数据流组合，而不是假定能跳到任意中间地址。

题目改用 LLVM IR/bitcode + `opt` pass plugin 而不是自定义 bytecode VM 时，攻击面拆分、工具链匹配和调试方法见独立的 [`LLVM_PASS_PWN.md`](./LLVM_PASS_PWN.md)。

## VM fuzzing harness

源代码可改时，把“加载程序”和“执行若干步”拆开：

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    VM vm;
    vm_init(&vm);
    if (vm_load(&vm, data, size) == 0)
        vm_run_bounded(&vm, 10000);
    vm_destroy(&vm);
    return 0;
}
```

关键约束：

- 每个 testcase 重置 VM/allocator/global state；
- 给 instruction count、recursion、memory 和 output 加上限；
- sanitizer 报告必须落到 runtime 第一次非法访问，而不是 guest 的预期 trap；
- corpus 按 opcode、operand width、object lifecycle 和 GC cycle 覆盖；
- crash 最小化后保留 bytecode disassembly 和状态 trace。

二进制目标则可把 interpreter loop 作为 persistent boundary，或用 QEMU/Frida mode；具体工具流程见 [`FUZZING_AND_CRASH_TRIAGE.md`](./FUZZING_AND_CRASH_TRIAGE.md)。

## Writeup 提炼实例

- [redpwnCTF 2020 Rust Pwn](https://www.willsroot.io/2020/06/redpwnctf-2020-rust-pwn-writeups.html)：unsafe 删除路径释放对象但保留容器内 stale pointer，最后还是按 UAF 生命周期分析。
- [bi0sCTF 2025 Uninitialized VM](https://bi0sblog-1271c6.gitlab.io/2025/06/13/Pwn/UninitializedVM-bi0sCTF2025/)：VM stack 状态错误被放大成 host 任意读写，说明先攻击 base/limit 比直接找 PC 更清晰。
- [Hack.lu 2022 placemat](https://pwner.gg/ctf-writeups/2022-10-30-hacklu-placemat)：C++ fake vtable 还要满足 RTTI/typeinfo 消费，详见 [`CPP_REVERSE.md`](./CPP_REVERSE.md)。
- [Rusty CodePad](https://ctftime.org/writeup/11911)：语言/编译环境沙盒题要同时检查编译属性、symbol export、构建脚本与可访问文件，不应把“禁止 unsafe”理解成完整沙盒。

## 最终检查表

- guest 地址与 host pointer 是否被明确区分？
- 每个 index/length 的 width、signedness、单位和溢出点是否列出？
- VM OOB 的起点、步长、范围、次数和副作用是否可复现？
- GC 前后对象是否移动，stale reference 指向哪里？
- Rust unsafe/FFI 的 safety invariant 是什么，哪个调用者破坏了它？
- host arbitrary read/write 是否已用无害地址验证？
- 最终动作是否满足宿主 libc/loader、控制流保护和 seccomp？
