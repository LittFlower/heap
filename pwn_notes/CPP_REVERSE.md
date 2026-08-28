# C++ Pwn 与逆向速查

这篇只总结逆向时常见的 libstdc++ 形状。C++ 标准规定容器行为，不规定对象必须长成某个内存布局；以下结构都要结合目标的编译器、标准库、ABI 和优化级别核对。

## 先识别运行库与 ABI

```bash
file ./chall
readelf -p .comment ./chall
readelf -Ws ./chall | rg 'GLIBCXX|CXXABI|__cxa|_Unwind'
objdump -T ./chall | rg 'GLIBCXX|CXXABI'
c++filt '_ZNSt6vectorIiSaIiEE9push_backERKi'
```

- 动态符号中的 `GLIBCXX_*` 能帮助确定 libstdc++ 所需的最低符号版本，但不能单独还原编译器全部选项。
- `std::__cxx11::basic_string` 通常说明启用了 GCC 5 起的 libstdc++ 双 ABI 新字符串实现；没有这个名字也可能只是符号被裁剪。
- 静态链接、LTO、内联或去符号后，应从分配大小、字段访问步长、析构路径和异常清理共同判断，不要只认函数名。

## `std::vector<T>`

64 位 libstdc++ 中常见对象主体是三个指针：

```text
start           指向首元素
finish          指向已构造元素之后
end_of_storage  指向已分配空间之后
```

若确认是这种实现：

```text
size()     = (finish - start) / sizeof(T)
capacity() = (end_of_storage - start) / sizeof(T)
```

逆向时重点看这些信号：

- `finish == end_of_storage` 时进入扩容路径；扩容会分配新缓冲区、移动或复制元素、销毁旧元素，再释放旧缓冲区。
- `push_back` 的快路径在 `finish` 写入元素，再把 `finish` 增加 `sizeof(T)`。
- `vector<bool>` 是位压缩特化，不能套三个普通 `T *` 的元素解释。
- 自定义 allocator、调试模式和其他标准库实现都可能改变布局。旧笔记中的一段“vector 构造函数”反编译结果带有额外字段，只能视作某个题目或自定义类的样本。

## `std::string` 与 SSO

64 位、新 ABI 的 libstdc++ `std::string` 常见大小为 32 字节，概念形状是：

```text
data pointer
length
union {
    local buffer[16];
    allocated capacity;
}
```

- 短字符串常直接放在对象内，字符容量通常为 15，再留一个 `\0`；此时 `data` 指向对象自身的 local buffer。
- 长字符串由 `data` 指向堆，union 中保存 capacity。
- `length` 是逻辑长度，不含结尾 NUL；不要用 `strlen(data)` 代替，字符串可以包含 NUL。
- GCC 旧 ABI 使用过写时复制布局；libc++ 的 SSO 标记和字段顺序也不同。先用空串/短串/长串对象或构造、析构分支验证。

Pwn 题里，覆写 string 的 `data`、`length`、`capacity` 可能造成越界读写或析构时错误释放；但析构究竟会不会 free，取决于 `data` 是否被实现判为 local buffer。

## `std::shared_ptr<T>`

libstdc++ 中常见的 `shared_ptr` 对象有两个指针：

```text
stored pointer    operator-> / get() 返回的对象指针
control block     强弱引用计数、删除器等
```

需要区分：

- `shared_ptr<T>(new T)` 往往分别分配对象和控制块。
- `make_shared<T>` 通常把控制块与对象放进同一块分配中，对象地址不一定等于分配首地址。
- aliasing constructor 允许 stored pointer 与控制块实际管理的对象不同。
- 最后一个强引用释放时销毁对象；最后一个弱引用也离开后才释放控制块。

引用计数的字段宽度、原子操作和控制块虚表都是实现细节。逆向时沿 `_M_release`、析构函数和删除器调用确认，不要只按固定偏移篡改。

## iostream 识别

常见线索包括 `std::__ostream_insert`、`basic_streambuf::sputn`、`overflow`、sentry 构造/析构，以及一次输出后把 `width` 恢复为 0。

- `operator<<` 输出 C 字符串时会寻找 NUL；`std::string` 输出使用显式长度。
- `std::setw` 只影响下一次格式化字段，fill 字符、左右对齐和 stream state 会参与填充路径。
- 反编译里看到 locale facet、sentry、`badbit`/`failbit` 和异常处理块，不代表业务逻辑很复杂；先把它们折叠成“格式化输出”再追数据源。

## vtable、RTTI 与多继承

GCC/Clang 在 ELF 上常采用 Itanium C++ ABI。常见单继承对象首字段是 vptr，虚调用概念上是先取 vptr，再从固定 slot 取函数，把对象作为 `this` 传入。实际还要考虑：

- vptr 通常指向 vtable 的 address point，不一定指向整个表的开头；它前面可以有 offset-to-top 和 RTTI 指针。
- 多继承/虚继承可能让一个完整对象内出现多个 vptr，再通过 thunk 调整 `this`。
- deleting/complete/base destructor 可能各有入口；不能把第一个 destructor symbol 当作唯一析构行为。
- `_ZTV*`、`_ZTI*`、`_ZTS*` 分别常提示 vtable、typeinfo 和 type name，但去符号/LTO 后应从只读表与间接调用恢复。
- 编译器 CFI、AArch64 PAC/BTI 或 x86 IBT/SHSTK 会分别约束某些控制流边，运行时是否生效必须单独确认。

COOP 的严格前提是能伪造或劫持一组对象/vptr，再借助程序现有的虚调用 sites/循环来调度整函数；它不是把 vptr 改成任意函数地址的别名。先恢复对象布局、`this` 调整、合法目标集合和 dispatcher 数据流。

### fake vtable 不只有函数槽

Itanium ABI 下，vptr 指向 address point；它前方常有 offset-to-top 与 RTTI/typeinfo。若对象随后经过 `dynamic_cast`、`typeid`、异常匹配或库内的类型关系检查，只伪造 `vptr[slot]` 可能在到达虚调用前就失败。

[Hack.lu CTF 2022 placemat](https://pwner.gg/ctf-writeups/2022-10-30-hacklu-placemat)让 fake vtable 前方保留兼容 typeinfo，再替换目标虚函数槽。迁移时应逐条检查：

- vptr 指向的是 address point 还是表起点；
- `vptr[-2]`/`vptr[-1]` 在目标 ABI 下是否被读取；
- typeinfo 对象和它的名称/基类描述是否可读且匹配；
- thunk 是否调整 `this`，目标方法期望的对象字段是否已经伪造；
- deleting destructor、异常路径或后续 free 会不会再次消费对象。

如果程序只有一条不做 RTTI 的直接虚调用，就不用为了形式完整去伪造没人消费的字段；最终依据是实际调用链。

## 异常展开

常见符号：`__cxa_throw`、`__cxa_begin_catch`、`__gxx_personality_v0`、`_Unwind_RaiseException`。ELF 中的 `.eh_frame` 负责栈展开信息，`.gcc_except_table` 常保存语言相关的 landing pad 映射。

分析步骤：

1. 从 `__cxa_throw` 的调用点确定异常对象和类型信息。
2. 找 personality 与 LSDA 对应的 landing pad，区分清理路径和真正的 catch。
3. 检查编译器生成的析构清理，避免把正常异常边误判成隐藏控制流。
4. 若考虑控制流利用，必须验证 unwind metadata、CFA 和寄存器恢复；单独改某个返回地址不会自动让指定 catch 接管。

### 让 unwinder 选择另一条 landing pad

若程序随后确实抛出异常，unwinder 会用各 frame 的恢复 PC 在 LSDA call-site table 中查找受保护区间与 landing pad。所以有的题目可以污染保存的返回 PC，让这个 frame 被解释成“异常发生在另一个 try 区间”，从而进入不同 cleanup/catch。

这不是普通 saved-RIP 劫持：

- 被污染 frame 必须还有合法 FDE/CFA，unwinder 能恢复到它；
- 恢复 PC 必须落入目标 call-site range，边界上还可能按 ABI 使用 `PC-1` 语义；
- LSDA action/type filter 必须接受当前异常类型，cleanup 与 catch 不能混称；
- landing pad 入口依赖 personality 设置的异常对象/selector 寄存器和编译器生成的栈状态；
- 地址加一或填满某段 code 只可能是题目附件中的试探，不是通用公式。

可在 `__cxa_throw`、personality 和 landing pad 下断点，用 `readelf --unwind`、`.eh_frame` 与 `.gcc_except_table` 交叉验证。[Ltfall 的 C++ 异常技巧](https://ltfa1l.top/2023/12/28/system/tricks/tricks/)提供了这种题型入口，这里把它收敛到实际 unwind metadata。

## `unordered_map` 的保守识别

不同库和版本的桶、节点、缓存 hash 策略差异很大。可以先找：

- 一组 bucket 指针和 bucket count；
- 单独分配的链式节点；
- `size`、`max_load_factor` 与 rehash 分支；
- hash、取模或 fast range hash 的调用。

确认具体 libstdc++ 版本后，再给 IDA 导入匹配的类型。不要把一份题目中的 bucket 偏移写成通用结论。

## 漏洞分析检查表

- 容器对象本身在栈、堆还是全局区？元素缓冲区是否另行分配？
- 对象当前处于 SSO、堆存储、已 move-from，还是异常清理中的半构造状态？
- 长度、容量和指针能分别控制到什么程度？
- 析构、扩容、拷贝、移动分别会调用哪个释放或删除器？
- 题目链接的是 libstdc++ 还是 libc++，是否开启 `_GLIBCXX_DEBUG` 或旧字符串 ABI？
- 固定偏移是否已用附件的动态库和实际对象样本验证？

语言 ABI 可对照 [Itanium C++ ABI](https://itanium-cxx-abi.github.io/cxx-abi/abi.html)，COOP 原始研究和其他来源见 [`UPSTREAM_REFERENCES.md`](./UPSTREAM_REFERENCES.md)。

自定义 bytecode VM、Rust unsafe/FFI 和 guest→host 原语升级见 [`RUNTIME_AND_VM_PWN.md`](./RUNTIME_AND_VM_PWN.md)。旧文件与本篇的迁移关系见 [`SOURCE_MAP.md`](./SOURCE_MAP.md)。
