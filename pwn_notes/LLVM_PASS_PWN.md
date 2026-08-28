# LLVM Pass Pwn

这类题通常让服务接收用户提交的 LLVM IR/bitcode，再交给 `opt`，动态加载题目提供的 pass plugin。攻击面可以分成：

```text
受控 IR/bitcode
  -> pass 的 visitor/transform 逻辑
  -> LLVM C++ 对象与 allocator
  -> 宿主 opt 进程的 native memory、ELF 与 libc
```

## 先匹配工具链和 Pass Manager

LLVM major version、C++ ABI、IR dialect 与 Pass Manager 都可能决定插件能否加载。旧式插件常见：

```bash
opt -load ./Plugin.so -legacy-pass ./exp.ll
```

New Pass Manager 插件常见：

```bash
opt -load-pass-plugin=./Plugin.so -passes='pass-name' ./exp.ll
```

先执行 `opt --version`、`file/readelf`，再用匹配 major 的 `clang -S -emit-llvm` 生成 IR。opaque pointer、target triple、data layout 和 intrinsic 在版本间也可能不兼容；“能被 clang 编译成 `.ll`”不等于目标 `opt` 能接受。

## 恢复注册入口和真正处理函数

- Legacy PM 可搜索 `RegisterPass` 产生的 option/name 字符串，以及 `runOnModule`、`runOnFunction` 等虚函数。
- New PM 优先找导出的 `llvmGetPassPluginInfo`、pipeline parsing callback 和 `run(...)` 实现。
- 全局 constructor、`__cxa_atexit` 和 vtable 只是定位线索；“最后一个 vtable slot 就是 `runOnFunction`”不是 ABI 规则。
- 先恢复题目 pass 对 IR 类型、operand 数量、常量宽度、BasicBlock/Instruction 生命周期的假设，再寻找 OOB、UAF、类型混淆或整数截断。

宿主是题目附带的 `opt`，不是 plugin `.so` 本身。PIE、RELRO、CET、libstdc++ 和 allocator 状态必须从实际 `opt` 与依赖重新采集，不能因为某道旧题的宿主无 PIE/Partial RELRO 就当成题型特征。

## 调试

```gdb
file ./opt
set args -load ./Plugin.so -legacy-pass ./exp.ll
catch load
run
info sharedlibrary
```

plugin 映射后再按 load bias 给处理函数下断点；也可在 `dlopen`、`llvmGetPassPluginInfo` 或已恢复的 pass callback 停住。复现必须保留服务使用的完整命令行、工作目录、环境变量和资源上限。

这一流程由 [Ltfall 的 LLVM Pass Pwn 笔记](https://ltfa1l.top/2023/12/28/system/tricks/tricks/)提供题型入口，并按 LLVM 官方的 [`opt` 文档](https://llvm.org/docs/CommandGuide/opt.html)、[New Pass Manager](https://llvm.org/docs/NewPassManager.html)和[Pass plugin 接口](https://llvm.org/docs/WritingAnLLVMNewPMPass.html)补全版本分支。

漏洞挖到 host native memory 之后，按普通用户态 Pwn 分析；若题目改用受控 bytecode/VM 而不是 LLVM IR，见 [`RUNTIME_AND_VM_PWN.md`](./RUNTIME_AND_VM_PWN.md)。fuzzing harness 写法见那篇的"VM fuzzing harness"一节，思路同样适用于给 pass 喂 IR。
