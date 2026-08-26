# House of Banana

## 结论

- 适用范围：**`exit→_dl_fini→DT_FINI_ARRAY` 这条最终触发点覆盖 2.23～2.43；Ha1vk 最初公开的 exploit 是针对 glibc 2.30 写的**。经典 largebin attack 在 2.30～2.41 是常见的投递方式，到了 2.42～2.43 就必须另找一条任意写或 chunk overlap 才能投递。
- 原语/效果：改写 rtld 命名空间或 link_map，让 exit→_dl_fini 这条路径去消费我们伪造的 DT_FINI/DT_FINI_ARRAY。
- 版本变化：2.42 起不能再用经典 largebin 写任意目标；2.43 的 `_dl_fini` 把具体调用逻辑拆到了 `_dl_call_fini` 里，但消费语义没有变。`link_map` 属于 ld.so 的私有 ABI，即使是同一个 glibc 版本，不同构建也得重新量一遍偏移。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 能改 rtld 命名空间/`link_map` 指针并布置 fake map；libc/ld leak |
| 关键环境与不变量 | 私有 `link_map` 布局、`l_real/l_init_called`、DT_FINI_ARRAY/SZ；exit |
| 最终输出原语 | `_dl_fini` 调受控 fini array，获得 CF |
| 版本边界应如何理解 | 最终触发点持续到 2.43，但强依赖 Build ID；经典 largebin 投递止于 2.41。2.42+ 若另有 AAW 仍可用 Banana，这是投递断裂而非思想硬封。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 从源码看

`elf/dl-fini.c` 会先按命名空间的 `_ns_loaded` 链枚举对象，要求枚举出的计数和 `_ns_nloaded` 一致，并且只把 `l == l_real` 的节点收进 `maps[]`。排序完成后，它只会去消费 `l_init_called` 为真的节点；2.43 把下面这段逻辑挪到了 `elf/dl-call_fini.c`，但关键数据流没有变：

```c
array = (ElfW(Addr) *)
  (map->l_addr + map->l_info[DT_FINI_ARRAY]->d_un.d_ptr);
size_t count =
  map->l_info[DT_FINI_ARRAYSZ]->d_un.d_val / sizeof (ElfW(Addr));
while (count-- > 0)
  ((fini_t) array[count]) ();
```

因此伪造的 fake map 至少不能漏掉下面这几条：

1. `l_next` 要让遍历出来的有效节点数仍然等于 `_ns_nloaded`；
2. `l_real == fake_map`；
3. 目标 Build ID 对应的 `l_init_called` 这一位要是 1；
4. `l_info[26]` 和 `l_info[28]` 分别要指向真实的 `Elf64_Dyn`，其中后者的 `d_val` 至少要是 8；
5. `_dl_sort_maps` 会读写的 `l_idx`、open count、依赖字段以及 fake map 本身的内存，都要能被接受。

旧模板只设置了 `l_info[26]`，却漏掉了随后必然会被解引用的 `l_info[28]`，同时也漏了 `l_real` 和 `l_init_called`，已经把它删掉了。新版生成器要求把所有私有偏移都显式传进去。

### 最终触发点、布局与投递三层

- [`poc_fini_array_sink_2.23_2.43.c`](./poc_fini_array_sink_2.23_2.43.c) 完全不需要猜私有偏移：它在线性的 `main` 里直接修改主程序真实 link_map 对应的两项 `Elf64_Dyn`，再进入 `exit→_dl_fini`。命中后受控回调会调用 `_exit(0)`；没命中则保留 `exit(113)` 这个失败状态，方便判断。它已经在 2.23、精确到小版本的 2.30，以及 2.43 上验证通过。
- 同一个 C 文件末尾还列出了伪造 `link_map` 需要的 `l_real/l_next/l_info[26]/l_info[28]/Elf64_Dyn/fini_array` 中文伪代码；具体私有 bitfield 的偏移仍然必须从附件的 ld.so 里重新提取。
- 原文用的 glibc 2.30 是靠 largebin attack 把堆地址投递过去的。2.30～2.41 之间可以按各自版本的 largebin 分支做适配；2.42 引入的 nextsize 完整性检查封住了这条公开投递路径，但并没有删除加载器本身的最终触发点。

源码里仍然能走到这个最终触发点，不代表旧的利用链就还成立：投递方式、私有结构和控制流终点，都需要按附件 libc/ld 的 Build ID 重新核实。

源码与背景：

- [glibc 2.43 `elf/dl-fini.c`](https://sourceware.org/cgit/glibc/tree/elf/dl-fini.c?h=release/2.43/master)
- [glibc 2.43 `elf/dl-call_fini.c`](https://sourceware.org/cgit/glibc/tree/elf/dl-call_fini.c?h=release/2.43/master)
- [glibc 2.43 私有 `link_map` 扩展](https://sourceware.org/cgit/glibc/tree/include/link.h?h=release/2.43/master)
- [glibc 2.41 `malloc.c`：末代经典 largebin 投递](https://github.com/bminor/glibc/blob/glibc-2.41/malloc/malloc.c)
- [GNU glibc 当前开发分支](https://github.com/bminor/glibc/tree/master)
- [House of all 综述](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/)
- [高版本 heap exploitation](https://roderickchan.github.io/zh-cn/2023-03-01-analysis-of-glibc-heap-exploitation-in-high-version/)
- [Ha1vk 原始 House of Banana（glibc 2.30）](https://www.anquanke.com/post/id/222948)

## PoC

- [`poc_fini_array_sink_2.23_2.43.c`](./poc_fini_array_sink_2.23_2.43.c)：线性展示真实 `exit→_dl_fini` 消费受控 fini_array

可执行部分不猜私有偏移；需要伪造独立 link_map 时，直接按文件末尾的中文伪代码和附件 ld.so 重算。

## Python 离线板子

[`banana.py`](./banana.py) 提供 `build_house_of_banana`，生成 `_dl_fini` 消费 `DT_FINI_ARRAY` 所需的动态项和数组。

### 函数用途

构造 `exit -> _dl_fini` 消费的最终对象：

```text
array = l_addr + l_info[DT_FINI_ARRAY]->d_un.d_ptr
count = l_info[DT_FINI_ARRAYSZ]->d_un.d_val / 8
while (count--) ((fini_t) array[count])();
```

### 对应 PoC

- [`poc_fini_array_sink_2.23_2.43.c`](./poc_fini_array_sink_2.23_2.43.c)。

### 动态项常量

```text
DT_FINI_ARRAY   = 26
DT_FINI_ARRAYSZ = 28
```

每个 `Elf64_Dyn` 是 0x10 字节：

```text
+0x00  d_tag
+0x08  d_un（d_ptr 或 d_val）
```

### 最小使用示例

```python
from banana import build_house_of_banana

writes = build_house_of_banana(
    fini_dyn_addr=0x7fff1000,      # DT_FINI_ARRAY 动态项地址
    fini_size_dyn_addr=0x7fff1010, # DT_FINI_ARRAYSZ 动态项地址
    fini_array_addr=0x500000,      # 受控 fini 数组
    callback_addr=0x401234,        # 数组中被调用的函数
    link_map_base=0x7fff0000,      # 目标 map 的 l_addr
    array_count=1,
)

# 三个 MemoryWrite：
# 1. DT_FINI_ARRAY Dyn
# 2. DT_FINI_ARRAYSZ Dyn
# 3. controlled fini array
for w in writes:
    print(w.label, hex(w.address), w.data.hex())
```

### 参数

| 参数 | 含义 |
|---|---|
| `fini_dyn_addr` | `DT_FINI_ARRAY` 对应的 `Elf64_Dyn` 地址。 |
| `fini_size_dyn_addr` | `DT_FINI_ARRAYSZ` 对应的 `Elf64_Dyn` 地址。 |
| `fini_array_addr` | 进程中长期存活的受控 fini 函数数组地址。 |
| `callback_addr` | 数组中被 `_dl_fini` 调用的函数地址。 |
| `link_map_base` | 目标 map 的 `l_addr`；`d_ptr = fini_array_addr - l_addr`。 |
| `array_count` | 数组元素数量，默认 1；动态项中保存的是字节数 `count * 8`。 |

### 返回对象

返回三个 `MemoryWrite`。`MemoryWrite` 每个成员含义：

| 成员 | 含义 |
|---|---|
| `address` | 要写入的绝对地址。 |
| `data` | 要写入的小端字节串（`bytes`）。 |
| `label` | 该写入的用途标签，用于调试和识别。 |

各写入内容：

```text
1. DT_FINI_ARRAY Dyn（fini_dyn_addr 处，0x10 字节）：
       d_tag = 26
       d_ptr = fini_array_addr - link_map_base

2. DT_FINI_ARRAYSZ Dyn（fini_size_dyn_addr 处，0x10 字节）：
       d_tag = 28
       d_val = array_count * 8

3. controlled fini array（fini_array_addr 处）：
       array_count 个 callback_addr
```

### 调用者必须提供

```text
libc/ld 基址和私有 link_map 布局（Build ID 相关）
能改写目标 map 动态项的原语（AAW / largebin / overlap）
进程能走到 exit，且 fake map 满足 _dl_fini 枚举和 l_init_called
```

### 函数不负责

```text
不生成私有 link_map
不负责命名空间 _ns_loaded / _ns_nloaded
不负责 l_real / l_init_called
不处理 2.42+ 的替代投递原语
```

## 迁移与调试

1. 先确认投递路径和最终触发点在目标 Build ID 上都确实存在。
2. 把占位地址和 add/edit/free 顺序，替换成题目实际给出的能力。
3. 在消费函数处下断点，逐字段核对 size、对齐、safe-linking，以及 FILE/link_map 等私有结构的布局。
