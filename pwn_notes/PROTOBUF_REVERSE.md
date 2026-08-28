# protobuf-c 逆向速查

目标是在没有 `.proto` 时，从二进制里的 protobuf-c descriptor 恢复消息、枚举和嵌套关系，再用真实流量往返验证。descriptor 的 C 布局随 protobuf-c 版本和架构变化；不要只靠一份旧笔记中的固定 dword 偏移。

## 识别 protobuf-c

```bash
readelf -Ws ./chall | rg 'protobuf_c|message_pack|message_unpack'
strings -a ./chall | rg 'protobuf-c|PROTOBUF_C|\.proto|package'
```

常见线索：

- `protobuf_c_message_unpack`、`protobuf_c_message_pack`、`protobuf_c_message_get_packed_size`；
- `ProtobufCMessageDescriptor`、`ProtobufCFieldDescriptor` 相关符号或生成代码命名；
- descriptor magic `0x28aaeef9`；
- 字段名、message 全名、C short name、package name 和 `.proto` 文件名字符串彼此成组。

静态链接和去符号会让函数名消失，此时可从 magic、字符串交叉引用和大量字段 descriptor 数组反查初始化对象。

## 从 message descriptor 开始

以目标二进制实际使用的官方 `protobuf-c.h` 布局为准。概念上，`ProtobufCMessageDescriptor` 会给出：

- magic、全名、短名、C 名、package；
- `sizeof_message`；
- `n_fields` 与 fields 数组；
- 按字段名/字段号查找用的索引；
- message init 回调和保留字段。

恢复步骤：

1. 找到 magic 和相邻名字指针，确认候选 message descriptor。
2. 按目标指针宽度和版本导入结构体，读取 `n_fields` 与 fields 指针。
3. 逐个解析 field descriptor，不要凭肉眼假设数组步长。
4. 用 field 的 `descriptor` 指针递归恢复嵌套 message 或 enum。
5. 依据生成 C struct 的 `offset`/`quantifier_offset` 检查你推断的类型和 repeated/optional 标记。
6. 写出最小 `.proto` 后生成代码，用一条抓到的报文做 unpack→pack 往返验证。

## field descriptor 关键含义

常见字段包括：

| 字段 | 用途 |
|---|---|
| `name` | `.proto` 中的字段名 |
| `id` | wire field number，不是数组下标 |
| `label` | optional/required/repeated 等标签 |
| `type` | int32、string、message、enum 等 protobuf-c 类型 |
| `quantifier_offset` | `has_xxx` 或 repeated 数量字段在生成 C struct 中的偏移 |
| `offset` | 字段数据在生成 C struct 中的偏移 |
| `descriptor` | 子 message/enum descriptor；标量通常不需要 |
| `default_value` | 显式默认值指针 |

proto2、proto3 和不同 protobuf-c 版本对 label、presence 与 flags 的表达会有差异。恢复语法版本时，必须把生成结构体、descriptor flag 和实际 wire 数据一起看。

“`default_value` 非空就是 proto2、为空就是 proto3” 只能当个粗筛：proto2 字段可以没有显式默认值，结构体字段本身也可能在多个生成器版本中一直存在但为 NULL。博客里的这个判断只用来出候选，最后还要靠 label/presence、descriptor flags、生成代码版本和往返测试确认。

## wire type 交叉验证

key 编码为 `(field_number << 3) | wire_type`。常见 wire type：

| wire type | 典型字段 |
|---:|---|
| 0 | varint：int32/int64、uint、sint 编码后的值、bool、enum |
| 1 | 64-bit：fixed64、sfixed64、double |
| 2 | length-delimited：string、bytes、嵌套 message、packed repeated |
| 5 | 32-bit：fixed32、sfixed32、float |

wire type 只能缩小候选类型，例如 type 0 不能区分 int32、bool 与 enum。descriptor 和业务值域才是主证据。

## 最小恢复示例

```proto
syntax = "proto2";

message DeviceMsg {
  required uint32 opcode = 1;
  optional bytes payload = 2;
  repeated uint64 values = 3 [packed = true];
}
```

生成 Python：

```bash
protoc --python_out=. devicemsg.proto
```

生成 protobuf-c 文件通常使用安装了插件的 protoc：

```bash
protoc --c_out=. devicemsg.proto
```

具体命令取决于本机打包方式；有些旧环境提供单独的 `protoc-c` 命令。用 `protoc --version`、`protoc-gen-c --version` 和项目构建脚本确认，不要把命令差异误判为协议差异。

Python 交互示例：

```python
from devicemsg_pb2 import DeviceMsg

msg = DeviceMsg(opcode=1, payload=b"AAAA")
msg.values.extend([0x10, 0x20])
wire = msg.SerializeToString()

check = DeviceMsg()
check.ParseFromString(wire)
assert check.SerializeToString() == wire
```

不要把字段顺序当作语义保证；未知字段也可能被保留或重新编码。测试时比较解析后的语义，同时保留原始报文字节用于定位实现差异。

## 导入生成结构体时

不要直接编辑 `/usr/include/protobuf-c/protobuf-c.h` 再依赖自己事后恢复。更安全的做法是复制目标版本所需 typedef/struct 到题目目录的最小头文件，删除与布局无关的函数声明和宏；必要时先用匹配编译器预处理，再让 IDA 的 Parse C Header 或类型库读取。这样不会污染系统头文件，也能把类型定义和附件版本一起归档。

- protobuf-c 生成的每个 message C struct 通常以 `ProtobufCMessage base` 开头。
- `bytes` 常映射为 `ProtobufCBinaryData`，包含长度和数据指针；不是 NUL 结尾字符串。
- repeated 字段通常有数量字段和元素指针，具体位置由 descriptor offset 给出。
- optional 标量在部分生成形式中配有 `has_field`；optional message 可用空指针表达不存在。
- enum descriptor 与 message descriptor 不同，递归时先看 field type 再解释指针。

[Ltfall 的 protobuf-c/IDA 笔记](https://ltfa1l.top/2023/12/28/system/tricks/tricks/)展示了从 message/field descriptor 恢复 `.proto` 的入口；本页保留它的结构体导入方法，修掉了系统头文件编辑和 syntax-version 单点判断这两处。

## 传输层不要混进 protobuf

protobuf 序列化本身不负责 TCP 消息边界。题目常在外层增加：

- 2/4/8 字节长度；
- opcode、校验和或 magic；
- varint 长度前缀；
- 菜单或 base64/hex 包装。

先从收发函数确认 frame，再把 payload 交给 protobuf 解析。若能解析第一包却从第二包开始错位，优先检查外层长度和粘包，而不是立即修改 `.proto`。

上游结构定义可对照 [protobuf-c 官方头文件](https://github.com/protobuf-c/protobuf-c/blob/master/protobuf-c/protobuf-c.h)。旧文件与本篇的迁移关系见 [`SOURCE_MAP.md`](./SOURCE_MAP.md)。
