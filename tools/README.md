# 验证工具

## run_in_docker.sh

用法：

```bash
./tools/run_in_docker.sh <glibc 版本> <相对根目录的 PoC.c>
```

编译发生在 `gcc:5` x86-64 容器，运行发生在与目标 glibc 对应的 Ubuntu 镜像/精确 loader。映射覆盖 2.23、2.24、2.26～2.43；2.25 没有对应 Ubuntu libc 包，需用 `glibc-aio build 2.25 amd64` 源码构建。

## 为什么需要精确旧包

老 Ubuntu 镜像会继续收到安全更新。例如当前 Ubuntu 18.04 虽显示 glibc 2.27，却可能 backport 2.29 的 tcache double-free key。runner 会优先查找 `build/glibc-exact/<package-id>` 中的首发包。准备脚本覆盖 2.23、2.26～2.30；其中 EOL 的 2.28～2.30 会在 glibc-aio 不可用时回退到 Ubuntu old-releases。

```bash
git clone https://github.com/matrix1001/glibc-all-in-one.git /path/to/glibc-all-in-one
cd /path/to/glibc-all-in-one
pip install -e .
glibc-aio mirror update

cd /path/to/heap_ultimate_cheatsheet
./tools/prepare_exact_libcs.sh /path/to/glibc-all-in-one
```

glibc-all-in-one v2 某些环境在解绝对 loader symlink 时会先报错，但 deb 已下载；脚本随后使用项目自带 legacy extractor 保留正确 symlink。

## check_all.sh

按 `validation_manifest.tsv` 跑代表性可执行 C PoC。部分老 FSOP/mmap PoC 受 ASLR 布局影响，脚本会有限重试，日志保存在 `build/validation/`。

```bash
# 检查每个目录的 README、PoC 中文说明、README 文件引用和动态 manifest
./tools/audit_static.sh
```

## sync_primitive_requirements.py

[`PRIMITIVE_REQUIREMENTS_MATRIX.md`](../PRIMITIVE_REQUIREMENTS_MATRIX.md) 是手法级原语要求的唯一事实源。修改总表后运行：

```bash
python3 tools/sync_primitive_requirements.py
```

脚本会把每个手法的最小输入原语、关键环境与不变量、最终输出原语，以及版本边界解释同步到对应目录的 `README.md`。同步章节由 HTML 标记管理；重复运行不会产生重复内容，也不会覆盖各目录已有的详细分析。

只检查、不改文件：

```bash
python3 tools/sync_primitive_requirements.py --check
```

`audit_static.sh` 已包含这项检查。`generate_readmes.py` 在重建基础 README 后也会自动执行同步，避免生成器擦掉这些章节。

`audit_static.sh` 还会调用 `audit_markdown_links.py`：所有手法间链接必须明确
指向目标 `README.md`，具体 `poc_*.c` 文件必须写成可点击链接，
从而保证 VS Code 的 Markdown 预览可以直接在文档和源码之间跳转。

198 项矩阵已使 141 个 C PoC 均至少在一个对应 glibc 上运行。Husk 的 2.27/2.35/2.37/2.39/2.41 完整 largebin 投递链也已纳入，但其隐藏全局变量偏移仍绑定 README 所列 Build ID。复杂布局和题目迁移步骤统一放在相关 C 文件末尾，用中文注释与伪代码说明。
