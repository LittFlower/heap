#!/usr/bin/env bash
# 检查目录结构、README 引用、manifest 与 PoC 中文说明的一致性。
# 本脚本只读源码，不负责运行不同 glibc；动态回归请用 check_all.sh。

set -euo pipefail

root_dir=$(cd "$(dirname "$0")/.." && pwd)
manifest="$root_dir/tools/validation_manifest.tsv"

fail=0
technique_count=0
c_count=0
manifest_count=0

# 每个顶层手法目录必须有自己的 README。
while IFS= read -r -d '' method_dir; do
  technique_count=$((technique_count + 1))
  if [[ ! -f "$method_dir/README.md" ]]; then
    printf '[FAIL] 缺少 README：%s\n' "${method_dir#"$root_dir/"}" >&2
    fail=1
  fi
done < <(find "$root_dir" -mindepth 1 -maxdepth 1 -type d \
  ! -name build ! -name tools ! -name '.*' -print0)

# Python 消费型板子与同目录测试是正式的离线接口；其余 Python 维护脚本仍应放在 tools/。
# 这里不再禁止手法目录中的 Python，由全量 pytest/compileall 和下方静态检查负责验证。


# 所有 C 教学 PoC 至少要有汉字说明。
while IFS= read -r -d '' source_file; do
  c_count=$((c_count + 1))

  if ! perl -CSDA -ne '$has_han ||= /\p{Han}/; END { exit(!$has_han) }' \
      "$source_file"; then
    printf '[FAIL] PoC 缺少中文说明：%s\n' "${source_file#"$root_dir/"}" >&2
    fail=1
  fi
done < <(find "$root_dir" -path "$root_dir/build" -prune -o \
  -type f -name 'poc_*.c' -print0)

# 进一步逐条检查注释，不能只靠文件头的一段中文蒙混过关。
# 网址、公式和结构字段列表等不可翻译内容由专用脚本合理豁免。
if ! python3 "$root_dir/tools/audit_chinese_comments.py" "$root_dir"; then
  fail=1
fi

# 教学步骤必须写成源码注释，不能重新引入 how2heap 风格的大量 printf。
# 保留的运行结果还必须使用短中文标签；格式说明符表触发器由脚本单独豁免。
if ! python3 "$root_dir/tools/audit_runtime_output.py" "$root_dir"; then
  fail=1
fi

# 正文和教学注释统一使用面向 CTF 选手的直白术语，避免重新引入已经
# 清理过的抽象英文、重复词和中英文替换后残留的错误空格。
if rg -n -i --pcre2 \
    'corrosion transplant|tamper zone|\bconsumer\b|\boversized\b|\bmodern\b|heap leak|最终最终|[\p{Han}] [\p{Han}]' \
    --glob '*.md' --glob 'poc_*.c' "$root_dir"; then
  printf '[FAIL] 文档或 PoC 中出现未清理的抽象术语/错误空格\n' >&2
  fail=1
fi

# VS Code 的 Markdown 预览只有在目标是明确文件时才能稳定跳转。检查所有
# 本地链接真实存在，同时禁止重新引入只指向目录、或只用反引号展示 PoC 的写法。
if ! python3 "$root_dir/tools/audit_markdown_links.py" "$root_dir"; then
  fail=1
fi

# 原语总表是唯一事实源；每个手法 README 中的输入、输出、不变量和版本边界
# 必须与总表逐字一致，避免单独维护后产生结论漂移。
if ! python3 "$root_dir/tools/sync_primitive_requirements.py" --check; then
  fail=1
fi

# 手法 README 中写出的具体 poc_xxx 文件必须真实存在。含通配符的泛称
# 不会被下面的正则提取，避免把 `poc_*.c` 当成文件名。
while IFS= read -r -d '' readme_file; do
  while IFS= read -r poc_name; do
    [[ -z "$poc_name" ]] && continue
    if [[ ! -f "$(dirname "$readme_file")/$poc_name" ]]; then
      printf '[FAIL] README 引用不存在：%s -> %s\n' \
        "${readme_file#"$root_dir/"}" "$poc_name" >&2
      fail=1
    fi
  done < <(perl -ne 'while (/`(poc_[A-Za-z0-9][A-Za-z0-9._-]*)`/g) { print "$1\n" }' \
    "$readme_file" | sort -u)
done < <(find "$root_dir" -mindepth 2 -maxdepth 2 -type f \
  -name README.md ! -path "$root_dir/build/*" -print0)

# 动态验证清单不能引用已重命名或删除的 PoC。
while IFS=$'\t' read -r version source_file mode; do
  [[ -z "$version" || "$version" == \#* ]] && continue
  manifest_count=$((manifest_count + 1))
  if [[ ! -f "$root_dir/$source_file" ]]; then
    printf '[FAIL] manifest 引用不存在：glibc %s -> %s\n' \
      "$version" "$source_file" >&2
    fail=1
  fi
done < "$manifest"

printf '[INFO] 手法目录=%d，C PoC=%d，动态矩阵=%d\n' \
  "$technique_count" "$c_count" "$manifest_count"

if (( fail )); then
  exit 1
fi

printf '[ OK ] 静态目录与文档一致性检查通过\n'
