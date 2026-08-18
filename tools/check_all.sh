#!/usr/bin/env bash
# 回归清单中的“代表版本”。完整输出写到 build/validation/*.log。

set -euo pipefail
root_dir=$(cd "$(dirname "$0")/.." && pwd)
runner="$root_dir/tools/run_in_docker.sh"
manifest="$root_dir/tools/validation_manifest.tsv"
log_dir="$root_dir/build/validation"
mkdir -p "$log_dir"

fail=0
while IFS=$'\t' read -r version source_file mode; do
  [[ -z "$version" || "$version" == \#* ]] && continue
  log="$log_dir/${version}__${source_file//\//__}.log"
  printf '[RUN] glibc %-4s %s\n' "$version" "$source_file"
  ok=0
  # 少数旧 FSOP/mmap PoC 受 ASLR 映射低位影响；与 how2heap CI 一样最多
  # 重试 20 次。确定性 PoC 通常第一轮即通过。
  for attempt in $(seq 1 20); do
    if "$runner" "$version" "$source_file" >"$log" 2>&1; then
      ok=1
      break
    fi
  done
  if (( ok )); then
    printf '[ OK] %s\n' "$source_file"
  elif [[ "$mode" == "flaky" ]]; then
    printf '[WARN] ASLR/映射相关 PoC 本轮失败，见 %s\n' "$log"
  else
    printf '[FAIL] %s，见 %s\n' "$source_file" "$log" >&2
    fail=1
  fi
done < "$manifest"

exit "$fail"
