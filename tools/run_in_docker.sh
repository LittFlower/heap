#!/usr/bin/env bash
# 在 x86-64 Docker 中编译，并用指定 Ubuntu/glibc 运行一个 PoC。
# 用较老的 gcc:5 构建可避免宿主启动文件要求 GLIBC_2.34，生成物能向前运行。

set -euo pipefail

if (( $# != 2 )); then
  echo "用法: $0 <glibc版本> <相对根目录的poc.c>" >&2
  exit 2
fi

version=$1
source_file=$2
root_dir=$(cd "$(dirname "$0")/.." && pwd)

case "$version" in
  2.23) image=ubuntu:16.04 ;;
  2.24) image=ubuntu:16.10 ;;
  2.26) image=ubuntu:17.10 ;;
  2.27) image=ubuntu:18.04 ;;
  2.28) image=ubuntu:18.10 ;;
  2.29) image=ubuntu:19.04 ;;
  2.30) image=ubuntu:19.10 ;;
  2.31) image=ubuntu:20.04 ;;
  2.32) image=ubuntu:20.10 ;;
  2.33) image=ubuntu:21.04 ;;
  2.34) image=ubuntu:21.10 ;;
  2.35) image=ubuntu:22.04 ;;
  2.36) image=ubuntu:22.10 ;;
  2.37) image=ubuntu:23.04 ;;
  2.38) image=ubuntu:23.10 ;;
  2.39) image=ubuntu:24.04 ;;
  2.40) image=ubuntu:24.10 ;;
  2.41) image=ubuntu:25.04 ;;
  2.42) image=ubuntu:25.10 ;;
  2.43) image=ubuntu:26.04 ;;
  *)
    echo "没有 $version 的运行时映射；支持 2.23, 2.24, 2.26～2.43（2.25 需自行源码构建）。" >&2
    exit 2
    ;;
esac

# Ubuntu 的老镜像标签会随安全更新而变化。例如当前 ubuntu:18.04 已把
# tcache double-free key 回移到标称 2.27，而上游/首发 2.27 没有。若已按
# README 用 glibc-all-in-one 准备首发包，则优先用精确 loader 验证边界。
exact_root=${HEAP_GLIBC_ROOT:-$root_dir/build/glibc-exact}
exact_id=
case "$version" in
  2.23) exact_id=2.23-0ubuntu3_amd64 ;;
  2.26) exact_id=2.26-0ubuntu2_amd64 ;;
  2.27) exact_id=2.27-3ubuntu1_amd64 ;;
  2.28) exact_id=2.28-0ubuntu1_amd64 ;;
  2.29) exact_id=2.29-0ubuntu2_amd64 ;;
  2.30) exact_id=2.30-0ubuntu2_amd64 ;;
esac

if [[ ! -f "$root_dir/$source_file" ]]; then
  echo "源码不存在: $root_dir/$source_file" >&2
  exit 2
fi

mkdir -p "$root_dir/build"
binary="build/$(printf '%s__%s' "$version" "$source_file" | tr '/.' '__')"

docker --context colima run --rm --platform linux/amd64 \
  -v "$root_dir:/work" -w /work gcc:5 \
  gcc -std=gnu99 -O0 -g -fno-omit-frame-pointer -Wno-unused-result \
      -Wno-free-nonheap-object "$source_file" -ldl -o "$binary"

if [[ -n "$exact_id" && -x "$exact_root/$exact_id/ld-${version}.so" ]]; then
  echo "[+] 目标运行时: 精确包 ${exact_id}（glibc-all-in-one）"
  docker --context colima run --rm --platform linux/amd64 \
    -v "$root_dir:/work:ro" -w /work ubuntu:24.04 \
    sh -c "LIBC_FATAL_STDERR_=1 '/work/${exact_root#$root_dir/}/$exact_id/ld-${version}.so' --library-path '/work/${exact_root#$root_dir/}/$exact_id' './$binary' </dev/null"
else
  actual=$(docker --context colima run --rm --platform linux/amd64 "$image" \
    sh -c "ldd --version 2>&1 | head -n 1")
  echo "[+] 目标运行时: $actual"
  docker --context colima run --rm --platform linux/amd64 \
    -v "$root_dir:/work:ro" -w /work "$image" \
    sh -c "LIBC_FATAL_STDERR_=1 './$binary' </dev/null"
fi
