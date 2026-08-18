#!/usr/bin/env bash
# 下载并提取用于历史边界验证的 glibc 首发 Ubuntu 包。
set -euo pipefail

if (( $# != 1 )); then
  echo "用法: $0 /path/to/glibc-all-in-one" >&2
  exit 2
fi

aio_dir=$(cd "$1" && pwd)
root_dir=$(cd "$(dirname "$0")/.." && pwd)
out_dir="$root_dir/build/glibc-exact"
packages=(
  2.23-0ubuntu3_amd64
  2.26-0ubuntu2_amd64
  2.27-3ubuntu1_amd64
  2.28-0ubuntu1_amd64
  2.29-0ubuntu2_amd64
  2.30-0ubuntu2_amd64
)

if [[ ! -x "$aio_dir/legacy/extract" ]]; then
  echo "找不到 $aio_dir/legacy/extract；请传入 glibc-all-in-one 仓库。" >&2
  exit 2
fi

mkdir -p "$out_dir"
for package_id in "${packages[@]}"; do
  version=${package_id%%-*}
  target="$out_dir/$package_id"
  if [[ -x "$target/ld-$version.so" ]]; then
    echo "[=] 已存在 $package_id"
    continue
  fi

  deb="$aio_dir/debs/libc6_${package_id}.deb"
  if [[ ! -f "$deb" ]]; then
    (cd "$aio_dir" && glibc-aio download "$package_id" --no-dbg --keep-deb) || true
  fi
  # 2.28～2.30 等 EOL Ubuntu 包通常只在 old-releases；即使宿主没有
  # 安装 glibc-aio CLI，也保留一个只下载 libc6 deb 的确定性 fallback。
  if [[ ! -f "$deb" ]]; then
    mkdir -p "$aio_dir/debs"
    curl -fL "https://old-releases.ubuntu.com/ubuntu/pool/main/g/glibc/libc6_${package_id}.deb" \
      -o "$deb" || true
  fi
  if [[ ! -f "$deb" ]]; then
    echo "下载失败：$deb 不存在" >&2
    exit 1
  fi

  mkdir -p "$target"
  "$aio_dir/legacy/extract" "$deb" "$target"
  test -x "$target/ld-$version.so"
  echo "[+] 已准备 $package_id"
done
