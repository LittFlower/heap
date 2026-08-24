#!/usr/bin/env python3
"""检查 Markdown 本地链接，保证在 VS Code 预览中可以直接跳转。"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlparse


LINK_RE = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)")
POC_TOKEN_RE = re.compile(r"`(poc_[A-Za-z0-9._-]+\.c)`")
SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")


def markdown_files(root: Path) -> list[Path]:
    """枚举交付目录中的 Markdown，忽略构建产物。"""

    return sorted(
        path
        for path in root.rglob("*.md")
        if "build" not in path.parts
    )


def destination_path(markdown: Path, raw_destination: str) -> Path | None:
    """把 Markdown 目标解析成本地路径；网络地址和页内锚点返回空值。"""

    destination = raw_destination.strip()

    # 项目当前没有带标题的本地链接；仍兼容 `<路径>` 包裹形式。
    if destination.startswith("<") and destination.endswith(">"):
        destination = destination[1:-1]

    if not destination or destination.startswith("#"):
        return None

    if destination.startswith("file://"):
        return Path(unquote(urlparse(destination).path))

    if SCHEME_RE.match(destination):
        return None

    # 文件后的 #标题 和 ?查询 不参与文件系统定位。
    destination = destination.split("#", 1)[0].split("?", 1)[0]
    destination = unquote(destination)
    if not destination:
        return None

    path = Path(destination)
    if not path.is_absolute():
        path = markdown.parent / path
    return path.resolve()


def line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def main() -> int:
    parser = argparse.ArgumentParser(description="审计 VS Code 可跳转的 Markdown 本地链接")
    parser.add_argument(
        "root",
        nargs="?",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="cheatsheet 根目录，默认取本脚本上一级目录",
    )
    args = parser.parse_args()

    root = args.root.resolve()
    files = markdown_files(root)
    local_links = 0
    failures = 0

    for markdown in files:
        text = markdown.read_text(encoding="utf-8")

        for match in LINK_RE.finditer(text):
            target = destination_path(markdown, match.group(1))
            if target is None:
                continue
            # 绝对路径指向作者本机的离线资料时，不属于交付目录的本地链接。
            # 这类引用保留为 provenance，但不能要求接收者拥有作者的本地路径。
            if target.is_absolute() and not target.is_relative_to(root):
                continue
            local_links += 1
            relative_source = markdown.relative_to(root)
            line = line_number(text, match.start())

            if not target.exists():
                print(
                    f"[FAIL] 本地链接不存在：{relative_source}:{line} -> "
                    f"{match.group(1)}"
                )
                failures += 1
            elif target.is_dir():
                print(
                    f"[FAIL] 链接仍指向目录：{relative_source}:{line} -> "
                    f"{match.group(1)}；请显式链接 README.md"
                )
                failures += 1

        # 真实存在的具体 PoC 文件名如果只放在反引号里，VS Code 预览无法点击。
        # 通配符 poc_* 不匹配本正则，因此仍可作为普通命名约定展示。
        for match in POC_TOKEN_RE.finditer(text):
            poc_name = match.group(1)
            poc_path = markdown.parent / poc_name
            if not poc_path.is_file():
                continue
            expected = f"[`{poc_name}`](./{poc_name})"
            full_start = match.start() - 1
            full_end = match.end() + len(f"](./{poc_name})")
            if full_start < 0 or text[full_start:full_end] != expected:
                relative_source = markdown.relative_to(root)
                line = line_number(text, match.start())
                print(
                    f"[FAIL] PoC 文件名不可点击：{relative_source}:{line}: "
                    f"{poc_name}"
                )
                failures += 1

    print(
        f"[INFO] Markdown={len(files)}，本地文件链接={local_links}，"
        f"跳转问题={failures}"
    )
    if failures:
        return 1
    print("[ OK ] Markdown 本地链接均可在 VS Code 中解析到明确文件")
    return 0


if __name__ == "__main__":
    sys.exit(main())
