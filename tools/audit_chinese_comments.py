#!/usr/bin/env python3
"""逐条检查教学 PoC 中是否仍有缺少中文解释的注释。"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path


HAN_RE = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff]")
LATIN_WORD_RE = re.compile(r"[A-Za-z]{2,}")
URL_RE = re.compile(r"^(?:参考(?:链接|资料)?[：:]\s*)?https?://\S+$")


@dataclass(frozen=True)
class Comment:
    path: Path
    line: int
    text: str


def extract_c_comments(path: Path) -> list[Comment]:
    """用一个轻量词法状态机提取 C 注释，避开字符串里的 // 与 /*。"""

    source = path.read_text(encoding="utf-8")
    comments: list[Comment] = []
    index = 0
    line = 1
    length = len(source)

    while index < length:
        char = source[index]

        if char in {'"', "'"}:
            quote = char
            index += 1
            while index < length:
                if source[index] == "\\":
                    index += 2
                    continue
                if source[index] == quote:
                    index += 1
                    break
                if source[index] == "\n":
                    line += 1
                index += 1
            continue

        if source.startswith("//", index):
            start_line = line
            end = source.find("\n", index + 2)
            if end == -1:
                end = length
            comments.append(Comment(path, start_line, source[index:end]))
            index = end
            continue

        if source.startswith("/*", index):
            start = index
            start_line = line
            end = source.find("*/", index + 2)
            if end == -1:
                end = length - 2
            token = source[start : end + 2]
            comments.append(Comment(path, start_line, token))
            line += token.count("\n")
            index = end + 2
            continue

        if char == "\n":
            line += 1
        index += 1

    return comments


def normalized_lines(comment: Comment) -> list[tuple[int, str]]:
    """去除注释定界符，返回每一条可读内容及其真实行号。"""

    raw_lines = comment.text.splitlines() or [comment.text]
    result: list[tuple[int, str]] = []
    for offset, raw in enumerate(raw_lines):
        text = raw.strip()
        if offset == 0:
            if text.startswith("//"):
                text = text[2:].strip()
            elif text.startswith("/*"):
                text = text[2:].strip()
        if offset == len(raw_lines) - 1 and text.endswith("*/"):
            text = text[:-2].strip()
        if text.startswith("*"):
            text = text[1:].strip()
        result.append((comment.line + offset, text))
    return result


def is_non_prose_annotation(text: str) -> bool:
    """放行网址、分隔线和纯公式；这些内容本身没有可翻译的自然语言。"""

    if not text:
        return True
    if URL_RE.fullmatch(text):
        return True
    if not LATIN_WORD_RE.search(text):
        return bool(re.fullmatch(r"[\d\s\W_]+", text))

    # 伪代码常用中文分号，并可能在行尾用 // 标出结构字段名。审计自然语言
    # 时先去掉这两种书写差异，不能把纯表达式误报成英文叙述。
    expression = text.replace("；", ";").split("//", 1)[0].rstrip()

    # 纯 C 表达式或结构字段列表不是英文叙述，但必须具有明显代码符号。
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\s*(?:->|\.|\[|\]|\(|\)|=|==|!=|>=|<=|\+|-|\*|/|\^|&|\||<|>|:|,)\s*[A-Za-z0-9_xX]*)+;?", expression):
        return True
    return False


def find_violations(comment: Comment) -> list[tuple[int, str]]:
    """逐行找出含英文叙述、却完全没有汉字解释的注释。"""

    violations: list[tuple[int, str]] = []
    for line, text in normalized_lines(comment):
        if is_non_prose_annotation(text):
            continue
        if HAN_RE.search(text):
            continue
        violations.append((line, text))
    return violations


def collect_pocs(root: Path) -> list[Path]:
    return sorted(
        path
        for path in root.rglob("poc_*")
        if path.is_file()
        and path.suffix == ".c"
        and "build" not in path.parts
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="审计 PoC 的逐行中文注释")
    parser.add_argument(
        "root",
        nargs="?",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="cheatsheet 根目录，默认取本脚本上一级目录",
    )
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="只显示统计，不逐条打印问题",
    )
    args = parser.parse_args()

    root = args.root.resolve()
    pocs = collect_pocs(root)
    comments: list[Comment] = []
    for path in pocs:
        comments.extend(extract_c_comments(path))

    bad_files: set[Path] = set()
    bad_lines = 0
    for comment in comments:
        for line, text in find_violations(comment):
            bad_files.add(comment.path)
            bad_lines += 1
            if not args.summary_only:
                relative = comment.path.relative_to(root)
                print(f"[FAIL] {relative}:{line}: {text}")

    print(
        f"[INFO] PoC={len(pocs)}，注释块={len(comments)}，"
        f"缺少中文解释的注释行={bad_lines}，涉及文件={len(bad_files)}"
    )
    if bad_lines:
        return 1
    print("[ OK ] 所有 PoC 的自然语言注释均包含中文解释")
    return 0


if __name__ == "__main__":
    sys.exit(main())
