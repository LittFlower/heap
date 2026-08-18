#!/usr/bin/env python3
"""检查 C PoC 的直接输出是否只保留简短中文状态或必要触发器。"""

from __future__ import annotations

import re
import sys
from pathlib import Path


CALL_RE = re.compile(r"(?m)^[ \t]*(printf|fprintf|puts)[ \t]*\(")
STRING_RE = re.compile(r'"((?:\\.|[^"\\])*)"', re.S)
HAN_RE = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff]")
STATUS_RE = re.compile(r"\[(?:\+|-|i)\]")
TRIGGERS = {"%X", "%Q"}
MAX_STATUS_LENGTH = 40


def statement_end(source: str, start: int) -> int:
    """从输出调用开头扫描到分号，避开字符串、字符常量和注释。"""

    index = source.find("(", start)
    depth = 0
    quote: str | None = None
    escaped = False
    line_comment = False
    block_comment = False

    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""

        if line_comment:
            if char == "\n":
                line_comment = False
        elif block_comment:
            if char == "*" and following == "/":
                block_comment = False
                index += 1
        elif quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        elif char == "/" and following == "/":
            line_comment = True
            index += 1
        elif char == "/" and following == "*":
            block_comment = True
            index += 1
        elif char in {'"', "'"}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == ";" and depth == 0:
            return index + 1

        index += 1

    raise ValueError("输出调用缺少语句结尾")


def visible_text(statement: str) -> str:
    """拼接相邻字符串，并去掉只影响显示的常见转义。"""

    text = "".join(STRING_RE.findall(statement))
    return text.replace(r"\n", "").replace(r"\t", "")


def main() -> int:
    root = (
        Path(sys.argv[1]).resolve()
        if len(sys.argv) > 1
        else Path(__file__).resolve().parent.parent
    )

    status_count = 0
    trigger_count = 0
    longest = 0
    failures = 0

    for path in sorted(root.rglob("poc_*.c")):
        if "build" in path.parts:
            continue
        source = path.read_text(encoding="utf-8")
        for match in CALL_RE.finditer(source):
            line = source.count("\n", 0, match.start()) + 1
            relative = path.relative_to(root)
            try:
                end = statement_end(source, match.start())
            except ValueError as error:
                print(f"[FAIL] {relative}:{line}: {error}")
                failures += 1
                continue

            text = visible_text(source[match.start() : end])
            if text in TRIGGERS:
                trigger_count += 1
                continue

            status_count += 1
            longest = max(longest, len(text))
            if not STATUS_RE.search(text):
                print(f"[FAIL] {relative}:{line}: 输出缺少状态标签：{text}")
                failures += 1
            if not HAN_RE.search(text):
                print(f"[FAIL] {relative}:{line}: 状态说明缺少中文：{text}")
                failures += 1
            if len(text) > MAX_STATUS_LENGTH:
                print(
                    f"[FAIL] {relative}:{line}: 状态说明过长 "
                    f"({len(text)}>{MAX_STATUS_LENGTH})：{text}"
                )
                failures += 1

    print(
        f"[INFO] C PoC 状态输出={status_count}，利用触发器={trigger_count}，"
        f"最长状态={longest} 字符"
    )
    if failures:
        return 1
    print("[ OK ] 运行时输出均为简短中文标签或必要触发器")
    return 0


if __name__ == "__main__":
    sys.exit(main())
