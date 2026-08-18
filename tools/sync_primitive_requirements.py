#!/usr/bin/env python3
"""把总表中的手法级原语要求同步到各目录 README。"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
MATRIX = ROOT / "PRIMITIVE_REQUIREMENTS_MATRIX.md"
START = "<!-- PRIMITIVE_REQUIREMENTS:START -->"
END = "<!-- PRIMITIVE_REQUIREMENTS:END -->"

ROW_RE = re.compile(
    r"^\| \[(?P<name>[^]]+)\]"
    r"\(\./(?P<directory>[^/)]+)/README\.md\)"
    r" \| (?P<input>.*?)"
    r" \| (?P<invariants>.*?)"
    r" \| (?P<output>.*?)"
    r" \| (?P<boundary>.*?) \|$"
)


@dataclass(frozen=True)
class Requirement:
    name: str
    directory: str
    input_primitive: str
    invariants: str
    output_primitive: str
    boundary: str


def read_requirements(root: Path) -> list[Requirement]:
    """只读取总表中链接到手法目录的五列表格行。"""

    matrix = root / MATRIX.name
    requirements: list[Requirement] = []

    for line in matrix.read_text(encoding="utf-8").splitlines():
        match = ROW_RE.match(line)
        if not match:
            continue
        requirements.append(
            Requirement(
                name=match.group("name"),
                directory=match.group("directory"),
                input_primitive=match.group("input"),
                invariants=match.group("invariants"),
                output_primitive=match.group("output"),
                boundary=match.group("boundary"),
            )
        )

    if len(requirements) != 60:
        raise RuntimeError(
            f"预期从 {matrix.name} 读取 60 个手法，实际读到 {len(requirements)} 个；"
            "请检查表格格式或同步脚本。"
        )

    directories = [item.directory for item in requirements]
    if len(directories) != len(set(directories)):
        raise RuntimeError("总表中存在重复的手法目录。")

    return requirements


def make_block(item: Requirement) -> str:
    """生成 README 中由本脚本维护的统一摘要块。"""

    return f"""{START}
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | {item.input_primitive} |
| 关键环境与不变量 | {item.invariants} |
| 最终输出原语 | {item.output_primitive} |
| 版本边界应如何理解 | {item.boundary} |
{END}"""


def insert_block(readme: str, block: str) -> str:
    """优先放在结论之后；没有结论标题时放在第一个二级标题前。"""

    if START in readme or END in readme:
        if readme.count(START) != 1 or readme.count(END) != 1:
            raise RuntimeError("README 中的原语同步标记不完整或重复。")
        start = readme.index(START)
        end = readme.index(END, start) + len(END)
        return readme[:start].rstrip() + "\n\n" + block + "\n\n" + readme[end:].lstrip()

    conclusion = re.search(r"^## (?:先说|一句话)?结论\s*$", readme, re.MULTILINE)
    if conclusion:
        next_heading = re.search(r"^## ", readme[conclusion.end() :], re.MULTILINE)
        if next_heading:
            insertion = conclusion.end() + next_heading.start()
        else:
            insertion = len(readme)
    else:
        first_heading = re.search(r"^## ", readme, re.MULTILINE)
        insertion = first_heading.start() if first_heading else len(readme)

    return readme[:insertion].rstrip() + "\n\n" + block + "\n\n" + readme[insertion:].lstrip()


def sync_readmes(root: Path = ROOT, check: bool = False) -> int:
    """同步全部 README；检查模式只报告差异，不写文件。"""

    stale: list[Path] = []
    for item in read_requirements(root):
        readme_path = root / item.directory / "README.md"
        if not readme_path.is_file():
            raise RuntimeError(f"总表指向的 README 不存在：{readme_path.relative_to(root)}")

        old_text = readme_path.read_text(encoding="utf-8")
        new_text = insert_block(old_text, make_block(item)).rstrip() + "\n"
        if new_text == old_text:
            continue

        stale.append(readme_path)
        if not check:
            readme_path.write_text(new_text, encoding="utf-8")

    if check and stale:
        for path in stale:
            print(f"[FAIL] 原语摘要未同步：{path.relative_to(root)}", file=sys.stderr)
        print("请运行：python3 tools/sync_primitive_requirements.py", file=sys.stderr)
        return 1

    if check:
        print("[ OK ] 60 个 README 的原语摘要与总表一致")
    else:
        print(f"[ OK ] 已同步 60 个 README；本次改写 {len(stale)} 个")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="把 PRIMITIVE_REQUIREMENTS_MATRIX.md 同步到各手法 README。"
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="只检查 README 是否与总表一致，不修改文件。",
    )
    args = parser.parse_args()

    try:
        return sync_readmes(check=args.check)
    except (OSError, RuntimeError) as error:
        print(f"[FAIL] {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
