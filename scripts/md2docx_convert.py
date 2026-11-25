#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Markdown 转 Word：pandoc + assets/reference.docx 样式集，附两步后处理。

用法:
    python scripts/md2docx_convert.py 结论报告.md -o 报告.docx [--toc]

后处理:
    1) 一级标题中以「附录」「附件」开头的段落改用无编号标题样式（不占章节编号）。
    2) 全部表格统一套用参考文档中的「网格表」样式。

依赖: pandoc（在 PATH）或 pypandoc（pip install pypandoc-binary）；python-docx 不需要。
"""
import argparse
import re
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path
from xml.etree import ElementTree

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
NS = {"w": W}
HERE = Path(__file__).resolve().parent
REFERENCE = HERE.parent / "assets" / "reference.docx"


def pandoc_cmd() -> list[str]:
    exe = shutil.which("pandoc")
    if exe:
        return [exe]
    try:
        import pypandoc
    except ImportError:
        sys.exit("未找到 pandoc：请安装 pandoc 或执行 pip install pypandoc-binary")
    pypandoc.ensure_pandoc_installed()
    return [pypandoc.get_pandoc_path()]


def style_ids_by_name(styles_xml: bytes) -> dict[str, str]:
    result: dict[str, str] = {}
    for style in ElementTree.fromstring(styles_xml).findall(".//w:style", NS):
        name = style.find("w:name", NS)
        if name is not None:
            result[name.attrib[f"{{{W}}}val"]] = style.attrib[f"{{{W}}}styleId"]
    return result


def postprocess(docx_path: Path, reference_path: Path) -> None:
    with zipfile.ZipFile(reference_path) as ref:
        styles = style_ids_by_name(ref.read("word/styles.xml"))
    heading_one = styles.get("heading 1", "Heading1")
    unnumbered = styles.get("标题 1 无编号")
    table_grid = styles.get("网格表")
    with zipfile.ZipFile(docx_path) as source:
        members = {item.filename: source.read(item.filename) for item in source.infolist()}
    document = ElementTree.fromstring(members["word/document.xml"])
    changed = False
    for paragraph in document.findall(".//w:p", NS):
        style = paragraph.find("w:pPr/w:pStyle", NS)
        if style is None:
            continue
        value = style.attrib.get(f"{{{W}}}val", "")
        if unnumbered and value == heading_one:
            text = "".join(t.text or "" for t in paragraph.findall(".//w:t", NS)).strip()
            if text.startswith(("附录", "附件")):
                style.attrib[f"{{{W}}}val"] = unnumbered
                changed = True
        if table_grid and value in {"Table", "Table Caption"}:
            style.attrib[f"{{{W}}}val"] = table_grid
            changed = True
    if table_grid:
        for table in document.findall(".//w:tbl", NS):
            properties = table.find("w:tblPr", NS)
            if properties is None:
                properties = ElementTree.Element(f"{{{W}}}tblPr")
                table.insert(0, properties)
            identifier = properties.find("w:tblStyle", NS)
            if identifier is None:
                identifier = ElementTree.Element(f"{{{W}}}tblStyle")
                properties.insert(0, identifier)
            if identifier.attrib.get(f"{{{W}}}val") != table_grid:
                identifier.attrib[f"{{{W}}}val"] = table_grid
                changed = True
    if changed:
        ElementTree.register_namespace("w", W)
        members["word/document.xml"] = ElementTree.tostring(
            document, encoding="utf-8", xml_declaration=True
        )
        temp = docx_path.with_suffix(".docx.tmp")
        with zipfile.ZipFile(temp, "w", compression=zipfile.ZIP_DEFLATED) as target:
            for name, data in members.items():
                target.writestr(name, data)
        # Windows 下杀软/索引可能瞬时占用目标文件，重试几次。
        for attempt in range(5):
            try:
                temp.replace(docx_path)
                break
            except PermissionError:
                if attempt == 4:
                    raise
                time.sleep(0.3 * (attempt + 1))


def main() -> None:
    parser = argparse.ArgumentParser(description="Markdown 转 Word（安全检测交付物）")
    parser.add_argument("input", help="Markdown 源文件")
    parser.add_argument("-o", "--output", required=True, help="输出 docx 路径")
    parser.add_argument("--toc", action="store_true", help="生成目录域（Word 中按 F9 刷新页码）")
    parser.add_argument("--reference", default=str(REFERENCE), help="参考 docx（样式来源）")
    args = parser.parse_args()

    reference = Path(args.reference)
    if not reference.exists():
        sys.exit(f"参考文档不存在: {reference}")
    output = Path(args.output)
    command = pandoc_cmd() + [
        args.input,
        "-f", "markdown",
        "-t", "docx",
        "--reference-doc", str(reference),
        "-o", str(output),
    ]
    if args.toc:
        command += ["--toc", "--toc-depth=3"]
    subprocess.run(command, check=True)
    postprocess(output, reference)
    print(f"Done: {output}")


if __name__ == "__main__":
    main()
