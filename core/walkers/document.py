# -*- coding: utf-8 -*-
"""文档容器遍历器：PDF"""
from ..utils import read_at, warn


def walk_pdf(f, off, size, findings, warnings):
    if read_at(f, off, 4) != b"%PDF":
        return None
    if off == 0:
        tail = read_at(f, max(0, size - 2048), 2048)
        if b"%%EOF" not in tail:
            warn(warnings, "danger", "PDF 未找到 %%EOF 结尾标记（可能被截断或追加了数据）")
            return None
    info = {"type": "PDF 文档", "kind": "container", "offset": off,
            "size": size - off, "brief": "PDF 文档"}
    findings.append(info)
    return size, info
