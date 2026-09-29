# -*- coding: utf-8 -*-
"""字体遍历器：TTF/OTF"""
import struct

from ..utils import read_at


def walk_ttf(f, off, size, findings, warnings):
    """TTF/OTF：校验 numTables 合理性后再认领目录区"""
    hdr = read_at(f, off, 12)
    if len(hdr) < 12:
        return None
    num_tables = struct.unpack(">H", hdr[4:6])[0]
    if not (1 <= num_tables <= 2000):
        return None
    claim = min(size - off, 12 + 16 * num_tables)
    ttype = "OTF 字体" if read_at(f, off, 4) == b"OTTO" else "TTF 字体"
    info = {"type": ttype, "kind": "container", "offset": off,
            "size": claim, "brief": f"{ttype} · {num_tables} 张表"}
    findings.append(info)
    return off + claim, info
