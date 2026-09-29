# -*- coding: utf-8 -*-
"""可执行/图标/快捷方式遍历器：EXE(PE)、ICO、LNK"""
import os
import struct

from ..utils import read_at, warn
from ..signatures import EXEC_EXTS


def walk_exe(f, off, size, findings, warnings):
    hdr = read_at(f, off, 64)
    if len(hdr) < 64 or hdr[:2] != b"MZ":
        return None
    try:
        pe = struct.unpack("<I", hdr[0x3C:0x40])[0]
        if pe <= 0 or pe > 0x10000000 or off + pe + 4 > size:
            return None
        if read_at(f, off + pe, 4) != b"PE\x00\x00":
            return None
    except Exception:
        return None
    info = {"type": "EXE 可执行 (PE)", "kind": "container", "offset": off,
            "size": min(size, off + 0x400) - off, "brief": "Windows PE 可执行程序"}
    findings.append(info)
    return min(size, off + 0x400), info  # 只认领头部，后段留给其他扫描


def walk_ico(f, off, size, findings, warnings):
    hdr = read_at(f, off, 6)
    if len(hdr) < 6:
        return None
    _res, typ, cnt = struct.unpack("<HHH", hdr)
    if typ != 1 or not (1 <= cnt <= 64):
        return None
    # 按目录表精确计算总体积：6 + 16*cnt + 各图像资源长度
    data = read_at(f, off, 6 + 16 * cnt)
    if len(data) < 6 + 16 * cnt:
        return None
    total = 6 + 16 * cnt
    ok = True
    for i in range(cnt):
        base = 6 + 16 * i
        res_size = struct.unpack("<I", data[base + 8:base + 12])[0]
        total += res_size
    if total > size:  # 目录声明超出文件 → 结构可疑
        ok = False
        total = size
    info = {"type": "ICO 图标", "kind": "container", "offset": off,
            "size": total, "brief": f"ICO 图标 · {cnt} 帧"
            + ("" if ok else " · 目录声明超出文件")}
    findings.append(info)
    return off + total, info


def walk_lnk(f, off, size, findings, warnings):
    """Windows 快捷方式：解析 LinkInfo 提取 LocalBasePath 指向的目标"""
    hdr = read_at(f, off, 0x4C)
    if len(hdr) < 0x4C or struct.unpack("<I", hdr[:4])[0] < 0x4C:
        return None
    flags = struct.unpack("<I", hdr[20:24])[0]
    target = None
    pos = off + 0x4C
    if flags & 1:  # LinkTargetIDList
        f.seek(pos)
        raw2 = f.read(2)
        if len(raw2) < 2:
            return None
        idlist_size = struct.unpack("<H", raw2)[0]
        pos += 2 + idlist_size
    if flags & 2:  # LinkInfo
        f.seek(pos)
        li_size_raw = f.read(4)
        if len(li_size_raw) < 4:
            return None
        li_size = struct.unpack("<I", li_size_raw)[0]
        li = read_at(f, pos, min(li_size, 8192))
        if len(li) >= 0x1C:
            lbpo = struct.unpack("<I", li[16:20])[0]  # LocalBasePathOffset
            if 4 <= lbpo < len(li):
                raw = li[lbpo:].split(b"\x00")[0]
                for enc in ("gbk", "cp437"):
                    try:
                        target = raw.decode(enc)
                        break
                    except UnicodeDecodeError:
                        continue
    if target:
        if not os.path.exists(target):
            warn(warnings, "danger",
                 f"快捷方式指向的目标不存在（{target}）→ 失效快捷方式")
        elif target.lower().endswith(EXEC_EXTS):
            warn(warnings, "warn",
                 f"快捷方式直接指向可执行文件：{os.path.basename(target)}，来源不明时慎双击")
    brief = "LNK 快捷方式" + (f" → {os.path.basename(target)}" if target else "（未解析到目标）")
    info = {"type": "LNK 快捷方式", "kind": "container", "offset": off,
            "size": size - off, "brief": brief, "target": target}
    findings.append(info)
    return size, info
