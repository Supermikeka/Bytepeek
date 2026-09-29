# -*- coding: utf-8 -*-
"""多媒体/图片容器遍历器：MP4(ISO-BMFF)、RIFF、PNG、JPEG、GIF"""
import struct

from ..utils import read_at, warn, tick, fmt_size


def walk_mp4(f, off, size, findings, warnings):
    """MP4/ISO-BMFF：顶层 box 链 + moov 索引覆盖范围，按 ftyp 主品牌细分类型"""
    if off >= 4:
        box_off = off - 4
        hdr8 = read_at(f, box_off, 8)
    else:
        box_off = off
        hdr8 = read_at(f, off, 8)
    if len(hdr8) < 8 or hdr8[4:8] != b"ftyp":
        return None
    pos = box_off
    boxes = []
    guard = 0
    while pos + 8 <= size and guard < 100000:
        f.seek(pos)
        hdr = f.read(8)
        if len(hdr) < 8:
            break
        sz, typ = struct.unpack(">I4s", hdr)
        hl = 8
        if sz == 1:
            sz = struct.unpack(">Q", f.read(8))[0]
            hl = 16
        elif sz == 0:
            sz = size - pos
        typ = typ.decode("latin1").strip()
        if sz < hl or pos + sz > size:
            break
        boxes.append((typ, pos, sz))
        tick(min(pos + sz, size), size)
        pos += sz
        guard += 1
        # moov 之后遇到无法解析的区域就停，交给主循环继续识别
        if typ == "moov":
            break
    if not boxes:
        return None
    if not any(t in ("ftyp", "moov", "mdat") for t, _, _ in boxes):
        return None
    end = pos

    # 按 ftyp 主品牌细分类型（先算类型名，moov 告警要用）
    brand = read_at(f, box_off + 8, 4) if end - box_off >= 16 else b""
    brand_names = {b"qt  ": "MOV 视频", b"M4A ": "M4A 音频", b"M4B ": "M4B 有声书",
                   b"heic": "HEIC 图片", b"heix": "HEIC 图片", b"mif1": "HEIF 图片",
                   b"hevc": "HEIC 图片", b"avif": "AVIF 图片", b"avis": "AVIF 视频",
                   b"3gp4": "3GP 视频", b"3gp5": "3GP 视频"}
    type_name = brand_names.get(brand, "MP4 视频")

    moov = next((b for b in boxes if b[0] == "moov"), None)
    indexed_max = 0
    duration_s = None
    if moov:
        _, mo, ms = moov
        # 递归找 mvhd / stco / co64
        stack = [(mo + 8, mo + ms)]
        while stack:
            a, b = stack.pop()
            p = a
            while p + 8 <= b:
                f.seek(p)
                h = f.read(8)
                if len(h) < 8:
                    break
                s, t = struct.unpack(">I4s", h)
                if s == 1:
                    s = struct.unpack(">Q", f.read(8))[0]
                if s < 8 or p + s > b:
                    break
                t = t.decode("latin1")
                if t == "mvhd":
                    f.seek(p + 8)
                    ver = f.read(1)[0]
                    f.seek(p + 8 + 4 + (8 if ver == 0 else 16) + 4)
                    ts, dur = struct.unpack(">II", f.read(8)) if ver == 0 else struct.unpack(">QQ", f.read(16))
                    if ts:
                        duration_s = dur / ts
                elif t in ("stco", "co64"):
                    f.seek(p + 12)
                    n = struct.unpack(">I", f.read(4))[0]
                    step = 4 if t == "stco" else 8
                    fmt = ">I" if t == "stco" else ">Q"
                    for _ in range(min(n, 1000000)):
                        v = struct.unpack(fmt, f.read(step))[0]
                        if v > indexed_max:
                            indexed_max = v
                elif t in ("trak", "mdia", "minf", "stbl", "edts"):
                    stack.append((p + 8, p + s))
                p += s

    has_moov = moov is not None
    if not has_moov and type_name == "MP4 视频":
        warn(warnings, "danger", "MP4 缺少 moov 索引 → 大概率无法直接播放（如流式录制中断）")
    info = {
        "type": type_name,
        "kind": "container",
        "offset": box_off, "size": end - box_off,
        "brief": (f"{type_name}"
                  + (f" · 时长 {duration_s:.0f}s" if duration_s else "")),
        "boxes": [t for t, _, _ in boxes],
        "duration_s": duration_s,
        "indexed_max": indexed_max,
    }
    findings.append(info)
    return end, info


def walk_riff(f, off, size, findings, warnings):
    hdr = read_at(f, off, 12)
    if len(hdr) < 12 or hdr[:4] != b"RIFF":
        return None
    form = hdr[8:12]
    names = {b"WAVE": "WAV 音频", b"AVI ": "AVI 视频", b"WEBP": "WebP 图片", b"ACON": "ANI 动画"}
    ftype = names.get(form, "RIFF 容器")
    declared = struct.unpack("<I", hdr[4:8])[0]
    if declared > size - off:
        if off == 0:
            warn(warnings, "danger",
                 f"RIFF 声明长度 {fmt_size(declared)} 超出文件实际大小 → 文件被截断/下载不完整")
            end = size
        else:
            return None  # 嵌入位置声明的长度越界 → 判为误报，不认领
    else:
        end = min(size, off + 8 + declared)
        if off == 0 and size - end > 1024:
            warn(warnings, "warn",
                 f"RIFF 数据结束后还有 {fmt_size(size - end)} 附加数据（疑似拼接了其他文件）")
    info = {"type": ftype, "kind": "container", "offset": off,
            "size": end - off,
            "brief": f"{ftype}"}
    findings.append(info)
    return end, info


def walk_png(f, off, size, findings, warnings):
    if off + 8 > size or read_at(f, off, 8) != b"\x89PNG\r\n\x1a\n":
        return None
    pos = off + 8
    end = None
    while pos + 8 <= size:
        f.seek(pos)
        h = f.read(8)
        ln = struct.unpack(">I", h[:4])[0]
        typ = h[4:8].decode("latin1", "replace")
        pos += 12 + ln
        if typ == "IEND":
            end = pos
            break
        if ln > size:
            break
    if end is None:
        return None
    info = {"type": "PNG 图片", "kind": "container", "offset": off,
            "size": end - off, "brief": "PNG 图片"}
    findings.append(info)
    if end < size and off == 0:   # 仅当 PNG 是文件主体时才提示追加数据
        warn(warnings, "warn",
             f"PNG 数据结束后还有 {fmt_size(size - end)} 附加数据（疑似隐藏/拼接了其他文件）")
    return end, info


def walk_jpeg(f, off, size, findings, warnings):
    if read_at(f, off, 3) != b"\xff\xd8\xff":
        return None
    tail = read_at(f, max(0, size - 64), 64)
    if b"\xff\xd9" not in tail:
        if off == 0:
            warn(warnings, "danger",
                 "JPEG 未找到 EOI 结尾标记(FF D9) → 文件可能被截断（缩略图/预览图常这样，不一定是坏事）")
    elif off == 0:
        idx = (size - len(tail)) + tail.rfind(b"\xff\xd9") + 2
        trailing = read_at(f, idx, min(4096, size - idx)) if idx < size else b""
        if trailing and trailing.strip(b"\x00"):
            warn(warnings, "warn",
                 f"JPEG EOI 之后还有 {fmt_size(size - idx)} 非零数据（疑似追加/隐藏了其他文件）")
    info = {"type": "JPEG 图片", "kind": "container", "offset": off,
            "size": size - off, "brief": "JPEG 图片"}
    findings.append(info)
    return size, info


def walk_gif(f, off, size, findings, warnings):
    hdr = read_at(f, off, 6)
    if hdr not in (b"GIF87a", b"GIF89a"):
        return None
    if off == 0 and size >= 1 and read_at(f, size - 1, 1) != b"\x3b":
        warn(warnings, "warn",
             "GIF 缺少结尾标记(0x3B) → 可能被截断或追加了数据")
    info = {"type": "GIF 动图", "kind": "container", "offset": off,
            "size": size - off, "brief": "GIF 动图"}
    findings.append(info)
    return size, info
