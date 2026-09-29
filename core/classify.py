# -*- coding: utf-8 -*-
"""分类与嗅探：签名搜索、未知区分类（熵/填充）、签名计数、纯文本嗅探"""
import json
from collections import Counter

from .utils import read_at, fmt_size, entropy, OVERLAP
from .signatures import SIGNATURES


def find_next_sig(f, pos, size, progress=None):
    sigs = [(s[2], s[0]) for s in SIGNATURES]
    base = pos
    WIN = 256 * 1024          # 小窗自适应：命中密集时避免反复读大块
    prev = b""
    while base < size:
        f.seek(base)
        data = f.read(WIN + OVERLAP)
        if not data:
            return None
        buf = prev + data
        buf_base = base - len(prev)
        best = None
        for magic, name in sigs:
            i = buf.find(magic)
            if i != -1:
                abs_off = buf_base + i
                if name == "MP4":
                    if abs_off < 4:
                        continue
                    abs_off -= 4  # ftyp 前面还有 4 字节 box size
                if name == "EXE" and abs_off % 512 != 0:
                    continue  # PE 要求节对齐，过滤误报
                if best is None or abs_off < best[0]:
                    best = (abs_off, name)
        if best:
            return best
        prev = data[-OVERLAP:]
        base += WIN
        if progress:
            progress(min(base, size), size)
    return None


def classify_gap(f, a, b, findings):
    n = b - a
    if n <= 0:
        return None
    samples = []
    for off in (a, (a + b) // 2, max(a, b - 262144)):
        samples.append(read_at(f, off, min(262144, b - off)))
    blob = b"".join(samples)
    if not blob:
        return None
    zero_ratio = blob.count(0) / len(blob)
    ent = entropy(blob[:262144])
    common_byte, common_cnt = Counter(blob).most_common(1)[0]
    if zero_ratio > 0.995:
        kind, label = "padding", "全零填充"
    elif common_cnt / len(blob) > 0.99:
        kind, label = "padding", f"常量填充(0x{common_byte:02X})"
    elif ent >= 7.0:
        kind, label = "unknown", "高熵数据（压缩/加密？）"
    elif ent >= 5.0:
        kind, label = "unknown", "中熵未知数据"
    else:
        kind, label = "unknown", "低熵未知数据"
    seg = {"start": a, "end": b, "kind": kind, "label": f"{label} {fmt_size(n)}"}
    if n >= 1024 * 1024 and kind == "padding":
        findings.append({"type": "灌水填充", "kind": "padding",
                         "offset": a, "size": n,
                         "brief": f"全零填充 {fmt_size(n)}（虚增体积，无真实内容）"})
    return seg


def count_sigs(f, pos, size, limit=512 * 1024 * 1024):
    """聚合模式：统计区域内各签名出现次数（不再逐个解析）"""
    end = min(size, pos + limit)
    sigs = [(s[2], s[0]) for s in SIGNATURES if s[0] not in ("EXE", "ICO", "MP4")]
    counts = Counter()
    base = pos
    prev = b""
    while base < end:
        f.seek(base)
        data = f.read(1024 * 1024 + OVERLAP)
        if not data:
            break
        buf = prev + data
        for magic, name in sigs:
            i = buf.find(magic)
            n = 0
            while i != -1 and n < 5000:
                counts[name] += 1
                n += 1
                i = buf.find(magic, i + len(magic))
        prev = data[-OVERLAP:]
        base += 1024 * 1024
    return counts


def sniff_text_path(path, size):
    """无魔数文件的文本嗅探：txt/json/xml/html/py/bat/url 等"""
    try:
        with open(path, "rb") as f:
            head = f.read(min(8192, size))
    except OSError:
        return None
    if not head or b"\x00" in head:
        return None
    text = None
    for enc in ("utf-8-sig", "utf-8", "gbk"):
        try:
            text = head.decode(enc)
            break
        except (UnicodeDecodeError, ValueError):
            continue
    if text is None:
        return None
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    if len(text) and printable / len(text) < 0.98:
        return None
    t = text.lstrip()
    low = t[:200].lower()
    if low.startswith("[internetshortcut]"):
        return "URL 快捷方式"
    if low.startswith("<!doctype html") or low.startswith("<html"):
        return "HTML 网页"
    if low.startswith("<?xml") or low.startswith("<svg"):
        return "XML 文档"
    if t.startswith(("{", "[")):
        try:
            json.loads(head.decode("utf-8-sig"))
            return "JSON 数据"
        except Exception:
            return "配置/文本"
    if t.startswith("#!"):
        return "脚本文件"
    return "纯文本/代码"
