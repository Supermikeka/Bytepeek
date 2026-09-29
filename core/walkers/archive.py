# -*- coding: utf-8 -*-
"""压缩类容器遍历器：ZIP（残缺可恢复）与 GZIP"""
import os
import struct
import zlib

from ..utils import read_at, warn, tick, fmt_size, CHUNK, MAX_SEARCH
from ..signatures import EXEC_EXTS


def walk_zip(f, off, size, findings, warnings, deep=False):
    """ZIP：优先标准解析，中央目录缺失时按本地头链走（残缺可救）"""
    if read_at(f, off, 4) != b"PK\x03\x04":
        return None
    entries = []
    pos = off
    truncated = False
    guard = 0
    while pos is not None and pos < size - 30 and guard < 500000:
        guard += 1
        f.seek(pos)
        if f.read(4) != b"PK\x03\x04":
            # 搜索下一个本地头（最多 MAX_SEARCH）
            end = min(size, pos + MAX_SEARCH)
            found = None
            base = pos
            while base < end:
                n = min(CHUNK, end - base)
                if n <= 8:      # 尾窗不足以容纳一个头，直接放弃
                    break
                f.seek(base)
                win = f.read(n)
                i = win.find(b"PK\x03\x04")
                if i != -1:
                    found = base + i
                    break
                base += max(1, len(win) - 4)
            if found is None:
                truncated = pos < size  # 还有数据但没有新头 → 中断
                break
            pos = found
            continue
        fixed = f.read(26)
        if len(fixed) < 26:
            break
        (_ver, flags, method, _mt, _md, crc,
         csize, usize, nlen, elen) = struct.unpack("<HHHHHIIIHH", fixed)
        if nlen == 0 or nlen > 4096 or method > 99:   # 字段不合理 → 大概率是伪头
            truncated = pos < size
            break
        name_raw = f.read(nlen)
        try:
            name = name_raw.decode("gbk")
        except UnicodeDecodeError:
            try:
                name = name_raw.decode("utf-8")
            except UnicodeDecodeError:
                name = name_raw.decode("cp437", "replace")
        printable = sum(1 for c in name if c.isprintable() or c in "\\/ ")
        if printable / max(len(name), 1) < 0.85:      # 文件名乱码率高 → 伪头
            truncated = pos < size
            break
        data_off = pos + 30 + nlen + elen
        is_dir = name.endswith("/") and csize == 0 and usize == 0
        entries.append({"name": name, "method": method, "crc": crc, "flags": flags,
                        "csize": csize, "usize": usize, "off": pos,
                        "data_off": data_off, "dir": is_dir})
        tick(min(data_off + (csize or 0), size), size)
        if is_dir:
            pos = data_off
        elif csize > 0 and not (flags & 0x08):
            pos = data_off + csize
        else:
            nxt = data_off + 1
            f.seek(nxt)
            win = f.read(min(CHUNK, size - nxt))
            i = win.find(b"PK\x03\x04")
            pos = nxt + i if i != -1 else None

    if not entries:
        return None
    last = entries[-1]
    data_end = min(size, last["data_off"] + (last["csize"] or 0))

    # 中央目录/EOCD 检测
    tail = read_at(f, max(0, size - 70000), 70000)
    eocd_idx = tail.rfind(b"PK\x05\x06")
    cd_ok = eocd_idx != -1
    if not cd_ok:
        warn(warnings, "danger",
             "ZIP 中央目录/结束记录缺失 → 常规解压软件打不开，但本地头链完整，数据可按头恢复")
    if truncated and cd_ok:
        truncated = False  # 链条虽没走到 CD，但 CD 完好 → 结构完整
    if truncated:
        warn(warnings, "warn", "ZIP 条目链在数据区中断（疑似被切断/截尾）")

    # 加密条目：只进明细，不拉警告（安装器内嵌 zip 常加密，属常态）
    encrypted = any(e["flags"] & 1 for e in entries)

    # 内嵌可执行文件：是否告警由主流程按宿主语境决定
    exec_names = [os.path.basename(e["name"]) for e in entries
                  if e["name"].lower().endswith(EXEC_EXTS)]

    # 完整 zip 应把中央目录+EOCD+注释一并认领
    consumed_end = data_end
    if cd_ok:
        cd_size = struct.unpack("<I", tail[eocd_idx + 12:eocd_idx + 16])[0]
        cd_off = struct.unpack("<I", tail[eocd_idx + 16:eocd_idx + 20])[0]
        clen = struct.unpack("<H", tail[eocd_idx + 20:eocd_idx + 22])[0]
        # EOCD 声明的目录位置与数据区严重不符 → 元数据可疑
        if not (data_end - 65536 <= off + cd_off <= data_end + 65536):
            warn(warnings, "warn",
                 f"EOCD 声明的目录偏移({off + cd_off:,})与数据区末端({data_end:,})不符 → 中央目录位置可疑")
        end_try = off + cd_off + cd_size + 22 + clen
        if data_end <= end_try <= size:
            consumed_end = end_try
        else:
            consumed_end = size

    # 识别 zip 内常见"马甲"格式
    names = [e["name"] for e in entries]
    lower = [n.lower() for n in names]
    flavor = None
    if "mimetype" in lower:
        flavor = "EPUB 电子书"
    elif "[content_types].xml" in lower:
        if any(n.startswith("word/") for n in lower):
            flavor = "DOCX 文档"
        elif any(n.startswith("xl/") for n in lower):
            flavor = "XLSX 表格"
        elif any(n.startswith("ppt/") for n in lower):
            flavor = "PPTX 演示"
    elif "androidmanifest.xml" in lower:
        flavor = "APK 安卓应用"
    elif any(n.endswith(".dex") for n in lower):
        flavor = "APK/JAR"

    # 深度校验：抽查前若干条目的 CRC（限流）
    crc_ok = crc_bad = 0
    if deep:
        budget = 128 * 1024 * 1024
        for e in entries[:64]:
            if e["dir"] or e["csize"] == 0 or budget <= 0:
                continue
            take = min(e["csize"], budget, 64 * 1024 * 1024)
            try:
                f.seek(e["data_off"])
                raw = f.read(take)
                if e["method"] == 8:
                    d = zlib.decompressobj(-15)
                    out = d.decompress(raw) + d.flush()
                else:
                    out = raw
                if zlib.crc32(out) & 0xFFFFFFFF == e["crc"]:
                    crc_ok += 1
                else:
                    crc_bad += 1
            except Exception:
                crc_bad += 1
            budget -= take

    total_u = sum(e["usize"] for e in entries)
    info = {
        "type": flavor or "ZIP 压缩包",
        "kind": "embedded",
        "offset": off, "size": data_end - off,
        "brief": (f"{flavor or 'ZIP 压缩包'} · {len(entries)} 项"
                  + ("" if flavor else f" · 解压后约 {fmt_size(total_u)}")
                  + (" · 含加密条目" if encrypted else "")
                  + ("" if cd_ok else " · 中央目录缺失")
                  + (" · 条目链中断" if truncated else "")),
        "entries": len(entries),
        "sample_names": [e["name"] for e in entries[:8]],
        "cd_ok": cd_ok, "truncated": truncated, "encrypted": encrypted,
        "has_exec": bool(exec_names), "exec_first": exec_names[0] if exec_names else "",
        "crc_checked": crc_ok + crc_bad, "crc_ok": crc_ok, "crc_bad": crc_bad,
    }
    findings.append(info)
    return consumed_end, info


def walk_gzip(f, off, size, findings, warnings):
    hdr = read_at(f, off, 10)
    if len(hdr) < 10 or hdr[:3] != b"\x1f\x8b\x08":
        return None
    flg = hdr[3]
    pos = off + 10
    if flg & 4:  # FEXTRA
        f.seek(pos)
        xlen = struct.unpack("<H", f.read(2))[0]
        pos += 2 + xlen
    if flg & 8:  # FNAME
        f.seek(pos)
        s = f.read(1024)
        pos += s.find(b"\x00") + 1
    if flg & 16:  # FCOMMENT
        f.seek(pos)
        s = f.read(1024)
        pos += s.find(b"\x00") + 1
    if flg & 2:
        pos += 2
    try:
        d = zlib.decompressobj(-15)
        f.seek(pos)
        end = pos
        while end < size:
            chunk = f.read(CHUNK)
            if not chunk:
                break
            d.decompress(chunk)
            end = f.tell()
            if d.eof:
                break
        info = {"type": "GZIP 压缩", "kind": "container", "offset": off,
                "size": end - off, "brief": "GZIP 压缩流"}
        findings.append(info)
        return end, info
    except Exception:
        return None
