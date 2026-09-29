# -*- coding: utf-8 -*-
"""扫描主流程：签名搜索 → 遍历器认领 → 未知区分级 → 语境化体检结论"""
import os
import re
import time

from .utils import set_progress, clear_progress, fmt_size, warn
from .signatures import SIGNATURES, TYPE_EXTS, ALL_KNOWN_EXTS
from .classify import find_next_sig, classify_gap, count_sigs, sniff_text_path
from .walkers import WALKERS


def scan_file(path, progress=None, deep=False):
    set_progress(progress)
    t0 = time.time()
    size = os.path.getsize(path)
    f = open(path, "rb")
    segments = []
    findings = []
    warnings = []
    pos = 0

    # 文件名体检
    base_name = os.path.basename(path)
    m2 = re.search(r"\.(zip|rar|7z|gz|tar|jpg|jpeg|png|gif|mp4|mkv|pdf|docx?|xlsx?|exe)\.[A-Za-z0-9]{1,4}$",
                   base_name, re.I)
    if m2:
        warn(warnings, "info",
             f"文件名含双重后缀（…{m2.group(0)}），常见于改名伪装/二次分发")
    if size < 16:
        warn(warnings, "info", "文件过小，无法进行有效分析")

    # 文本嗅探优先：干净的可打印文本直接按文本家族识别（HTML/JSON/XML/代码等），
    # 避免文本里恰好含 "ftyp"/"RIFF" 等字样被误判成二进制容器
    if size >= 16:
        t = sniff_text_path(path, size)
        if t:
            findings.append({"type": t, "kind": "text", "offset": 0,
                             "size": size, "brief": t})
            segments.append({"start": 0, "end": size, "kind": "data", "label": t})
            pos = size  # 跳过二进制主循环

    # ISO9660 / TAR 特判（签名不在文件头，无法走通用签名搜索）
    early = None
    if size > 0x8006 and _probe(f, 0x8001, 5) == b"CD001":
        early = "ISO 光盘镜像"
    elif size > 262 and _probe(f, 257, 5) == b"ustar":
        early = "TAR 归档"
    if early:
        findings.append({"type": early, "kind": "container",
                         "offset": 0, "size": size, "brief": early})
        segments.append({"start": 0, "end": size, "kind": "container", "label": early})
        pos = size  # 跳过主循环

    while pos < size:
        if len(findings) >= 40:   # 命中过多 → 聚合模式，避免刷屏
            rest = count_sigs(f, pos, size)
            if rest:
                top = "、".join(f"{v}×{k}" for k, v in rest.most_common(6))
                truncated_note = "（超出统计区，已省略）" if pos + 512 * 1024 * 1024 < size else ""
                findings.append({"type": "嵌入资源(聚合)", "kind": "aggregate",
                                 "offset": pos, "size": size - pos,
                                 "brief": f"内含大量嵌入对象：{top}{truncated_note}"})
                segments.append({"start": pos, "end": size, "kind": "data",
                                 "label": "嵌入资源区"})
            else:
                seg = classify_gap(f, pos, size, findings)
                if seg:
                    segments.append(seg)
            pos = size
            break
        hit = find_next_sig(f, pos, size, progress)
        if hit is None:
            seg = classify_gap(f, pos, size, findings)
            if seg:
                segments.append(seg)
            break
        off, name = hit
        if off > pos:
            seg = classify_gap(f, pos, off, findings)
            if seg:
                segments.append(seg)
        walker = WALKERS.get(name)
        consumed = None
        if walker:
            try:
                consumed = walker(f, off, size, findings, warnings)
            except Exception:
                consumed = None
        if consumed:
            end, info = consumed
            segments.append({"start": info.get("offset", off), "end": end,
                             "kind": info.get("kind", "data"),
                             "label": info["type"]})
            pos = min(end, size)
        else:
            sig = next(s for s in SIGNATURES if s[0] == name)
            findings.append({"type": sig[0], "kind": "sig", "offset": off,
                             "size": len(sig[2]),
                             "brief": f"签名命中：{sig[0]}（{sig[3]}，未做结构解析）"})
            segments.append({"start": off, "end": min(off + 32, size),
                             "kind": "data", "label": sig[0]})
            if name == "EXE":
                warn(warnings, "warn",
                     "MZ 头但非有效 PE 结构 → 可能是伪装/损坏的可执行文件或纯数据")
            pos = min(off + 32, size)
        if progress:
            progress(min(pos, size), size)

    f.close()
    clear_progress()

    # 纯文本兜底（主循环没认出任何东西时）
    if not findings:
        t = sniff_text_path(path, size)
        if t:
            findings.append({"type": t, "kind": "text", "offset": 0,
                             "size": size, "brief": t})
            segments = [{"start": 0, "end": size, "kind": "data", "label": t}]

    recognized = sum(s["end"] - s["start"] for s in segments if s["kind"] in ("data", "container", "embedded"))
    padding = sum(s["end"] - s["start"] for s in segments if s["kind"] == "padding")
    unknown = size - recognized - padding
    if size and padding + unknown > size * 0.5 and (recognized or findings):
        warn(warnings, "warn", f"实体内容仅约 {recognized / size:.0%}，"
                               f"{fmt_size(padding + unknown)} 为填充/未知区（疑似灌水马甲文件）")

    primary = findings[0]["type"] if findings else "未知类型"

    # 嵌套 zip 的可执行文件：按宿主语境分级（exe 内嵌属安装器常态，降级为 info）
    host_is_exe = bool(findings) and findings[0].get("type", "").startswith("EXE")
    for x in findings:
        if x.get("has_exec"):
            if host_is_exe and x.get("offset", 0) > 0:
                warn(warnings, "info", "exe 内嵌 zip 含可执行文件（安装器常见，无需紧张）")
            else:
                warn(warnings, "danger",
                     f"压缩包内含可执行文件（{x.get('exec_first', '?')}），运行前务必查毒")

    # 拼接检测：多种容器结构共存（小体积资源不计；exe+压缩包是安装器常态）
    types = {x["type"] for x in findings
             if x.get("kind") in ("container", "embedded") and x.get("size", 0) >= 1024 * 1024}
    if len(types) >= 2:
        base_types = {t.split(" ")[0] for t in types}
        if "EXE" in base_types and base_types & {"ZIP", "RAR", "7Z", "GZIP", "CAB", "WIM"}:
            warn(warnings, "info", "exe 内嵌压缩包数据（常见于安装包/自解压程序）")
        else:
            warn(warnings, "danger",
                 f"多种容器结构拼接（{' + '.join(sorted(types))}）→ 疑似马甲/捆绑文件")

    # 高熵加密嫌疑（仅当外层不是标准压缩/多媒体容器时）
    if not findings or findings[0].get("kind") == "sig":
        hi = sum(s["end"] - s["start"] for s in segments
                 if s["kind"] == "unknown" and s["label"].startswith("高熵"))
        if size and hi > size * 0.6:
            warn(warnings, "warn",
                 f"{hi / size:.0%} 区域为高熵数据且外层非标准压缩容器 → 内容可能被加密或为私有格式")

    # 扩展名与实际内容不符
    ext = os.path.splitext(path)[1].lower().lstrip(".")
    if findings and ext and ext in ALL_KNOWN_EXTS:
        base_type = findings[0]["type"].split(" ")[0]
        ok_exts = TYPE_EXTS.get(base_type, set())
        if ok_exts and ext not in ok_exts:
            warn(warnings, "danger",
                 f"扩展名 .{ext} 与实际内容（{findings[0]['type']}）不符 → 后缀被改过/伪装文件")

    # summary（按级别排序：danger > warn > info）
    lvl_rank = {"danger": 0, "warn": 1, "info": 2}
    ws = sorted(warnings, key=lambda w: lvl_rank.get(w["level"], 3))
    summary = primary if not findings else "；".join(x["brief"] for x in findings[:3])
    if ws:
        summary += " ⚠ " + "；".join(w["msg"] for w in ws[:2])

    if any(w["level"] == "danger" for w in warnings):
        v_level, v_word = "danger", "危险"
    elif warnings:
        v_level, v_word = "warn", "注意"
    else:
        v_level, v_word = "ok", "正常"

    return {
        "file": path,
        "size": size,
        "size_text": fmt_size(size),
        "primary": primary,
        "duration_ms": int((time.time() - t0) * 1000),
        "verdict_level": v_level,
        "verdict_word": v_word,
        "segments": segments,
        "findings": findings,
        "warnings": warnings,
        "coverage": {"recognized": recognized, "padding": padding, "unknown": unknown},
        "summary": summary,
    }


def _probe(f, off, n):
    """在文件偏移处取 n 字节（不抛异常）"""
    try:
        f.seek(off)
        return f.read(n)
    except OSError:
        return b""
