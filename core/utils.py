# -*- coding: utf-8 -*-
"""通用小工具：大小格式化、熵计算、读文件片段、警告装配、进度回报"""
import math
from collections import Counter

CHUNK = 8 * 1024 * 1024          # 分块扫描窗口
OVERLAP = 16                      # 跨块重叠，防止签名被截断
MAX_SEARCH = 512 * 1024 * 1024    # 残缺 zip 找下一头时的最大搜索窗


def fmt_size(n):
    if n >= 1024 ** 3:
        return f"{n / 1024 ** 3:.2f} GB"
    if n >= 1024 ** 2:
        return f"{n / 1024 ** 2:.1f} MB"
    if n >= 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n} B"


def read_at(f, off, n):
    f.seek(off)
    return f.read(n)


def entropy(data):
    if not data:
        return 0.0
    c = Counter(data)
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def warn(warnings, level, msg):
    """level: info / warn / danger"""
    warnings.append({"level": level, "msg": msg})


# ---------------- 进度回报：遍历器内部调用 tick，按百分比节流（防 UI 事件洪泛）
_progress_cb = None
_progress_state = {"pct": -1}


def set_progress(cb):
    global _progress_cb
    _progress_cb = cb
    _progress_state["pct"] = -1


def clear_progress():
    global _progress_cb
    _progress_cb = None


def tick(done, total):
    if not _progress_cb:
        return
    pct = int(min(done, total) / max(total, 1) * 100)
    if pct != _progress_state["pct"]:
        _progress_state["pct"] = pct
        try:
            _progress_cb(min(done, total), total)
        except Exception:
            pass
