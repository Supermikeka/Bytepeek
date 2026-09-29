# -*- coding: utf-8 -*-
r"""报告生成 —— 扫描结果的 HTML/文本导出 + 详情格式化"""
import datetime
from html import escape

APP_VERSION = "v1.4.3"

_LEVEL_COLOR = {"danger": "#F87171", "warn": "#FBBF24", "info": "#7DD3FC"}
_LEVEL_WORD = {"danger": "红", "warn": "黄", "info": "蓝"}
_KIND_COLOR = {"data": "#7DD3FC", "container": "#7DD3FC", "embedded": "#A78BFA",
               "padding": "#3A4150", "unknown": "#FBBF24", "text": "#7DD3FC",
               "aggregate": "#A78BFA"}
_FINDING_LABELS = (
    ("entries", "条目数"), ("duration_s", "时长(秒)"), ("sample_names", "内容示例"),
    ("target", "指向目标"), ("crc_checked", "CRC抽查"), ("crc_ok", "CRC通过"),
    ("crc_bad", "CRC失败"), ("indexed_max", "索引覆盖到"), ("boxes", "顶层box"),
)


def verdict_of(r):
    """从警告列表推导风险级别：返回 (level, 中文词)"""
    levels = [w.get("level") for w in r.get("warnings", [])]
    if "danger" in levels:
        return "danger", "危险"
    if "warn" in levels:
        return "warn", "注意"
    return "ok", "正常"


def format_detail(r):
    """完整详情的多行中文文本（主窗口详情框 / 文本报告共用）"""
    L = []
    L.append(f"文件：{r.get('file', '')}")
    L.append(f"大小：{r.get('size_text', '')}    扫描耗时：{r.get('duration_ms', '?')} ms")
    L.append(f"判定：{verdict_of(r)[1]}    主类型：{r.get('primary', '')}")
    L.append(f"结论：{r.get('summary', '')}")
    size = r.get("size") or 0
    cov = r.get("coverage") or {}
    if size and cov:
        L.append("字节构成：已识别 {:.0%} | 填充 {:.0%} | 未知 {:.0%}".format(
            cov.get("recognized", 0) / size, cov.get("padding", 0) / size,
            cov.get("unknown", 0) / size))
    L.append("")
    for i, f in enumerate(r.get("findings", []), 1):
        L.append(f"── 发现 {i}：{f.get('type', '')}  @第 {f.get('offset', 0):,} 字节 ──")
        if f.get("brief"):
            L.append(f"    说明：{f['brief']}")
        if f.get("size") is not None:
            L.append(f"    范围：自 {f.get('offset', 0):,} 起约 {f.get('size', 0):,} 字节")
        for key, label in _FINDING_LABELS:
            v = f.get(key)
            if v not in (None, ""):
                L.append(f"    {label}：{v}")
        L.append("")
    ws = r.get("warnings", [])
    if ws:
        L.append("── 警告（红>黄>蓝）──")
        for w in ws:
            L.append(f"  [{_LEVEL_WORD.get(w.get('level'), '?')}] {w.get('msg', '')}")
    else:
        L.append("── 无警告 ──")
    return "\n".join(L)


def export_text(r):
    head = [
        "=" * 62,
        f"BytePeek {APP_VERSION} 扫描报告",
        f"生成时间：{datetime.datetime.now():%Y-%m-%d %H:%M:%S}",
        "=" * 62,
        "",
    ]
    return "\n".join(head) + format_detail(r) + "\n"


_CSS = """
  body{background:#121417;color:#e8eaed;font-family:'Microsoft YaHei UI',sans-serif;margin:0;padding:28px 16px;line-height:1.65}
  .wrap{max-width:900px;margin:0 auto}
  h1{font-size:20px;margin:0 0 2px}
  .meta{color:#9aa4b2;font-size:12.5px;margin-bottom:16px}
  h2{font-size:15px;color:#7dd3fc;border-left:3px solid #7dd3fc;padding-left:9px;margin:22px 0 8px}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th,td{border:1px solid #2d333d;padding:6px 9px;text-align:left;vertical-align:top}
  th{background:#232830;color:#9aa4b2;font-weight:600}
  .card{background:#1c2026;border:1px solid #2d333d;border-radius:10px;padding:14px 16px;margin-bottom:12px}
  .num{font-variant-numeric:tabular-nums;white-space:nowrap}
  .d{color:#f87171;font-weight:600}.w{color:#fbbf24;font-weight:600}.i{color:#7dd3fc}
  .ok{color:#4ade80;font-weight:700}.bad{color:#f87171;font-weight:700}.wr{color:#fbbf24;font-weight:700}
  .bar{display:flex;height:18px;border-radius:6px;overflow:hidden;border:1px solid #2d333d;margin:6px 0 4px}
  .seg{min-width:2px}
  .legend{color:#9aa4b2;font-size:12px;margin-bottom:4px}
"""


def _badge_html(level, word):
    if level == "danger":
        return '<span class="bad">✖ 危险</span>'
    if level == "warn":
        return '<span class="wr">⚠ 注意</span>'
    return '<span class="ok">✔ 正常</span>'


def export_html(r):
    level, word = verdict_of(r)
    size = r.get("size") or 0
    cov = r.get("coverage") or {}
    parts = []
    parts.append("<!DOCTYPE html><html lang='zh-CN'><head><meta charset='UTF-8'>")
    parts.append(f"<title>BytePeek 扫描报告 · {escape(r.get('file', ''))}</title>")
    parts.append(f"<style>{_CSS}</style></head><body><div class='wrap'>")
    parts.append("<h1>BytePeek 扫描报告</h1>")
    parts.append(f"<div class='meta'>生成时间 {datetime.datetime.now():%Y-%m-%d %H:%M:%S}"
                 f" ｜ BytePeek {APP_VERSION} ｜ 深度校验：{'已开启' if r.get('deep') else '未开启'}</div>")

    parts.append("<h2>文件信息</h2><div class='card'><table>")
    parts.append(f"<tr><th style='width:110px'>文件路径</th><td>{escape(r.get('file', ''))}</td></tr>")
    parts.append(f"<tr><th>大小</th><td class='num'>{r.get('size_text', '')}（{size:,} 字节）</td></tr>")
    parts.append(f"<tr><th>判定</th><td>{_badge_html(level, word)}　主类型：{escape(r.get('primary', ''))}</td></tr>")
    parts.append(f"<tr><th>耗时</th><td class='num'>{r.get('duration_ms', '?')} ms</td></tr>")
    parts.append(f"<tr><th>结论</th><td>{escape(r.get('summary', ''))}</td></tr></table></div>")

    if size and r.get("segments"):
        parts.append("<h2>字节构成</h2><div class='card'>")
        parts.append("<div class='bar'>")
        for s in r["segments"]:
            pct = (s["end"] - s["start"]) / size * 100
            parts.append(f"<div class='seg' style='width:{pct:.3f}%;background:"
                         f"{_KIND_COLOR.get(s['kind'], '#7DD3FC')}'></div>")
        parts.append("</div>")
        parts.append("<div class='legend'>■蓝=已识别结构　■紫=内嵌压缩包　■黄=未知/高熵　■深灰=灌水填充</div>")
        parts.append(f"<div>已识别 <b>{cov.get('recognized', 0) / size:.0%}</b>　"
                     f"填充 <b>{cov.get('padding', 0) / size:.0%}</b>　"
                     f"未知 <b>{cov.get('unknown', 0) / size:.0%}</b></div></div>")

    parts.append("<h2>发现明细</h2><div class='card'><table>")
    parts.append("<tr><th style='width:36px'>#</th><th style='width:150px'>类型</th>"
                 "<th style='width:120px'>偏移</th><th style='width:110px'>大小</th><th>说明</th></tr>")
    for i, f in enumerate(r.get("findings", []), 1):
        fsize = f.get("size")
        fsize_s = f"{fsize:,}" if isinstance(fsize, int) else "—"
        parts.append(f"<tr><td class='num'>{i}</td><td>{escape(str(f.get('type', '')))}</td>"
                     f"<td class='num'>@{f.get('offset', 0):,}</td><td class='num'>{fsize_s}</td>"
                     f"<td>{escape(str(f.get('brief', '')))}")
        for key, label in _FINDING_LABELS:
            v = f.get(key)
            if v not in (None, ""):
                parts.append(f"<br><span style='color:#9aa4b2'>{label}：{escape(str(v))}</span>")
        parts.append("</td></tr>")
    parts.append("</table></div>")

    ws = r.get("warnings", [])
    parts.append("<h2>警告</h2><div class='card'>")
    if ws:
        parts.append("<table>")
        for w in ws:
            lv = w.get("level", "info")
            parts.append(f"<tr><td style='width:70px' class='{lv[0]}'>"
                         f"{_LEVEL_WORD.get(lv, '?')} {escape(lv)}</td>"
                         f"<td>{escape(w.get('msg', ''))}</td></tr>")
        parts.append("</table>")
    else:
        parts.append("<span class='ok'>✔ 无警告</span>")
    parts.append("</div>")

    parts.append(f"<div class='meta'>本报告由 BytePeek {APP_VERSION} 自动生成 · "
                 f"仅基于文件字节内容的静态分析</div>")
    parts.append("</div></body></html>")
    return "".join(parts)


def write_report(r, path):
    if str(path).lower().endswith((".html", ".htm")):
        content = export_html(r)
    else:
        content = export_text(r)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path
