# -*- coding: utf-8 -*-
"""右下角 Toast 悬浮窗：右键菜单扫描入口，显示进度与结果，自动关闭。
信息设计原则：一眼看懂 —— 大字结论 + 风险徽章 + 一行关键数据 + 至多一条提醒。"""
import os
import queue
import threading
import tkinter as tk
from tkinter import ttk

from core import scan_file
import history
import report
from .theme import CARD, LINE, TXT, SUB, ACC, OK, BAD, WARN, FONT, style_dark, short


def run_toast(paths):
    root = tk.Tk()
    root.overrideredirect(True)
    root.attributes("-topmost", True)
    root.configure(bg=LINE)
    style_dark(root)
    W, H = 400, 190
    sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
    root.geometry(f"{W}x{H}+{sw - W - 24}+{sh - H - 66}")
    card = tk.Frame(root, bg=CARD)
    card.pack(fill="both", expand=True, padx=1, pady=1)

    head = tk.Frame(card, bg=CARD)
    head.pack(fill="x", padx=12, pady=(10, 2))
    dot = tk.Canvas(head, width=10, height=10, bg=CARD, highlightthickness=0)
    dot.pack(side="left")
    dot.create_oval(1, 1, 9, 9, fill=ACC, width=0)
    name_lbl = tk.Label(head, bg=CARD, fg=TXT, font=(FONT, 10, "bold"), anchor="w")
    name_lbl.pack(side="left", padx=6, fill="x", expand=True)
    close = tk.Label(head, text="✕", bg=CARD, fg=SUB, font=(FONT, 10))
    close.pack(side="right")
    close.bind("<Button-1>", lambda e: root.destroy())

    prog = ttk.Progressbar(card, mode="determinate", maximum=100, length=370,
                           style="green.Horizontal.TProgressbar")
    prog.pack(padx=12, pady=(4, 4))

    # ── 大结论行：主类型 + 风险徽章
    row = tk.Frame(card, bg=CARD)
    row.pack(fill="x", padx=12, pady=(2, 0))
    type_lbl = tk.Label(row, text="", bg=CARD, fg=TXT, font=(FONT, 15, "bold"), anchor="w")
    type_lbl.pack(side="left")
    badge = tk.Label(row, text="", bg=CARD, fg="#121417", font=(FONT, 10, "bold"))
    badge.pack(side="right", ipadx=8, ipady=2)

    # ── 关键数据行
    meta_lbl = tk.Label(card, text="", bg=CARD, fg=SUB, font=(FONT, 9), anchor="w")
    meta_lbl.pack(fill="x", padx=12, pady=(4, 0))

    # ── 提醒行（至多一条，最严重的）
    warn_lbl = tk.Label(card, text="", bg=CARD, fg=WARN, font=(FONT, 9),
                        wraplength=370, justify="left", anchor="nw")
    warn_lbl.pack(fill="x", padx=12, pady=(2, 0))

    st_lbl = tk.Label(card, text="准备扫描…", bg=CARD, fg=SUB, font=(FONT, 9), anchor="w")
    st_lbl.pack(fill="x", padx=12, pady=(2, 8))

    paths = [p for p in paths if os.path.isfile(p)]
    if not paths:
        st_lbl.config(text="无效目标", fg=BAD)
        root.after(2500, root.destroy)
        root.mainloop()
        return
    if len(paths) > 1:
        name_lbl.config(text=f"共 {len(paths)} 个文件", fg=WARN)

    state = {"done": 0}
    badge_styles = {"ok": (OK, "✔ 正常"), "warn": (WARN, "⚠ 注意"),
                    "danger": (BAD, "✖ 危险")}

    def _finish_one(r):
        state["done"] += 1
        prog.config(value=100)  # 无论最后事件停在哪，完成时进度条拉满
        name_lbl.config(text=short(os.path.basename(r["file"]), 40))
        level, _word = report.verdict_of(r)
        color, btext = badge_styles.get(level, (OK, "✔ 正常"))
        dot.itemconfig(1, fill=color)
        type_lbl.config(text=r.get("primary", "未知类型"), fg=color)
        badge.config(text=btext, bg=color, fg="#121417")
        real = [w for w in r.get("warnings", []) if w.get("level") in ("danger", "warn")]
        meta_lbl.config(text=f"{r['size_text']} · {r['duration_ms']} ms · "
                             + ("无风险提示" if not real else f"{len(real)} 条提醒"),
                        fg=SUB)
        warn_lbl.config(text=("⚠ " + real[0]["msg"]) if real else "")
        st_lbl.config(text=f"完成 {state['done']}/{len(paths)}", fg=SUB)
        history.add_scan(r)
        if state["done"] >= len(paths):
            root.after(12000, root.destroy)

    q2 = queue.Queue()

    def _worker():
        for p in paths:
            try:
                r = scan_file(
                    p, progress=lambda d, t: q2.put(("prog", d / max(t, 1) * 100)))
                q2.put(("done", r))
            except Exception as e:
                q2.put(("error", str(e)))

    def _poll_toast():
        # 单次事件出错也不能杀死轮询（否则悬浮窗冻结不自动关闭）
        try:
            try:
                while True:
                    ev, payload = q2.get_nowait()
                    if ev == "prog":
                        prog.config(value=payload)
                        st_lbl.config(text=f"扫描中… {payload:.0f}%")
                    elif ev == "done":
                        _finish_one(payload)
                    elif ev == "error":
                        st_lbl.config(text=f"出错：{payload}", fg=BAD)
                        root.after(4000, root.destroy)
                        return
            except queue.Empty:
                pass
        except Exception:
            pass
        root.after(80, _poll_toast)

    threading.Thread(target=_worker, daemon=True).start()
    root.after(80, _poll_toast)
    root.mainloop()
