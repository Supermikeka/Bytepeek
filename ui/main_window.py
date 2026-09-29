# -*- coding: utf-8 -*-
"""BytePeek 主窗口：选择文件扫描 + 结果详情 + 历史记录 + 报告导出 + 右键菜单管理"""
import datetime
import os
import queue
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from core import scan_file, fmt_size
import history
import context_menu
import report
from .theme import (BG, CARD, LINE, TXT, SUB, ACC, OK, BAD, WARN, FONT,
                    KIND_COLOR, style_dark, short)


def run_main():
    root = tk.Tk()
    root.title("BytePeek · 文件类型鉴定器")
    root.geometry("780x820")
    root.resizable(False, False)  # 锁死窗口尺寸
    root.configure(bg=BG)
    style_dark(root)

    q = queue.Queue()
    state = {"busy": False, "results": {}, "current": None}

    def _btn(parent, text, cmd):
        """按钮统一入口：点击执行后把焦点交还窗口，消除 clam 主题的黑色虚线选中框"""
        def run():
            cmd()
            root.focus_set()
        return ttk.Button(parent, text=text, command=run, takefocus=False)

    # ── 顶部：选择区
    top = ttk.Frame(root)
    top.pack(fill="x", padx=12, pady=(12, 6))
    drop = tk.Canvas(top, width=752, height=92, bg=CARD, highlightthickness=1,
                     highlightbackground=LINE)
    drop.pack()
    drop.create_text(376, 32, text="点击这里选择文件开始鉴定", fill=TXT,
                     font=(FONT, 13, "bold"))
    drop.create_text(376, 60, text="支持识别嵌套/拼接/灌水文件 · 结果自动存入历史 · 可导出 HTML 报告",
                     fill=SUB, font=(FONT, 9))
    deep_var = tk.BooleanVar(value=False)

    def _pick(_e=None):
        ps = filedialog.askopenfilenames()
        if ps:
            start_scan(list(ps))
    drop.bind("<Button-1>", _pick)

    opts = ttk.Frame(root)
    opts.pack(fill="x", padx=12)
    ttk.Checkbutton(opts, text="深度校验（抽查内嵌压缩包 CRC，较慢）",
                    variable=deep_var, takefocus=False).pack(side="left")

    # ── 右键绑定（勾选式，主页显眼位置）
    bound_var = tk.BooleanVar(value=False)
    lbl_bind = ttk.Label(opts, foreground=SUB)

    def _toggle_bind():
        try:
            if bound_var.get():
                context_menu.bind()      # 以当前程序真实位置写入（路径自动更正）
            else:
                context_menu.unbind()
        except Exception as e:
            messagebox.showerror("操作失败", str(e))
        refresh_bind()

    def refresh_bind():
        ok, cmd = context_menu.status()
        bound_var.set(ok)
        lbl_bind.config(text=("✔ 已绑定" if ok else "○ 未绑定"),
                        foreground=(OK if ok else SUB))

    ttk.Checkbutton(opts, text="绑定右键菜单",
                    variable=bound_var, command=_toggle_bind, takefocus=False).pack(
        side="left", padx=(18, 4))
    lbl_bind.pack(side="left")

    # 启动纠偏：清理旧版动词；软件被移动后自动把右键指向新位置
    context_menu.sync_on_start()
    refresh_bind()

    # ── 进度条
    prog_var = tk.DoubleVar(value=0)
    ttk.Progressbar(root, orient="horizontal", maximum=100, variable=prog_var,
                    style="green.Horizontal.TProgressbar").pack(fill="x", padx=12, pady=(6, 0))

    # ── 结果区
    res = ttk.Frame(root, style="Card.TFrame")
    res.pack(fill="x", padx=12, pady=6)
    hdr = ttk.Frame(res, style="Card.TFrame")
    hdr.pack(fill="x", padx=10, pady=(8, 2))
    ttk.Label(hdr, text="扫描结果", style="Card.TLabel", font=(FONT, 10, "bold")).pack(side="left")
    btn_exp = _btn(hdr, "⬇ 导出报告", lambda: _save_report(state.get("current")))
    btn_exp.config(state="disabled")
    btn_exp.pack(side="right")
    _btn(hdr, "清空本次", lambda: _clear_current()).pack(side="right", padx=(6, 0))
    _btn(hdr, "重新扫描", lambda: _rescan_current()).pack(side="right", padx=(6, 0))
    _btn(hdr, "打开位置", lambda: _open_current()).pack(side="right", padx=(6, 0))
    canvas = tk.Canvas(res, width=752, height=26, bg=CARD, highlightthickness=1,
                       highlightbackground=LINE)
    canvas.pack(padx=10)
    ttk.Label(res, text="图例：■蓝=已识别结构   ■紫=内嵌压缩包   ■黄=未知/高熵（常为加密数据）   ■深灰=灌水填充",
              style="Sub.TLabel", font=(FONT, 8)).pack(anchor="w", padx=10, pady=(2, 0))
    lbl_summary = ttk.Label(res, text="尚未扫描", style="Sub.TLabel", wraplength=730,
                            justify="left")
    lbl_summary.pack(anchor="w", padx=10, pady=4)
    tv_find = ttk.Treeview(res, columns=("type", "off", "brief"), show="headings", height=5)
    for col, w in (("type", 150), ("off", 130), ("brief", 450)):
        tv_find.heading(col, text={"type": "发现", "off": "偏移", "brief": "说明"}[col])
        tv_find.column(col, width=w, anchor="w")
    tv_find.pack(fill="x", padx=10, pady=(2, 4))

    # ── 详情区：当前结果的完整解读
    detail = tk.Text(res, height=9, bg="#181c22", fg=TXT, font=(FONT, 9),
                     relief="flat", state="disabled", wrap="word", padx=8, pady=6)
    detail.pack(fill="x", padx=10, pady=(0, 10))

    # ── 历史区
    his = ttk.Frame(root)
    his.pack(fill="both", expand=True, padx=12, pady=6)
    ttk.Label(his, text="扫描历史", font=(FONT, 10, "bold")).pack(anchor="w")
    bar = ttk.Frame(his)
    bar.pack(fill="x", pady=2)
    tv_his = ttk.Treeview(his, columns=("ts", "size", "file", "sum"), show="headings", height=6)
    for col, w in (("ts", 130), ("size", 90), ("file", 330), ("sum", 190)):
        tv_his.heading(col, text={"ts": "时间", "size": "大小", "file": "文件", "sum": "结论"}[col])
        tv_his.column(col, width=w, anchor="w")
    tv_his.pack(fill="both", expand=True)

    def _open_folder():
        sel = tv_his.selection()
        if not sel:
            return
        r = history.get_verdict(int(sel[0]))
        if r:
            os.startfile(os.path.dirname(r["file"]))

    def _rescan():
        sel = tv_his.selection()
        if sel:
            r = history.get_verdict(int(sel[0]))
            if r:
                start_scan([r["file"]])

    def _export_history():
        sel = tv_his.selection()
        if not sel:
            messagebox.showinfo("提示", "请先在列表中选择一条扫描记录")
            return
        r = history.get_verdict(int(sel[0]))
        if r:
            _save_report(r)

    def _clear():
        if messagebox.askyesno("确认", "清空全部扫描历史？"):
            history.clear()
            refresh_history()

    for txt, cmd in (("导出报告", _export_history), ("清空记录", _clear),
                     ("打开位置", _open_folder), ("重新扫描", _rescan)):
        _btn(bar, txt, cmd).pack(side="right", padx=(6, 0))

    # ── 报告导出
    def _save_report(r):
        if not r:
            messagebox.showinfo("提示", "还没有可导出的扫描结果，请先扫描一个文件")
            return
        base = os.path.splitext(os.path.basename(r.get("file", "")))[0] or "报告"
        stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        fn = filedialog.asksaveasfilename(
            initialfile=f"BytePeek报告_{base}_{stamp}.html",
            defaultextension=".html",
            filetypes=[("HTML 报告", "*.html"), ("文本报告", "*.txt")])
        if not fn:
            return
        try:
            report.write_report(r, fn)
            status.config(text=f"报告已导出：{fn}")
        except Exception as e:
            messagebox.showerror("导出失败", str(e))

    # ── 当前结果操作（只影响上方结果区，不动历史库）
    def _clear_current():
        state["current"] = None
        prog_var.set(0)
        lbl_summary.config(text="尚未扫描", foreground=SUB)
        canvas.delete("all")
        tv_find.delete(*tv_find.get_children())
        detail.config(state="normal")
        detail.delete("1.0", "end")
        detail.config(state="disabled")
        btn_exp.config(state="disabled")
        status.config(text="已清空当前结果（历史记录不受影响）")

    def _rescan_current():
        r = state.get("current")
        if r:
            start_scan([r["file"]])
        else:
            messagebox.showinfo("提示", "还没有可重新扫描的结果，请先扫描一个文件")

    def _open_current():
        r = state.get("current")
        if r:
            os.startfile(os.path.dirname(r["file"]))
        else:
            messagebox.showinfo("提示", "还没有扫描结果，请先扫描一个文件")

    status = ttk.Label(root, text="就绪", foreground=SUB, anchor="w")
    status.pack(fill="x", padx=14, side="bottom")

    # ── 扫描流程
    def start_scan(paths):
        if state["busy"]:
            messagebox.showinfo("忙碌", "正在扫描中，请稍候")
            return
        paths = [p for p in paths if os.path.isfile(p)]
        if not paths:
            messagebox.showwarning("无效", "请提供文件（暂不支持文件夹）")
            return
        state["busy"] = True
        status.config(text=f"扫描中… 0/{len(paths)}")
        deep = deep_var.get()
        threading.Thread(target=_worker, args=(paths, deep, q), daemon=True).start()
        root.after(80, _poll)

    def _worker(paths, deep, _q):
        for i, p in enumerate(paths):
            try:
                r = scan_file(
                    p, progress=lambda d, t, _i=i: _q.put(("prog", _i, len(paths), d, t)),
                    deep=deep)
                _q.put(("done", r))
            except Exception as e:
                _q.put(("error", p, str(e)))

    def _poll():
        # 任何单次事件处理出错都不允许杀死轮询循环（否则界面永久"卡死"）
        try:
            try:
                while True:
                    ev = q.get_nowait()
                    if ev[0] == "prog":
                        _, i, n, d, t = ev
                        prog_var.set(d / max(t, 1) * 100)
                        status.config(text=f"扫描中… {i + 1}/{n}  {d / max(t, 1):.0%}")
                    elif ev[0] == "done":
                        show_result(ev[1])
                    elif ev[0] == "error":
                        prog_var.set(0)
                        status.config(text=f"出错：{ev[2]}")
            except queue.Empty:
                pass
        except Exception as e:
            try:
                status.config(text=f"内部错误（已恢复）：{e}")
            except Exception:
                pass
        # 历史库同步：右键悬浮窗的扫描约 2 秒内自动出现在下方列表
        state["tick"] = state.get("tick", 0) + 1
        if state["tick"] >= 25:
            state["tick"] = 0
            try:
                top = (history.list_scans(limit=1) or [(0,)])[0][0]
                if state.get("his_top") is None:
                    state["his_top"] = top
                elif top != state["his_top"]:
                    state["his_top"] = top
                    refresh_history()
            except Exception:
                pass
        root.after(80, _poll)

    def show_result(r):
        state["busy"] = False
        prog_var.set(0)
        history.add_scan(r)
        state["results"][r["file"]] = r
        state["current"] = r
        btn_exp.config(state="normal")
        worst = "danger" if any(w["level"] == "danger" for w in r["warnings"]) \
            else ("warn" if r["warnings"] else None)
        lbl_summary.config(
            text=f"{os.path.basename(r['file'])}  ·  {r['size_text']}  ·  {r['duration_ms']}ms\n"
                 + r["summary"],
            foreground={"danger": BAD, "warn": WARN, None: OK}[worst])
        canvas.delete("all")
        w = 752
        for seg in r["segments"]:
            x0 = w * seg["start"] / max(r["size"], 1)
            x1 = w * seg["end"] / max(r["size"], 1)
            canvas.create_rectangle(x0, 2, max(x1, x0 + 2), 24, width=0,
                                    fill=KIND_COLOR.get(seg["kind"], ACC))
        tv_find.delete(*tv_find.get_children())
        for x in r["findings"]:
            tv_find.insert("", "end", values=(x["type"], f"@{x['offset']:,}", x["brief"]))
        detail.config(state="normal")
        detail.delete("1.0", "end")
        detail.insert("1.0", report.format_detail(r))
        detail.config(state="disabled")
        refresh_history()
        state["his_top"] = (history.list_scans(limit=1) or [(0,)])[0][0]
        status.config(text=f"完成：{os.path.basename(r['file'])}（{r['duration_ms']}ms）")

    def refresh_history():
        tv_his.delete(*tv_his.get_children())
        for row in history.list_scans():
            tv_his.insert("", "end", iid=str(row[0]),
                          values=(row[1], fmt_size(row[3]),
                                  short(row[2], 40), short(row[5], 26)))

    refresh_history()
    root.mainloop()
