# -*- coding: utf-8 -*-
"""UI 主题：深色配色、样式与共享小工具"""
from tkinter import ttk

BG, CARD, LINE = "#121417", "#1c2026", "#2d333d"
TXT, SUB, ACC = "#e8eaed", "#9aa4b2", "#7dd3fc"
OK, BAD, WARN, EMB, PAD = "#4ade80", "#f87171", "#fbbf24", "#a78bfa", "#3a4150"
FONT = "Microsoft YaHei UI"
KIND_COLOR = {"data": ACC, "container": ACC, "embedded": EMB,
              "padding": PAD, "unknown": WARN, "text": ACC, "aggregate": EMB}


def style_dark(root):
    s = ttk.Style(root)
    s.theme_use("clam")
    s.configure(".", background=BG, foreground=TXT, font=(FONT, 10), borderwidth=0)
    s.configure("TFrame", background=BG)
    s.configure("Card.TFrame", background=CARD)
    s.configure("TLabel", background=BG, foreground=TXT)
    s.configure("Card.TLabel", background=CARD, foreground=TXT)
    s.configure("Sub.TLabel", background=CARD, foreground=SUB)
    s.configure("TButton", background=CARD, foreground=TXT, padding=(10, 5))
    s.map("TButton", background=[("active", LINE), ("pressed", LINE)])
    s.configure("Acc.TButton", background="#15304a", foreground=ACC)
    s.map("Acc.TButton", background=[("active", "#1b3d5f")])
    s.configure("TCheckbutton", background=BG, foreground=TXT)
    s.map("TCheckbutton", background=[("active", BG)])
    s.configure("Treeview", background=CARD, fieldbackground=CARD, foreground=TXT,
                rowheight=26, borderwidth=0)
    s.configure("Treeview.Heading", background="#232830", foreground=SUB,
                font=(FONT, 9, "bold"))
    s.map("Treeview", background=[("selected", "#2d3a4a")])
    s.configure("green.Horizontal.TProgressbar", troughcolor="#262c36",
                background=ACC, borderwidth=0)


def short(path, n=46):
    if len(path) <= n:
        return path
    return path[:n // 2 - 2] + " … " + path[-n // 2 + 1:]
