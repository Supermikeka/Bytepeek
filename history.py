# -*- coding: utf-8 -*-
r"""扫描历史记录 —— SQLite 存储（%LOCALAPPDATA%\BytePeek\history.db）"""
import os
import json
import sqlite3
import datetime

APP_DIR = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "BytePeek")
DB_PATH = os.path.join(APP_DIR, "history.db")


def _conn():
    os.makedirs(APP_DIR, exist_ok=True)
    c = sqlite3.connect(DB_PATH, timeout=5)
    c.execute("""CREATE TABLE IF NOT EXISTS scans(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT, path TEXT, size INTEGER,
        primary_type TEXT, summary TEXT, verdict TEXT)""")
    return c


def add_scan(verdict):
    try:
        c = _conn()
        c.execute("INSERT INTO scans(ts,path,size,primary_type,summary,verdict) VALUES(?,?,?,?,?,?)",
                  (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                   verdict["file"], verdict["size"], verdict["primary"],
                   verdict["summary"], json.dumps(verdict, ensure_ascii=False)))
        c.commit()
        c.close()
    except Exception:
        pass


def list_scans(limit=300):
    try:
        c = _conn()
        rows = c.execute("SELECT id,ts,path,size,primary_type,summary FROM scans ORDER BY id DESC LIMIT ?",
                         (limit,)).fetchall()
        c.close()
        return rows
    except Exception:
        return []


def get_verdict(row_id):
    try:
        c = _conn()
        r = c.execute("SELECT verdict FROM scans WHERE id=?", (row_id,)).fetchone()
        c.close()
        return json.loads(r[0]) if r else None
    except Exception:
        return None


def clear():
    try:
        c = _conn()
        c.execute("DELETE FROM scans")
        c.commit()
        c.close()
    except Exception:
        pass
