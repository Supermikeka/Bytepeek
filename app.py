# -*- coding: utf-8 -*-
r"""BytePeek 入口：
  app.py                     → 主窗口
  app.py --toast <文件>      → 右下角悬浮窗扫描（右键菜单用）
  app.py scan <文件...>      → 命令行模式，输出 JSON
"""
import os
import sys


def _crash_log(tp, val, tb):
    r"""未捕获异常落盘：%LOCALAPPDATA%\BytePeek\crash.log"""
    import traceback
    import datetime
    try:
        d = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "BytePeek")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "crash.log"), "a", encoding="utf-8") as fp:
            fp.write(f"\n[{datetime.datetime.now():%Y-%m-%d %H:%M:%S}]\n")
            traceback.print_exception(tp, val, tb, file=fp)
    except Exception:
        pass


def main():
    sys.excepthook = _crash_log
    try:
        import context_menu
        context_menu.ensure_upgrade()  # 任何启动方式都静默升级右键菜单注册
    except Exception:
        pass
    a = sys.argv[1:]
    if a and a[0] == "scan":
        import json
        from core import scan_file
        for p in a[1:]:
            print(json.dumps(scan_file(p), ensure_ascii=False, indent=2))
        return 0
    if a and a[0] == "--toast":
        from ui.toast import run_toast
        return run_toast(a[1:])
    from ui.main_window import run_main
    return run_main()


if __name__ == "__main__":
    try:
        sys.exit(main() or 0)
    except Exception:
        _crash_log(*sys.exc_info())
        sys.exit(1)
