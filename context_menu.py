# -*- coding: utf-8 -*-
r"""右键菜单集成 —— 写 HKCU\Software\Classes\*\shell（用户级，无需管理员）。
交互模型：主窗口勾选框"绑定右键菜单" → bind()；取消勾选 → unbind()。
启动时 sync_on_start() 自动纠偏：清理旧版动词 + 若已绑定但路径过期（软件被移动）则重写为当前路径。"""
import os
import sys
import winreg

KEY = r"Software\Classes\*\shell\BytePeekScan"
MENU_TEXT = "用 BytePeek 扫描类型"
LEGACY_KEYS = (r"Software\Classes\*\shell\WhatisItScan",)


def default_target():
    """右键菜单指向的目标（强制反斜杠规范化，正斜杠会让资源管理器报"无法访问"）"""
    if getattr(sys, "frozen", False):
        return os.path.normpath(sys.executable)
    return os.path.normpath(os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app.py"))


def install(target_path):
    """target_path: exe 路径（打包后）或脚本路径（开发模式，自动带解释器）"""
    target_path = os.path.normpath(os.path.abspath(target_path))
    if target_path.lower().endswith(".exe"):
        icon = target_path
        cmd = f'"{target_path}" --toast "%1"'
    else:
        icon = sys.executable
        cmd = f'"{os.path.normpath(sys.executable)}" "{target_path}" --toast "%1"'
    k = winreg.CreateKey(winreg.HKEY_CURRENT_USER, KEY)
    winreg.SetValueEx(k, None, 0, winreg.REG_SZ, MENU_TEXT)
    winreg.SetValueEx(k, "Icon", 0, winreg.REG_SZ, icon)
    # Player：多选文件时资源管理器只传一个文件，避免"幽灵扫描"
    winreg.SetValueEx(k, "MultiSelectModel", 0, winreg.REG_SZ, "Player")
    winreg.CloseKey(k)
    c = winreg.CreateKey(winreg.HKEY_CURRENT_USER, KEY + r"\command")
    winreg.SetValueEx(c, None, 0, winreg.REG_SZ, cmd)
    winreg.CloseKey(c)


def uninstall():
    try:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, KEY + r"\command")
    except FileNotFoundError:
        pass
    try:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, KEY)
    except FileNotFoundError:
        pass


def bind():
    """勾选框入口：以当前程序真实位置（重）写入右键菜单"""
    install(default_target())


def unbind():
    """取消勾选入口"""
    uninstall()


def status():
    """返回 (是否已绑定, 命令行字符串)"""
    try:
        c = winreg.OpenKey(winreg.HKEY_CURRENT_USER, KEY + r"\command")
        cmd = winreg.QueryValueEx(c, None)[0]
        winreg.CloseKey(c)
        return True, cmd
    except OSError:
        return False, ""


def uninstall_legacy():
    """删除历史版本遗留的菜单动词"""
    for old in LEGACY_KEYS:
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, old + r"\command")
        except OSError:
            pass
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, old)
        except OSError:
            pass


def _registered_command():
    ok, cmd = status()
    return cmd if ok else None


def sync_on_start():
    """启动纠偏：清理旧动词；若已绑定但命令路径与当前程序不符（软件被移动），
    自动重写为当前路径。返回当前是否处于绑定状态。"""
    uninstall_legacy()
    cmd = _registered_command()
    if cmd is None:
        return False
    want = f'"{default_target()}" --toast "%1"'
    if os.path.normcase(cmd) != os.path.normcase(want):
        bind()  # 路径过期（软件被移动/斜杠不规范）→ 静默重写
    return True
