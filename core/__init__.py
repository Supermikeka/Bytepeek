# -*- coding: utf-8 -*-
"""BytePeek 扫描引擎包。
公共 API：core.scan_file(path, progress=None, deep=False) -> verdict dict
"""
from .scanner import scan_file
from .utils import fmt_size

__all__ = ["scan_file", "fmt_size"]
