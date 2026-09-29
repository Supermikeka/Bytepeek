# -*- coding: utf-8 -*-
"""整文件认领的迷你遍历器：适用于基本不会嵌套他文件的格式（MIDI/AMR/APE/RM/SWF/RTF/PEM）"""


def claim_all_walker(type_name):
    """仅当位于文件头(off==0)时认领到 EOF；嵌入位置一律退回签名命中，避免吞掉宿主剩余数据"""
    def _w(f, off, size, findings, warnings):
        if off != 0:
            return None
        info = {"type": type_name, "kind": "container", "offset": 0,
                "size": size, "brief": type_name}
        findings.append(info)
        return size, info
    return _w
