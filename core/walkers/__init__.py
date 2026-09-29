# -*- coding: utf-8 -*-
"""遍历器注册表：签名名 -> 遍历器函数"""
from .archive import walk_zip, walk_gzip
from .media import walk_mp4, walk_riff, walk_png, walk_jpeg, walk_gif
from .document import walk_pdf
from .executable import walk_exe, walk_ico, walk_lnk
from .fonts import walk_ttf
from .simple import claim_all_walker

WALKERS = {
    "ZIP": walk_zip, "MP4": walk_mp4, "RIFF": walk_riff, "PNG": walk_png,
    "PDF": walk_pdf, "GZIP": walk_gzip, "EXE": walk_exe, "ICO": walk_ico,
    "JPEG": walk_jpeg, "GIF87a": walk_gif, "GIF89a": walk_gif, "LNK": walk_lnk,
    "TTF": walk_ttf, "OTTO": walk_ttf,
    "MIDI": claim_all_walker("MIDI 音频"), "AMR": claim_all_walker("AMR 音频"),
    "APE": claim_all_walker("APE 音频"), "RM": claim_all_walker("RM 视频"),
    "SWF": claim_all_walker("SWF 动画"), "SWF2": claim_all_walker("SWF 动画"),
    "SWF3": claim_all_walker("SWF 动画"), "RTF": claim_all_walker("RTF 文档"),
    "PEM": claim_all_walker("PEM 证书"),
}
