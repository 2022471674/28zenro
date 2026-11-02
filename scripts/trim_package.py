# -*- coding: utf-8 -*-
"""打包发布目录瘦身修剪（构建完成后手动执行一次）。

用法::

    python scripts/trim_package.py <发布目录>          # <目录>/cipherNest 或其父目录都行
    python scripts/trim_package.py D:\\Cod​e\\pythonCode\\release\\V1.0.3

裁剪项（全部是运行时用不到的冗余）：

1. ``PySide6/qml``            —— 纯 Widgets 应用不使用 Qt Quick（-24MB）；
2. ``PySide6/opengl32sw.dll`` —— OpenGL 软件渲染回退，有 GPU 的机器用不到
   （-20MB；如需在远程桌面/无 GPU 环境使用请勿删）；
3. ``PySide6/translations``   —— 全量语言包只保留中英（zh* / en*，含
   qtwebengine_locales 的 zh-CN / en-US / en-GB .pak），其余删（-45MB）。

Qt 找不到某语言的 .qm 会自动回退英文，删除不影响中文界面。

为什么不用 spec 打完自动执行：PyInstaller 的 COLLECT 在 spec 模块执行
**之后**才真正写盘，spec 里拿不到最终目录结构，因此修剪必须在构建完成后
作为独立步骤运行（脚本幂等，可重复执行）。
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path


def _locate_base(arg: str) -> Path:
    """接受 ..\\V1.0.3 或 ..\\V1.0.3\\cipherNest，定位到 <发布目录>/cipherNest。"""
    p = Path(arg).resolve()
    if (p / "cipherNest.exe").is_file():
        return p
    if (p / "cipherNest" / "cipherNest.exe").is_file():
        return p / "cipherNest"
    raise SystemExit(f"找不到发布目录（没有 cipherNest.exe）：{arg}")


def _rmtree(path: Path) -> int:
    if not path.is_dir():
        return 0
    size = sum(f.stat().st_size for f in path.rglob("*") if f.is_file())
    shutil.rmtree(path, ignore_errors=True)
    return size


def _unlink(path: Path) -> int:
    if not path.is_file():
        return 0
    size = path.stat().st_size
    try:
        path.unlink()
    except OSError as exc:
        print(f"  跳过（被占用）：{path.name} —— {exc}")
        return 0
    return size


def _keep_lang(name: str) -> bool:
    """翻译文件名：zh* / en* 保留（zh_CN / en_US / en-GB …）。"""
    lowered = name.lower()
    return lowered.startswith("zh") or lowered.startswith("en")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    base = _locate_base(argv[1])
    internal = base / "_internal"
    pyside = internal / "PySide6"
    freed = 0

    if pyside.is_dir():
        freed += _rmtree(pyside / "qml")
        for junk in ("opengl32sw.dll",):
            freed += _unlink(pyside / junk)

    trans = pyside / "translations" if pyside.is_dir() else None
    if trans and trans.is_dir():
        for entry in list(trans.iterdir()):
            if entry.is_dir():
                # 子目录（qtwebengine_locales）：只保留中英 .pak
                if entry.name.lower() == "qtwebengine_locales":
                    for pak in list(entry.iterdir()):
                        stem = pak.stem.lower()
                        if stem not in ("zh-cn", "zh-cn-tw", "en-us", "en-gb"):
                            freed += _unlink(pak)
                else:
                    freed += _rmtree(entry)
            elif not _keep_lang(entry.name):
                freed += _unlink(entry)

    # WebEngine / Qt 自带的 Detect It Easy? no; 顺手清运行临时垃圾
    for junk in (base / "payload",):        # GUI 运行时生成的数据目录
        if junk.is_dir() and not any(junk.iterdir()):
            freed += _rmtree(junk)

    print(f"已释放 {freed / 1048576:.1f} MB（{base}）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
