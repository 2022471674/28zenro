# -*- coding: utf-8 -*-
"""思维导图页（Mermaid 渲染）。

接受用户输入的 Mermaid 语法（``mindmap`` / ``graph`` / ``flowchart`` 等），
点击「渲染」后弹出独立对话框，用本地 mermaid.js 渲染成图，并可导出为 SVG
（矢量）或 PNG（位图）。

设计约定
--------
- 主页面只放一个源码输入框 + 操作按钮，不常驻预览；
- 渲染结果放在独立模态对话框里，含导出 SVG / PNG 按钮；
- 渲染完全依赖本地 ``static/mermaid.min.js``，离线可用、打包后路径经
  :func:`lib.runtime_paths.find_resource` 定位，不请求外网；
- 导出 SVG：直接取 mermaid 生成的 ``<svg>`` 节点序列化（矢量无损）；
- 导出 PNG：用 ``QtSvg.QSvgRenderer`` 把 SVG 光栅化为位图（不依赖
  WebEngine 视口，离线 / 打包 / 无 GPU 环境都稳定）；
- 导出文件名默认带时间戳，落到 ``store`` 里 ``watermark.output_dir``
  （与图片工具共用输出目录），用户也可在保存对话框里改位置。
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt, QUrl
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from lib import watermark
from lib.runtime_paths import find_resource

#: 默认示例：一个最简 mindmap，方便用户直接点「渲染」看到效果。
DEFAULT_SAMPLE = """mindmap
  root((思维导图))
    核心概念
      密码学
      编码
      逆向
    工具
      Mermaid
      导出
        SVG
        PNG
    使用
      输入语法
      点击渲染
"""


# ---------------------------------------------------------------------------
# 模板库：常用 Mermaid 图示例，供「模板」下拉快速填入。
# 每项 (显示名, 源码)。
# ---------------------------------------------------------------------------
TEMPLATES: tuple[tuple[str, str], ...] = (
    ("思维导图", DEFAULT_SAMPLE),
    ("流程图", """flowchart LR
  A[开始] --> B{是否登录?}
  B -- 是 --> C[进入主页]
  B -- 否 --> D[跳转登录]
  D --> E[输入账号密码]
  E --> B
  C --> F[结束]
"""),
    ("时序图", """sequenceDiagram
  participant U as 用户
  participant S as 服务器
  participant DB as 数据库
  U->>S: 发送请求
  S->>DB: 查询数据
  DB-->>S: 返回结果
  S-->>U: 响应数据
"""),
    ("状态图", """stateDiagram-v2
  [*] --> 待机
  待机 --> 运行: 启动
  运行 --> 暂停: 暂停
  暂停 --> 运行: 继续
  运行 --> 停止: 停止
  停止 --> [*]
"""),
    ("类图", """classDiagram
  class 动物 {
    +名称
    +吃()
  }
  class 狗 {
    +叫()
  }
  动物 <|-- 狗
"""),
    ("甘特图", """gantt
  title 项目计划
  dateFormat YYYY-MM-DD
  section 需求
    需求分析: a1, 2026-01-01, 7d
  section 开发
    编码: a2, after a1, 14d
  section 测试
    测试: a3, after a2, 7d
"""),
    ("饼图", """pie title 占比
  "分类 A" : 40
  "分类 B" : 30
  "分类 C" : 20
  "其他" : 10
"""),
)

#: mermaid 渲染后包裹在页面里的容器（导出时按 id 抓取 SVG）。
_CONTAINER_ID = "mindmap-container"


class _RenderDialog(QDialog):
    """渲染结果弹窗：内嵌 WebEngine 显示思维导图，并支持导出 SVG / PNG。"""

    def __init__(self, theme, store, code: str,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._svg_data: str | None = None
        self.setWindowTitle("思维导图渲染")
        self.resize(900, 640)
        self._build_ui()
        self._render(code)

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        top = QHBoxLayout()
        top.setSpacing(8)
        self.export_svg_btn = QPushButton("导出 SVG")
        self.export_svg_btn.setObjectName("ghbtn")
        self.export_svg_btn.clicked.connect(self._export_svg)
        top.addWidget(self.export_svg_btn)
        self.export_png_btn = QPushButton("导出 PNG")
        self.export_png_btn.setObjectName("ghbtn")
        self.export_png_btn.clicked.connect(self._export_png)
        top.addWidget(self.export_png_btn)
        top.addStretch(1)
        self.status_label = QLabel("")
        self.status_label.setObjectName("status-info")
        self.status_label.setWordWrap(True)
        top.addWidget(self.status_label)
        layout.addLayout(top)

        self.view = QWebEngineView()
        self.view.setContextMenuPolicy(Qt.ContextMenuPolicy.NoContextMenu)
        layout.addWidget(self.view, stretch=1)

    # ------------------------------------------------------------------ 渲染
    def _render(self, code: str) -> None:
        self._set_status(True, "正在渲染…")
        html = self._build_html(code)
        # setHtml 默认 baseUrl 为 about:blank，file:// 子资源（mermaid.js）
        # 会被同源策略拦截，必须显式指定本地目录为 baseUrl 才能加载脚本；
        # baseUrl 必须以目录分隔符结尾，否则相对资源被解析到上一级目录。
        js_path = find_resource("static/mermaid.min.js")
        base_url = (QUrl.fromLocalFile(str(js_path.parent) + "/") if js_path else None)
        self.view.setHtml(html, base_url)
        from PySide6.QtCore import QTimer
        QTimer.singleShot(600, self._collect_svg)

    def _collect_svg(self, attempt: int = 0) -> None:
        """读取渲染好的 SVG；mermaid 异步渲染，最多重试几次。"""
        script = (
            "(() => { const el = document.getElementById('%s'); "
            "return el ? el.innerHTML : ''; })()" % _CONTAINER_ID
        )
        self.view.page().runJavaScript(script, lambda r: self._on_svg_ready(r, attempt))

    def _on_svg_ready(self, result, attempt: int = 0) -> None:
        if not result or "<svg" not in result:
            if attempt < 5:
                from PySide6.QtCore import QTimer
                QTimer.singleShot(300, lambda: self._collect_svg(attempt + 1))
                return
            self._set_status(False, "渲染未生成结果：请检查 Mermaid 语法。")
            return
        self._svg_data = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<svg xmlns="http://www.w3.org/2000/svg" '
            'xmlns:xlink="http://www.w3.org/1999/xlink">\n'
            + result +
            '\n</svg>'
        )
        self._set_status(True, "渲染完成，可导出 SVG / PNG。")

    # ------------------------------------------------------------------ 导出
    def _export_svg(self) -> None:
        if not self._svg_data:
            self._set_status(False, "请先等渲染完成，再导出 SVG。")
            return
        path = self._ask_save_path("SVG 图片 (*.svg)", "svg")
        if not path:
            return
        try:
            Path(path).write_text(self._svg_data, encoding="utf-8")
        except OSError as exc:
            self._set_status(False, f"保存失败：{exc}")
            return
        self._set_status(True, f"已导出 SVG：{path}")

    def _export_png(self) -> None:
        if not self._svg_data:
            self._set_status(False, "请先等渲染完成，再导出 PNG。")
            return
        path = self._ask_save_path("PNG 图片 (*.png)", "png")
        if not path:
            return
        try:
            from PySide6.QtGui import QImage, QPainter
            from PySide6.QtSvg import QSvgRenderer

            renderer = QSvgRenderer(self._svg_data.encode("utf-8"))
            if not renderer.isValid():
                self._set_status(False, "SVG 解析失败，无法导出 PNG。")
                return
            default_size = renderer.defaultSize()
            scale = 2.0
            w = max(1, int(default_size.width() * scale))
            h = max(1, int(default_size.height() * scale))
            image = QImage(w, h, QImage.Format.Format_ARGB32)
            image.fill(0xFFFFFFFF)  # 白底
            painter = QPainter(image)
            renderer.render(painter)
            painter.end()
            if image.save(path):
                self._set_status(True, f"已导出 PNG：{path}")
            else:
                self._set_status(False, f"PNG 保存失败：{path}")
        except Exception as exc:  # noqa: BLE001  导出兜底
            self._set_status(False, f"PNG 导出失败：{exc}")

    def _ask_save_path(self, filter_text: str, ext: str) -> str:
        cfg = self.store.get("watermark", default={}) or {}
        out_dir = watermark.resolve_output_dir(cfg.get("output_dir"))
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default = str(out_dir / f"mindmap_{stamp}.{ext}")
        path, _ = QFileDialog.getSaveFileName(
            self, "导出思维导图", default, filter_text)
        return path

    # ------------------------------------------------------------------ 工具
    def _build_html(self, code: str) -> str:
        escaped = (
            code.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )
        mermaid_theme = "dark" if self.theme.mode == "dark" else "default"
        return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    html, body {{ margin: 0; padding: 0; background: {self.theme.bg}; }}
    #{_CONTAINER_ID} {{ display: inline-block; padding: 12px; }}
  </style>
</head>
<body>
  <pre class="mermaid" id="{_CONTAINER_ID}">{escaped}</pre>
  <script src="mermaid.min.js"></script>
  <script>
    mermaid.initialize({{
      startOnLoad: true,
      theme: '{mermaid_theme}',
      securityLevel: 'loose'
    }});
    mermaid.run({{ querySelector: '.mermaid' }});
  </script>
</body>
</html>"""

    def _set_status(self, ok: bool, text: str) -> None:
        self.status_label.setText(text)
        self.status_label.setObjectName("status-ok" if ok else "status-err")
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)

    # ------------------------------------------------------------------ 生命周期
    def closeEvent(self, event) -> None:  # noqa: N802  Qt 约定
        """关闭时释放 WebEngine 视图，避免残留渲染进程。"""
        try:
            self.view.setHtml("")
        except Exception:  # noqa: BLE001  释放过程兜底
            pass
        super().closeEvent(event)


class MindMapPage(QWidget):
    """思维导图页：单输入框 + 渲染按钮，结果在弹窗里显示。"""

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._dialog: _RenderDialog | None = None
        self._build_ui()

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(10)

        # -- 顶部操作行 --
        actions = QHBoxLayout()
        actions.setSpacing(8)
        self.render_btn = QPushButton("渲染")
        self.render_btn.setObjectName("ghbtn-primary")
        self.render_btn.clicked.connect(self.render_diagram)
        actions.addWidget(self.render_btn)
        self.sample_btn = QPushButton("填入示例")
        self.sample_btn.setObjectName("ghbtn")
        self.sample_btn.clicked.connect(self._fill_sample)
        actions.addWidget(self.sample_btn)

        # 模板下拉：选择一个模板快速填入对应源码
        self.template_combo = QComboBox()
        self.template_combo.addItem("选择模板…")
        for name, _src in TEMPLATES:
            self.template_combo.addItem(name)
        self.template_combo.currentIndexChanged.connect(self._apply_template)
        actions.addWidget(self.template_combo)
        actions.addStretch(1)
        self.status_label = QLabel("")
        self.status_label.setObjectName("status-info")
        self.status_label.setWordWrap(True)
        actions.addWidget(self.status_label)
        layout.addLayout(actions)

        # -- 源码输入（占据全部空间） --
        input_label = QLabel("Mermaid 源码")
        input_label.setObjectName("caption")
        layout.addWidget(input_label)
        self.input_edit = QPlainTextEdit()
        self.input_edit.setObjectName("io")
        self.input_edit.setPlaceholderText(
            "在此粘贴 Mermaid 语法（如 mindmap / graph / flowchart）…")
        self.input_edit.setPlainText(DEFAULT_SAMPLE)
        layout.addWidget(self.input_edit, stretch=1)

    # ------------------------------------------------------------------ 渲染
    def render_diagram(self) -> None:
        """校验输入后弹出渲染结果对话框。"""
        code = self.input_edit.toPlainText()
        if not code.strip():
            self._set_status(False, "请先输入 Mermaid 语法。")
            return
        self._set_status(True, "")
        dialog = _RenderDialog(self.theme, self.store, code, self)
        self._dialog = dialog
        dialog.show()

    def _fill_sample(self) -> None:
        self.input_edit.setPlainText(DEFAULT_SAMPLE)

    def _apply_template(self, index: int) -> None:
        """下拉选择模板时，把对应源码填入输入框（index 0 是占位项）。"""
        if index <= 0:
            return
        name, src = TEMPLATES[index - 1]
        self.input_edit.setPlainText(src)
        self._set_status(True, f"已填入模板「{name}」，点击「渲染」查看。")
        # 填入后复位下拉，方便下次再选其它模板
        self.template_combo.blockSignals(True)
        self.template_combo.setCurrentIndex(0)
        self.template_combo.blockSignals(False)

    def _set_status(self, ok: bool, text: str) -> None:
        self.status_label.setText(text)
        self.status_label.setObjectName("status-ok" if ok else "status-err")
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)

    # ------------------------------------------------------------------ 生命周期
    def set_theme(self, palette) -> None:
        self.theme = palette

    def shutdown(self) -> None:
        """关闭已打开的渲染弹窗（若存在）。"""
        if self._dialog is not None:
            self._dialog.close()
            self._dialog = None
