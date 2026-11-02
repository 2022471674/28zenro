# -*- coding: utf-8 -*-
"""Markdown 编辑页（编辑 + 渲染 + 导出）。

接受用户输入的 Markdown 文本，点击「渲染」后弹出独立对话框，用本地
``markdown`` 库渲染成 HTML 并内嵌 WebEngine 预览，支持导出 HTML / PDF /
Word（.doc，HTML 格式，Word 可直接打开）。

设计约定
--------
- 主页面只放一个源码输入框 + 操作按钮，不常驻预览（与思维导图页一致）；
- 渲染结果放在独立模态对话框里，含导出 HTML / PDF / Word 按钮；
- Markdown → HTML 用 Python 标准 ``markdown`` 库（本地渲染，不请求外网，
  离线可用），扩展启用 ``extra`` / ``tables`` / ``fenced_code`` / ``toc``；
- 导出 HTML：渲染后的 HTML 写成独立 ``.html``（内嵌基础样式）；
- 导出 PDF：WebEngine 预览页 ``printToPdf`` 直接打印成 PDF；
- 导出 Word：无 ``python-docx`` / ``pandoc`` 依赖时，把 HTML 内容写成
  ``.doc``（Word 兼容的 HTML 文档），保证无第三方依赖也能导出；
- 导出文件名默认带时间戳，落到 ``store`` 里 ``watermark.output_dir``
  （与图片 / 思维导图工具共用输出目录），用户也可在保存对话框里改位置。
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt, QUrl
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWidgets import (
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
from lib.runtime_paths import data_root

#: 默认示例：一段覆盖常见语法的 Markdown，方便用户直接点「渲染」看效果。
DEFAULT_SAMPLE = """# Markdown 编辑器

欢迎使用 **28zenro** 的 Markdown 工具。

## 功能

- 编辑 Markdown 源码
- 实时渲染预览（代码高亮 + 行号）
- 导出 HTML / PDF / Word

## 代码示例

```python
import hashlib


def md5(text: str) -> str:
    # 计算 MD5 摘要
    return hashlib.md5(text.encode()).hexdigest()


if __name__ == "__main__":
    print(md5("28zenro"))  # 输出 32 位十六进制
```

## 表格

| 名称 | 说明 |
| ---- | ---- |
| HTML | 网页文档 |
| PDF  | 打印文档 |
| DOC  | Word 文档 |

> 引用：点击「渲染」查看效果。
"""

#: markdown 扩展集（本地渲染，离线可用）。
_MD_EXTENSIONS = ["extra", "tables", "fenced_code", "toc", "sane_lists"]

#: HTML 导出时包裹的基础样式（内联，无外部资源）。
#: 亮色 / 暗色通过 CSS 变量（``--md-*``）切换，代码块行号 / 语言徽标由
#: :data:`_POST_SCRIPT` 里的 JS 后处理生成。
_BASE_CSS = """
:root {
  --md-bg: #ffffff;
  --md-fg: #24292f;
  --md-muted: #57606a;
  --md-border: #dfe2e5;
  --md-border-soft: #eaecef;
  --md-code-bg: #f6f8fa;
  --md-code-fg: #24292f;
  --md-block-bg: #f6f8fa;
  --md-block-border: #e1e4e8;
  --md-heading-rule: #eaecef;
  --md-th-bg: #f6f8fa;
  --md-link: #0969da;
  --md-quote-bar: #dfe2e5;
  --md-gutter-fg: #8c959f;
  --md-gutter-bg: #f0f3f6;
  --md-lang-badge-bg: #eaeef2;
  --md-lang-badge-fg: #57606a;
  --md-scrollbar: #d0d7de;
  --md-scrollbar-hover: #b6bec7;
  --md-hl-keyword: #cf222e;
  --md-hl-string: #0a3069;
  --md-hl-comment: #6e7781;
  --md-hl-number: #0550ae;
  --md-hl-func: #8250df;
  --md-hl-builtin: #953800;
}
body[data-md-theme="dark"] {
  --md-bg: #0d1117;
  --md-fg: #c9d1d9;
  --md-muted: #8b949e;
  --md-border: #30363d;
  --md-border-soft: #21262d;
  --md-code-bg: #161b22;
  --md-code-fg: #e6edf3;
  --md-block-bg: #161b22;
  --md-block-border: #30363d;
  --md-heading-rule: #30363d;
  --md-th-bg: #161b22;
  --md-link: #58a6ff;
  --md-quote-bar: #30363d;
  --md-gutter-fg: #6e7681;
  --md-gutter-bg: #161b22;
  --md-lang-badge-bg: #21262d;
  --md-lang-badge-fg: #8b949e;
  --md-scrollbar: #30363d;
  --md-scrollbar-hover: #484f58;
  --md-hl-keyword: #ff7b72;
  --md-hl-string: #a5d6ff;
  --md-hl-comment: #8b949e;
  --md-hl-number: #79c0ff;
  --md-hl-func: #d2a8ff;
  --md-hl-builtin: #ffa657;
}
* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
  margin: 2rem auto;
  max-width: 900px;
  padding: 0 1.5rem;
  font-family: -apple-system, "Segoe UI", "Microsoft YaHei", "PingFang SC",
               sans-serif;
  line-height: 1.7;
  color: var(--md-fg);
  background: var(--md-bg);
  word-wrap: break-word;
}
h1, h2, h3, h4, h5, h6 {
  font-weight: 600;
  line-height: 1.25;
  margin-top: 1.5em;
  margin-bottom: 0.6em;
}
h1 { font-size: 2em; }
h2 { font-size: 1.5em; }
h3 { font-size: 1.25em; }
h4 { font-size: 1em; }
h1, h2 {
  border-bottom: 1px solid var(--md-heading-rule);
  padding-bottom: 0.3em;
}
p { margin: 0.6em 0; }
a { color: var(--md-link); text-decoration: none; }
a:hover { text-decoration: underline; }

/* ---- 行内代码 ---- */
code {
  background: var(--md-code-bg);
  color: var(--md-code-fg);
  padding: 0.15em 0.4em;
  border-radius: 4px;
  font-family: "JetBrains Mono", "Cascadia Code", Consolas, "Courier New", monospace;
  font-size: 0.875em;
}

/* ---- 代码块（含行号 / 语言徽标） ---- */
pre {
  position: relative;
  margin: 1em 0;
  border: 1px solid var(--md-block-border);
  border-radius: 8px;
  background: var(--md-block-bg);
  overflow: hidden;
}
pre code {
  display: block;
  background: none;
  padding: 1em 1.2em;
  overflow-x: auto;
  font-size: 0.875em;
  line-height: 1.55;
  tab-size: 4;
}
pre code::-webkit-scrollbar,
pre::-webkit-scrollbar {
  height: 10px;
  width: 10px;
}
pre code::-webkit-scrollbar-thumb,
pre::-webkit-scrollbar-thumb {
  background: var(--md-scrollbar);
  border-radius: 5px;
}
pre code::-webkit-scrollbar-thumb:hover,
pre::-webkit-scrollbar-thumb:hover {
  background: var(--md-scrollbar-hover);
}

/* 带行号时：横向滚动体为 code，纵向用 pre 的容器高度自然撑开 */
pre.md-lineno code {
  padding-left: 0.6em;
}
.md-line {
  display: table-row;
}
.md-line > .md-ln {
  display: table-cell;
  text-align: right;
  padding-right: 1em;
  padding-left: 0.8em;
  color: var(--md-gutter-fg);
  background: var(--md-gutter-bg);
  border-right: 1px solid var(--md-block-border);
  user-select: none;
  -webkit-user-select: none;
  min-width: 2.5em;
  white-space: nowrap;
}
.md-line > .md-txt {
  display: table-cell;
  padding-left: 1em;
  white-space: pre;
}
pre.md-lineno code {
  display: table;
  border-collapse: collapse;
  padding: 0;
}

/* 语言徽标 */
.md-lang {
  position: absolute;
  top: 0;
  right: 0;
  padding: 2px 8px;
  font-size: 0.72em;
  font-family: "JetBrains Mono", Consolas, monospace;
  color: var(--md-lang-badge-fg);
  background: var(--md-lang-badge-bg);
  border-bottom-left-radius: 6px;
  opacity: 0.85;
  user-select: none;
}

/* 复制按钮 */
.md-copy {
  position: absolute;
  top: 6px;
  right: 6px;
  padding: 3px 9px;
  font-size: 0.72em;
  color: var(--md-muted);
  background: var(--md-lang-badge-bg);
  border: 1px solid var(--md-block-border);
  border-radius: 5px;
  cursor: pointer;
  opacity: 0;
  transition: opacity 0.15s ease;
}
pre:hover .md-copy { opacity: 1; }
.md-copy:hover { color: var(--md-fg); }

/* ---- 表格 ---- */
table {
  border-collapse: collapse;
  margin: 1em 0;
  display: block;
  overflow-x: auto;
}
th, td {
  border: 1px solid var(--md-border);
  padding: 0.45em 0.9em;
}
th { background: var(--md-th-bg); font-weight: 600; }
tr:nth-child(even) td { background: var(--md-th-bg); }

/* ---- 引用 ---- */
blockquote {
  border-left: 4px solid var(--md-quote-bar);
  margin: 1em 0;
  padding: 0.2em 1em;
  color: var(--md-muted);
}

/* ---- 列表 ---- */
ul, ol { padding-left: 2em; }
li { margin: 0.25em 0; }
li > input[type="checkbox"] { margin-right: 0.4em; }

/* ---- 图片 / 分隔线 ---- */
img { max-width: 100%; border-radius: 6px; }
hr { border: none; border-top: 2px solid var(--md-border-soft); margin: 2em 0; }
"""


#: JS 后处理：给代码块加行号、语言徽标、复制按钮，并高亮关键字。
_POST_SCRIPT = r"""
(function () {
  function esc(s) {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }
  // 轻量关键字高亮（常见语言，避免引入外部高亮库，离线可用）
  var KEYWORDS = [
    'def','return','class','import','from','if','else','elif','for','while',
    'try','except','finally','with','as','lambda','pass','break','continue',
    'None','True','False','and','or','not','in','is','print','yield','raise',
    'async','await','new','function','const','let','var','public','private',
    'static','void','int','str','bool','list','dict','tuple','set'
  ];
  var STRING_RE = /("[^"]*"|'[^']*'|`[^`]*`)/g;
  var COMMENT_RE = /(#[^\n]*|\/\/[^\n]*)/g;
  var NUMBER_RE = /\b(\d+(?:\.\d+)?)\b/g;
  var FUNC_RE = /\b([A-Za-z_][A-Za-z0-9_]*)(?=\()/g;

  function highlightLine(line, lang) {
    var out = esc(line);
    // 占位符保护：先把注释 / 字符串替换成唯一占位符，避免后续关键字 /
    // 数字正则匹配到已生成的 <span> 标签文本导致嵌套错乱。
    var protectedTokens = [];
    out = out.replace(COMMENT_RE, function (m) {
      var ph = '\u0000CMT' + protectedTokens.length + '\u0000';
      protectedTokens.push('<span class="tok-comment">' + m + '</span>');
      return ph;
    });
    out = out.replace(STRING_RE, function (m) {
      var ph = '\u0000STR' + protectedTokens.length + '\u0000';
      protectedTokens.push('<span class="tok-string">' + m + '</span>');
      return ph;
    });
    // 关键字
    var kwRe = new RegExp('\\b(' + KEYWORDS.join('|') + ')\\b', 'g');
    out = out.replace(kwRe, '<span class="tok-keyword">$1</span>');
    // 数字
    out = out.replace(NUMBER_RE, '<span class="tok-number">$1</span>');
    // 函数调用
    out = out.replace(FUNC_RE, '<span class="tok-func">$1</span>');
    // 还原占位符
    protectedTokens.forEach(function (tok, i) {
      out = out.replace('\u0000CMT' + i + '\u0000', tok);
      out = out.replace('\u0000STR' + i + '\u0000', tok);
    });
    return out;
  }

  var pres = document.querySelectorAll('pre');
  pres.forEach(function (pre) {
    var code = pre.querySelector('code');
    if (!code) return;
    var classes = (code.className || '').split(/\s+/);
    var lang = '';
    classes.forEach(function (c) {
      var m = c.match(/^language-(.+)$/);
      if (m) lang = m[1];
    });
    var raw = code.textContent;
    // 去尾部多余换行
    raw = raw.replace(/\n$/, '');
    var lines = raw.split('\n');

    // 语言徽标
    if (lang) {
      var badge = document.createElement('span');
      badge.className = 'md-lang';
      badge.textContent = lang;
      pre.appendChild(badge);
    }
    // 复制按钮
    var btn = document.createElement('button');
    btn.className = 'md-copy';
    btn.type = 'button';
    btn.textContent = '复制';
    btn.addEventListener('click', function () {
      var t = raw;
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(t).then(function () {
          btn.textContent = '已复制'; setTimeout(function(){ btn.textContent='复制'; }, 1200);
        });
      } else {
        var ta = document.createElement('textarea');
        ta.value = t; document.body.appendChild(ta); ta.select();
        try { document.execCommand('copy'); btn.textContent='已复制'; } catch(e) {}
        document.body.removeChild(ta);
        setTimeout(function(){ btn.textContent='复制'; }, 1200);
      }
    });
    pre.appendChild(btn);

    // 行号：多行才加行号，单行只高亮
    if (lines.length > 1) {
      pre.classList.add('md-lineno');
      var html = '';
      for (var i = 0; i < lines.length; i++) {
        var n = String(i + 1);
        html += '<span class="md-line"><span class="md-ln">' + n + '</span>' +
                '<span class="md-txt">' + highlightLine(lines[i], lang) +
                '</span></span>';
      }
      code.innerHTML = html;
    } else {
      code.innerHTML = highlightLine(lines[0] || '', lang);
    }
  });
})();
"""


#: 高亮 token 的颜色（亮色 / 暗色由 CSS 变量控制）。
_TOKEN_CSS = """
.tok-keyword { color: var(--md-hl-keyword); font-weight: 500; }
.tok-string  { color: var(--md-hl-string); }
.tok-comment { color: var(--md-hl-comment); font-style: italic; }
.tok-number  { color: var(--md-hl-number); }
.tok-func    { color: var(--md-hl-func); }
"""


class _RenderDialog(QDialog):
    """渲染结果弹窗：内嵌 WebEngine 显示 Markdown 渲染结果，并支持导出。"""

    def __init__(self, theme, store, code: str,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._html_body: str = ""
        self.setWindowTitle("Markdown 渲染")
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
        self.export_html_btn = QPushButton("导出 HTML")
        self.export_html_btn.setObjectName("ghbtn")
        self.export_html_btn.clicked.connect(self._export_html)
        top.addWidget(self.export_html_btn)
        self.export_pdf_btn = QPushButton("导出 PDF")
        self.export_pdf_btn.setObjectName("ghbtn")
        self.export_pdf_btn.clicked.connect(self._export_pdf)
        top.addWidget(self.export_pdf_btn)
        self.export_word_btn = QPushButton("导出 Word")
        self.export_word_btn.setObjectName("ghbtn")
        self.export_word_btn.clicked.connect(self._export_word)
        top.addWidget(self.export_word_btn)
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
        import markdown

        self._set_status(True, "正在渲染…")
        try:
            self._html_body = markdown.markdown(
                code, extensions=_MD_EXTENSIONS)
        except Exception as exc:  # noqa: BLE001  markdown 渲染兜底
            self._set_status(False, f"渲染失败：{exc}")
            return
        self.view.setHtml(self._build_html(self._html_body))
        self._set_status(True, "渲染完成，可导出 HTML / PDF / Word。")

    # ------------------------------------------------------------------ 导出
    def _export_html(self) -> None:
        if not self._html_body:
            self._set_status(False, "请先等渲染完成，再导出。")
            return
        path = self._ask_save_path("HTML 文档 (*.html)", "html")
        if not path:
            return
        try:
            Path(path).write_text(self._build_html(self._html_body),
                                  encoding="utf-8")
        except OSError as exc:
            self._set_status(False, f"保存失败：{exc}")
            return
        self._set_status(True, f"已导出 HTML：{path}")

    def _export_pdf(self) -> None:
        if not self._html_body:
            self._set_status(False, "请先等渲染完成，再导出。")
            return
        path = self._ask_save_path("PDF 文档 (*.pdf)", "pdf")
        if not path:
            return
        self._set_status(True, "正在导出 PDF…")
        try:
            self.view.printToPdf(path)
        except Exception as exc:  # noqa: BLE001  PDF 导出兜底
            self._set_status(False, f"PDF 导出失败：{exc}")
            return
        self._set_status(True, f"已导出 PDF：{path}")

    def _export_word(self) -> None:
        if not self._html_body:
            self._set_status(False, "请先等渲染完成，再导出。")
            return
        # 优先用 python-docx（若已安装）生成真正的 .docx；否则降级为
        # HTML 格式的 .doc（Word / WPS 均可直接打开，无第三方依赖）。
        try:
            import docx  # noqa: F401  探测是否可用
            use_docx = True
        except ImportError:
            use_docx = False

        if use_docx:
            path = self._ask_save_path("Word 文档 (*.docx)", "docx")
            if not path:
                return
            self._export_docx(path)
        else:
            path = self._ask_save_path("Word 文档 (*.doc)", "doc")
            if not path:
                return
            self._export_doc_html(path)

    def _export_docx(self, path: str) -> None:
        """用 python-docx 生成 .docx（按标题 / 段落 / 列表 / 代码块简化转换）。"""
        try:
            import re

            import docx
            from docx.shared import Pt

            doc = docx.Document()
            body = self._html_body
            # 极简 HTML→docx：逐行按标签粗判断（够用即可，完整解析留给 markdown 库）。
            # 这里按 markdown 源码更可靠，但我们只存了 HTML；改为按行启发式。
            lines = body.splitlines()
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                # 标题
                m = re.match(r"^<h([1-6])>(.*)</h\1>$", line)
                if m:
                    level = int(m.group(1))
                    text = _strip_tags(m.group(2))
                    doc.add_heading(text, level=level)
                    continue
                # 代码块外的行：去标签
                text = _strip_tags(line)
                if text:
                    doc.add_paragraph(text)
            doc.save(path)
        except Exception as exc:  # noqa: BLE001
            self._set_status(False, f"Word 导出失败：{exc}")
            return
        self._set_status(True, f"已导出 Word：{path}")

    def _export_doc_html(self, path: str) -> None:
        """无 docx 依赖时：把 HTML 写成 .doc（Word 兼容），保证可导出。"""
        try:
            Path(path).write_text(self._build_html(self._html_body),
                                  encoding="utf-8")
        except OSError as exc:
            self._set_status(False, f"保存失败：{exc}")
            return
        self._set_status(True, f"已导出 Word：{path}")

    def _ask_save_path(self, filter_text: str, ext: str) -> str:
        cfg = self.store.get("watermark", default={}) or {}
        out_dir = watermark.resolve_output_dir(cfg.get("output_dir"))
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default = str(out_dir / f"markdown_{stamp}.{ext}")
        path, _ = QFileDialog.getSaveFileName(
            self, "导出 Markdown", default, filter_text)
        return path

    # ------------------------------------------------------------------ 工具
    def _build_html(self, body: str) -> str:
        theme_mode = getattr(self.theme, "mode", "light")
        is_dark = theme_mode == "dark"
        return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <style>{_BASE_CSS}
  {_TOKEN_CSS}
  </style>
</head>
<body data-md-theme="{'dark' if is_dark else 'light'}">
{body}
<script>{_POST_SCRIPT}</script>
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


def _strip_tags(html: str) -> str:
    """去掉简单 HTML 标签（用于 docx 文本转换）。"""
    import re

    text = re.sub(r"<[^>]+>", "", html)
    import html as _html

    return _html.unescape(text).strip()


class MarkdownPage(QWidget):
    """Markdown 编辑页：单输入框 + 渲染按钮，结果在弹窗里显示。"""

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

        actions = QHBoxLayout()
        actions.setSpacing(8)
        self.render_btn = QPushButton("渲染")
        self.render_btn.setObjectName("ghbtn-primary")
        self.render_btn.clicked.connect(self.render_markdown)
        actions.addWidget(self.render_btn)
        self.sample_btn = QPushButton("填入示例")
        self.sample_btn.setObjectName("ghbtn")
        self.sample_btn.clicked.connect(self._fill_sample)
        actions.addWidget(self.sample_btn)
        actions.addStretch(1)
        self.status_label = QLabel("")
        self.status_label.setObjectName("status-info")
        self.status_label.setWordWrap(True)
        actions.addWidget(self.status_label)
        layout.addLayout(actions)

        input_label = QLabel("Markdown 源码")
        input_label.setObjectName("caption")
        layout.addWidget(input_label)
        self.input_edit = QPlainTextEdit()
        self.input_edit.setObjectName("io")
        self.input_edit.setPlaceholderText(
            "在此输入 Markdown 文本（标题 / 列表 / 表格 / 代码块…）")
        self.input_edit.setPlainText(DEFAULT_SAMPLE)
        layout.addWidget(self.input_edit, stretch=1)

    # ------------------------------------------------------------------ 渲染
    def render_markdown(self) -> None:
        """校验输入后弹出渲染结果对话框。"""
        code = self.input_edit.toPlainText()
        if not code.strip():
            self._set_status(False, "请先输入 Markdown 内容。")
            return
        self._set_status(True, "")
        dialog = _RenderDialog(self.theme, self.store, code, self)
        self._dialog = dialog
        dialog.show()

    def _fill_sample(self) -> None:
        self.input_edit.setPlainText(DEFAULT_SAMPLE)

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
