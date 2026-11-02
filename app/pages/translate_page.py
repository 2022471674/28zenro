# -*- coding: utf-8 -*-
"""智能翻译页（OpenAI 兼容模型服务）。

网络请求跑在 QThread 里，主线程通过信号收结果，不阻塞界面；
模型配置（服务地址 / 模型 / 超时 / API Key / 自定义 Header / 提示词）
从 store 的 ``llm`` 节读取，设置页保存后下次翻译立即生效。
"""

from __future__ import annotations

from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from app.widgets.codec_panel import CodecPanel
from lib import llm_codec, translate_codec


class _TranslateWorker(QThread):
    """后台翻译线程：把结果 / 异常文案经信号抛回主线程。"""

    finished_ok = Signal(str)
    finished_err = Signal(str)

    def __init__(self, text: str, cfg: dict, parent=None) -> None:
        super().__init__(parent)
        self.text = text
        self.cfg = cfg

    def run(self) -> None:  # noqa: D102  线程体
        try:
            result = translate_codec.translate(
                self.text,
                base_url=self.cfg.get("base_url", ""),
                model=self.cfg.get("model", ""),
                timeout=float(self.cfg.get("timeout", 120) or 120),
                api_key=self.cfg.get("api_key") or None,
                system_prompt_zh=self.cfg.get("system_prompt_zh") or None,
                system_prompt_en=self.cfg.get("system_prompt_en") or None,
                headers=llm_codec.parse_headers(self.cfg.get("headers", "")),
            )
        except Exception as exc:  # noqa: BLE001  线程内异常统一转信号
            self.finished_err.emit(str(exc))
            return
        self.finished_ok.emit(result)


class TranslatePage(QWidget):
    """翻译页：输入文本 → 自动判断中英方向 → 输出译文。"""

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._worker: _TranslateWorker | None = None
        self._build()

    def _build(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(12)

        actions = QHBoxLayout()
        actions.setSpacing(8)
        self.translate_btn = QPushButton("翻译（中英自动互译）")
        self.translate_btn.setObjectName("ghbtn-primary")
        self.translate_btn.clicked.connect(self._start)
        actions.addWidget(self.translate_btn)
        actions.addStretch(1)
        layout.addLayout(actions)

        self.status_label = QLabel("")
        self.status_label.setObjectName("caption")
        layout.addWidget(self.status_label)

        self.panel = CodecPanel(self.theme)
        layout.addWidget(self.panel, stretch=1)

    def _start(self) -> None:
        text = self.panel.get_input()
        if not text.strip():
            return
        if self._worker is not None and self._worker.isRunning():
            return  # 上一次翻译尚未结束

        cfg = self.store.get("llm", default={}) or {}
        self.translate_btn.setEnabled(False)
        self.status_label.setText(self.theme.UI_TRANSLATING)

        self._worker = _TranslateWorker(text, cfg, self)
        self._worker.finished_ok.connect(self._on_ok)
        self._worker.finished_err.connect(self._on_err)
        self._worker.start()

    def _on_ok(self, result: str) -> None:
        self.translate_btn.setEnabled(True)
        self.status_label.setText("")
        self.panel.set_output(result)

    def _on_err(self, reason: str) -> None:
        self.translate_btn.setEnabled(True)
        self.status_label.setText(reason)
        self.panel.set_output(f"[{self.theme.UI_TRANSLATE_FAILED}] {reason}")
