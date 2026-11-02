# -*- coding: utf-8 -*-
"""哈希长度扩展攻击页：伪造 md5/sha1/sha256(secret||data) 的 MAC。

输入原始摘要、原始数据、追加内容与 secret 长度，纯 Python 实现 MD5 / SHA1 /
SHA256 的 padding 与压缩函数（见 :mod:`lib.hash_ext`），无需知道 secret 即可
推算出 ``H(secret || data || padding || append)`` 的新摘要与完整伪造消息。

用于 CTF / 授权测试中的 MAC 伪造演示，请勿用于未授权目标。
"""

from __future__ import annotations

from PySide6.QtWidgets import (
    QApplication,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from app.widgets.no_wheel import NoWheelComboBox, NoWheelSpinBox
from lib import hash_ext


class HashExtPage(QWidget):
    """哈希长度扩展攻击页。"""

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._build_ui()

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        outer.addWidget(scroll)

        container = QWidget()
        scroll.setWidget(container)
        layout = QVBoxLayout(container)
        layout.setContentsMargins(36, 28, 36, 28)
        layout.setSpacing(10)

        form = QFormLayout()
        form.setHorizontalSpacing(16)
        form.setVerticalSpacing(8)

        self.algo_combo = NoWheelComboBox()
        for key, label in (("md5", "MD5（32 位）"),
                           ("sha1", "SHA1（40 位）"),
                           ("sha256", "SHA256（64 位）")):
            self.algo_combo.addItem(label, key)
        form.addRow("哈希算法", self.algo_combo)

        self.hash_edit = QLineEdit()
        self.hash_edit.setPlaceholderText("原始摘要 H(secret||data) 的十六进制")
        form.addRow("原始摘要", self.hash_edit)

        self.data_edit = QLineEdit()
        self.data_edit.setPlaceholderText("公开的消息 data（如 count=10&user=1）")
        form.addRow("原始数据 data", self.data_edit)

        self.append_edit = QLineEdit()
        self.append_edit.setPlaceholderText("要追加的内容（如 &admin=true）")
        form.addRow("追加内容 append", self.append_edit)

        self.secret_len_spin = NoWheelSpinBox()
        self.secret_len_spin.setRange(0, 1_000_000)
        self.secret_len_spin.setValue(0)
        form.addRow("secret 长度（字节）", self.secret_len_spin)

        layout.addLayout(form)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        self.run_btn = QPushButton("执行长度扩展")
        self.run_btn.setObjectName("ghbtn-primary")
        self.run_btn.clicked.connect(self._run)
        buttons.addWidget(self.run_btn)
        clear_btn = QPushButton("清空")
        clear_btn.setObjectName("ghbtn")
        clear_btn.clicked.connect(self._clear)
        buttons.addWidget(clear_btn)
        copy_btn = QPushButton("复制结果")
        copy_btn.setObjectName("ghbtn")
        copy_btn.clicked.connect(self._copy)
        buttons.addWidget(copy_btn)
        buttons.addStretch(1)
        layout.addLayout(buttons)

        layout.addWidget(self._section("结果"))
        self.result_view = QPlainTextEdit()
        self.result_view.setObjectName("io")
        self.result_view.setReadOnly(True)
        self.result_view.setPlaceholderText(
            "点击「执行长度扩展」后，这里显示伪造摘要与新消息…")
        self.result_view.setMinimumHeight(220)
        layout.addWidget(self.result_view, stretch=1)

        self.status_label = QLabel("")
        self.status_label.setObjectName("status-info")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

    # ------------------------------------------------------------------ 小部件
    @staticmethod
    def _section(text: str) -> QLabel:
        label = QLabel(text)
        label.setObjectName("section")
        return label

    # ------------------------------------------------------------------ 操作
    def _run(self) -> None:
        algo = self.algo_combo.currentData()
        original_hash = self.hash_edit.text().strip()
        data = self.data_edit.text()
        append = self.append_edit.text()
        secret_len = self.secret_len_spin.value()

        if not original_hash:
            self._set_status(False, "请填写原始摘要。")
            return

        try:
            result = hash_ext.length_extend_full(
                algo, original_hash, data, append, secret_len)
        except hash_ext.HashExtError as exc:
            self._set_status(False, f"长度扩展失败：{exc}")
            return
        except Exception as exc:  # noqa: BLE001
            self._set_status(False, f"长度扩展失败：{exc}")
            return

        new_msg = result["new_message"]
        # 若 data 为空，new_message 只含 padding+append，也一并展示
        lines = [
            f"算法：{algo.upper()}",
            f"伪造摘要（hex）：{result['new_hash']}",
            "",
            f"新消息体（data || padding || append，hex）：",
            new_msg,
            "",
            "说明：把「原始 data + 新消息体」发送给服务端（即 data||padding||append），",
            "服务端计算 H(secret||data||padding||append) 即为上面的伪造摘要。",
        ]
        self.result_view.setPlainText("\n".join(lines))
        self._set_status(True, "长度扩展完成。")

    def _clear(self) -> None:
        self.hash_edit.clear()
        self.data_edit.clear()
        self.append_edit.clear()
        self.secret_len_spin.setValue(0)
        self.result_view.clear()
        self._set_status(True, "")

    def _copy(self) -> None:
        text = self.result_view.toPlainText().strip()
        if not text:
            self._set_status(False, "还没有可复制的结果。")
            return
        QApplication.clipboard().setText(text)
        self._set_status(True, "已复制结果到剪贴板。")

    # ------------------------------------------------------------------ 输出
    def _set_status(self, ok: bool, text: str) -> None:
        self.status_label.setText(text)
        self.status_label.setObjectName("status-ok" if ok else "status-err")
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)

    def shutdown(self) -> None:
        pass
