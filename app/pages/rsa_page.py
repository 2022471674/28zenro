# -*- coding: utf-8 -*-
"""RSA / 大整数攻击页（独立页面）：分解 / RSA 恢复 / 常见攻击 / 基础运算。

四个子标签覆盖 CTF 密码学中 RSA 与大整数的常见攻击，算法全部委托
``lib.rsa_attack``（纯标准库实现，无第三方依赖），本页不含任何密码学代码：

- **大整数分解**：试除法 / Fermat / Pollard's rho / p-1 综合分解；
- **RSA 恢复**：已知 p、q、e 恢复 d 与 PEM 私钥；已知 n、e、d 反推 p、q；
- **RSA 攻击**：共模攻击、低加密指数、Wiener 攻击、Hastad 广播攻击；
- **基础运算**：模逆、CRT、欧拉函数、gcd/lcm、快速幂、整数开方、素性判定。

所有数值输入均支持十进制或十六进制（可带 ``0x`` 前缀，含 a-f 字母自动按
十六进制解析）。耗时的分解运算放后台线程执行，界面不阻塞，可随时停止。
"""

from __future__ import annotations

import threading

from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from lib import rsa_attack


class _RsaWorker(QThread):
    """后台执行一次 RSA 运算（可停止），结果 / 错误经信号回传。"""

    done = Signal(object, str)

    def __init__(self, fn, parent=None) -> None:
        super().__init__(parent)
        self._fn = fn

    def run(self) -> None:  # noqa: D102  线程体
        try:
            result = self._fn()
        except Exception as exc:  # noqa: BLE001  统一转信号给界面
            self.done.emit(None, str(exc))
        else:
            self.done.emit(result, "")


def _io(readonly: bool = False, height: int = 96) -> QPlainTextEdit:
    area = QPlainTextEdit()
    area.setObjectName("io")
    area.setReadOnly(readonly)
    area.setMinimumHeight(height)
    return area


def _section(text: str) -> QLabel:
    label = QLabel(text)
    label.setObjectName("section")
    return label


def _status() -> QLabel:
    label = QLabel("")
    label.setObjectName("status-info")
    label.setWordWrap(True)
    return label


def _set_status(label: QLabel, ok: bool | None, text: str) -> None:
    label.setObjectName(
        "status-info" if ok is None else ("status-ok" if ok else "status-err"))
    label.setText(text)
    label.style().unpolish(label)
    label.style().polish(label)


def _copy(text: str) -> None:
    if text:
        QApplication.clipboard().setText(text)


class RsaPage(QWidget):
    """RSA / 大整数攻击页。"""

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._workers: set = set()
        self._build()

    # ------------------------------------------------------------------ UI
    def _build(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(10)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_factor_tab(), "大整数分解")
        self.tabs.addTab(self._build_recover_tab(), "RSA 恢复")
        self.tabs.addTab(self._build_attack_tab(), "RSA 攻击")
        self.tabs.addTab(self._build_basic_tab(), "基础运算")
        layout.addWidget(self.tabs, stretch=1)

    # ---- Tab 1：大整数分解 ------------------------------------------------
    def _build_factor_tab(self) -> QWidget:
        inner = QWidget()
        layout = QVBoxLayout(inner)
        layout.setContentsMargins(8, 14, 8, 8)
        layout.setSpacing(8)

        layout.addWidget(_section("待分解的大整数 n（十进制或十六进制）"))
        self.factor_input = _io(height=72)
        self.factor_input.setPlaceholderText(
            "输入要分解的整数，如 3233 或 0xca1（RSA 的模数 n）…")
        layout.addWidget(self.factor_input)

        opt = QHBoxLayout()
        opt.setSpacing(8)
        opt.addWidget(self._label("算法"))
        self.factor_mode = QLineEdit()
        # 用复选框表达各算法的开关更直观，但为简洁用固定组合说明
        self.factor_fermat = QCheckBox("Fermat")
        self.factor_fermat.setChecked(True)
        self.factor_prho = QCheckBox("Pollard's rho")
        self.factor_prho.setChecked(True)
        self.factor_pm1 = QCheckBox("Pollard's p-1")
        self.factor_pm1.setChecked(True)
        opt.addWidget(self.factor_fermat)
        opt.addWidget(self.factor_prho)
        opt.addWidget(self.factor_pm1)
        opt.addStretch(1)
        layout.addLayout(opt)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        self.factor_run = QPushButton("分解")
        self.factor_run.setObjectName("ghbtn-primary")
        self.factor_run.clicked.connect(self._do_factor)
        self.factor_stop = QPushButton("停止")
        self.factor_stop.setObjectName("ghbtn")
        self.factor_stop.setEnabled(False)
        self.factor_stop.clicked.connect(self._stop_all)
        clear = QPushButton("清空")
        clear.setObjectName("ghbtn")
        clear.clicked.connect(
            lambda: (self.factor_input.clear(), self.factor_output.clear(),
                     _set_status(self.factor_status, None, "")))
        copy_btn = QPushButton("复制结果")
        copy_btn.setObjectName("ghbtn")
        copy_btn.clicked.connect(lambda: _copy(self.factor_output.toPlainText()))
        buttons.addWidget(self.factor_run)
        buttons.addWidget(self.factor_stop)
        buttons.addWidget(clear)
        buttons.addStretch(1)
        buttons.addWidget(copy_btn)
        layout.addLayout(buttons)

        layout.addWidget(_section("质因子（含重数，升序）"))
        self.factor_output = _io(readonly=True, height=120)
        layout.addWidget(self.factor_output)

        self.factor_status = _status()
        layout.addWidget(self.factor_status)
        return self._wrap(inner)

    # ---- Tab 2：RSA 恢复 --------------------------------------------------
    def _build_recover_tab(self) -> QWidget:
        inner = QWidget()
        layout = QVBoxLayout(inner)
        layout.setContentsMargins(8, 14, 8, 8)
        layout.setSpacing(8)

        layout.addWidget(_section("方式一：已知 p、q、e → 恢复 d 与 PEM 私钥"))
        row1 = QHBoxLayout()
        row1.setSpacing(8)
        row1.addWidget(self._label("p"))
        self.rec_p = QLineEdit()
        row1.addWidget(self.rec_p, stretch=1)
        row1.addWidget(self._label("q"))
        self.rec_q = QLineEdit()
        row1.addWidget(self.rec_q, stretch=1)
        row1.addWidget(self._label("e"))
        self.rec_e = QLineEdit()
        self.rec_e.setText("65537")
        row1.addWidget(self.rec_e, stretch=1)
        layout.addLayout(row1)

        btn1 = QHBoxLayout()
        btn1.setSpacing(8)
        self.rec_run = QPushButton("恢复 d / 私钥")
        self.rec_run.setObjectName("ghbtn-primary")
        self.rec_run.clicked.connect(self._do_recover)
        btn1.addWidget(self.rec_run)
        btn1.addStretch(1)
        layout.addLayout(btn1)

        layout.addWidget(_section("方式二：已知 n、e、d → 反推 p、q"))
        row2 = QHBoxLayout()
        row2.setSpacing(8)
        row2.addWidget(self._label("n"))
        self.rec_n = QLineEdit()
        row2.addWidget(self.rec_n, stretch=1)
        row2.addWidget(self._label("e"))
        self.rec_e2 = QLineEdit()
        self.rec_e2.setText("65537")
        row2.addWidget(self.rec_e2, stretch=1)
        row2.addWidget(self._label("d"))
        self.rec_d = QLineEdit()
        row2.addWidget(self.rec_d, stretch=1)
        layout.addLayout(row2)

        btn2 = QHBoxLayout()
        btn2.setSpacing(8)
        self.rec_pq_run = QPushButton("反推 p、q")
        self.rec_pq_run.setObjectName("ghbtn")
        self.rec_pq_run.clicked.connect(self._do_recover_pq)
        clear = QPushButton("清空")
        clear.setObjectName("ghbtn")
        clear.clicked.connect(
            lambda: (self.rec_p.clear(), self.rec_q.clear(), self.rec_e.clear(),
                     self.rec_n.clear(), self.rec_e2.clear(), self.rec_d.clear(),
                     self.rec_output.clear(),
                     _set_status(self.rec_status, None, "")))
        btn2.addWidget(self.rec_pq_run)
        btn2.addWidget(clear)
        btn2.addStretch(1)
        layout.addLayout(btn2)

        layout.addWidget(_section("结果"))
        self.rec_output = _io(readonly=True, height=160)
        layout.addWidget(self.rec_output)

        self.rec_status = _status()
        layout.addWidget(self.rec_status)
        return self._wrap(inner)

    # ---- Tab 3：RSA 攻击 --------------------------------------------------
    def _build_attack_tab(self) -> QWidget:
        inner = QWidget()
        layout = QVBoxLayout(inner)
        layout.setContentsMargins(8, 14, 8, 8)
        layout.setSpacing(8)

        layout.addWidget(_section("共模攻击（同一 m，不同 e1/e2，同 n）"))
        r1 = QHBoxLayout()
        r1.setSpacing(8)
        r1.addWidget(self._label("c1"))
        self.atk_c1 = QLineEdit()
        r1.addWidget(self.atk_c1, stretch=1)
        r1.addWidget(self._label("c2"))
        self.atk_c2 = QLineEdit()
        r1.addWidget(self.atk_c2, stretch=1)
        r1.addWidget(self._label("e1"))
        self.atk_e1 = QLineEdit()
        r1.addWidget(self.atk_e1, stretch=1)
        r1.addWidget(self._label("e2"))
        self.atk_e2 = QLineEdit()
        r1.addWidget(self.atk_e2, stretch=1)
        r1.addWidget(self._label("n"))
        self.atk_n = QLineEdit()
        r1.addWidget(self.atk_n, stretch=1)
        layout.addLayout(r1)
        self.atk_common_btn = QPushButton("共模攻击")
        self.atk_common_btn.setObjectName("ghbtn-primary")
        self.atk_common_btn.clicked.connect(lambda: self._do_attack("common"))
        layout.addWidget(self.atk_common_btn)

        layout.addWidget(_section("低加密指数 / 小明文（c = m^e 且 m^e < n）"))
        r2 = QHBoxLayout()
        r2.setSpacing(8)
        r2.addWidget(self._label("c"))
        self.atk_c = QLineEdit()
        r2.addWidget(self.atk_c, stretch=1)
        r2.addWidget(self._label("e"))
        self.atk_e = QLineEdit()
        self.atk_e.setText("3")
        r2.addWidget(self.atk_e, stretch=1)
        r2.addWidget(self._label("n（可省略）"))
        self.atk_n2 = QLineEdit()
        r2.addWidget(self.atk_n2, stretch=1)
        layout.addLayout(r2)
        self.atk_low_btn = QPushButton("低指数攻击")
        self.atk_low_btn.setObjectName("ghbtn")
        self.atk_low_btn.clicked.connect(lambda: self._do_attack("low"))
        layout.addWidget(self.atk_low_btn)

        layout.addWidget(_section("Wiener 攻击（d 较小）"))
        r3 = QHBoxLayout()
        r3.setSpacing(8)
        r3.addWidget(self._label("n"))
        self.atk_wn = QLineEdit()
        r3.addWidget(self.atk_wn, stretch=1)
        r3.addWidget(self._label("e"))
        self.atk_we = QLineEdit()
        r3.addWidget(self.atk_we, stretch=1)
        layout.addLayout(r3)
        self.atk_wiener_btn = QPushButton("Wiener 攻击")
        self.atk_wiener_btn.setObjectName("ghbtn")
        self.atk_wiener_btn.clicked.connect(lambda: self._do_attack("wiener"))
        layout.addWidget(self.atk_wiener_btn)

        layout.addWidget(_section("Hastad 广播攻击（同一 m，e=3，多个 n）"))
        layout.addWidget(self._label(
            "n 列表（每行一个模数；c 列表与 e 列表同序，每行一个）"))
        r4 = QHBoxLayout()
        r4.setSpacing(8)
        r4.addWidget(self._label("密文 c"))
        self.atk_hc = _io(height=64)
        r4.addWidget(self.atk_hc, stretch=1)
        r4.addWidget(self._label("指数 e"))
        self.atk_he = _io(height=64)
        self.atk_he.setPlainText("3\n3\n3")
        r4.addWidget(self.atk_he, stretch=1)
        r4.addWidget(self._label("模数 n"))
        self.atk_hn = _io(height=64)
        r4.addWidget(self.atk_hn, stretch=1)
        layout.addLayout(r4)
        self.atk_hastad_btn = QPushButton("Hastad 广播攻击")
        self.atk_hastad_btn.setObjectName("ghbtn")
        self.atk_hastad_btn.clicked.connect(lambda: self._do_attack("hastad"))
        layout.addWidget(self.atk_hastad_btn)

        layout.addWidget(_section("攻击结果"))
        self.atk_output = _io(readonly=True, height=120)
        layout.addWidget(self.atk_output)

        self.atk_status = _status()
        layout.addWidget(self.atk_status)
        return self._wrap(inner)

    # ---- Tab 4：基础运算 --------------------------------------------------
    def _build_basic_tab(self) -> QWidget:
        inner = QWidget()
        layout = QVBoxLayout(inner)
        layout.setContentsMargins(8, 14, 8, 8)
        layout.setSpacing(8)

        layout.addWidget(_section("运算类型"))
        layout.addWidget(self._label(
            "按需填写下方各运算的输入，点击对应按钮即可（数值支持十进制/十六进制）"))

        # gcd / lcm
        row_g = QHBoxLayout()
        row_g.setSpacing(8)
        row_g.addWidget(self._label("gcd / lcm：a"))
        self.basic_a = QLineEdit()
        row_g.addWidget(self.basic_a, stretch=1)
        row_g.addWidget(self._label("b"))
        self.basic_b = QLineEdit()
        row_g.addWidget(self.basic_b, stretch=1)
        layout.addLayout(row_g)
        btn_g = QHBoxLayout()
        btn_g.setSpacing(8)
        gcd_btn = QPushButton("gcd")
        gcd_btn.setObjectName("ghbtn")
        gcd_btn.clicked.connect(lambda: self._do_basic("gcd"))
        lcm_btn = QPushButton("lcm")
        lcm_btn.setObjectName("ghbtn")
        lcm_btn.clicked.connect(lambda: self._do_basic("lcm"))
        btn_g.addWidget(gcd_btn)
        btn_g.addWidget(lcm_btn)
        btn_g.addStretch(1)
        layout.addLayout(btn_g)

        # modinv
        row_i = QHBoxLayout()
        row_i.setSpacing(8)
        row_i.addWidget(self._label("模逆：a"))
        self.basic_a2 = QLineEdit()
        row_i.addWidget(self.basic_a2, stretch=1)
        row_i.addWidget(self._label("m"))
        self.basic_m = QLineEdit()
        row_i.addWidget(self.basic_m, stretch=1)
        layout.addLayout(row_i)
        btn_i = QHBoxLayout()
        modinv_btn = QPushButton("模逆 a⁻¹ mod m")
        modinv_btn.setObjectName("ghbtn")
        modinv_btn.clicked.connect(lambda: self._do_basic("modinv"))
        btn_i.addWidget(modinv_btn)
        btn_i.addStretch(1)
        layout.addLayout(btn_i)

        # powmod
        row_p = QHBoxLayout()
        row_p.setSpacing(8)
        row_p.addWidget(self._label("幂：base"))
        self.basic_base = QLineEdit()
        row_p.addWidget(self.basic_base, stretch=1)
        row_p.addWidget(self._label("exp"))
        self.basic_exp = QLineEdit()
        row_p.addWidget(self.basic_exp, stretch=1)
        row_p.addWidget(self._label("mod"))
        self.basic_mod = QLineEdit()
        row_p.addWidget(self.basic_mod, stretch=1)
        layout.addLayout(row_p)
        btn_p = QHBoxLayout()
        pow_btn = QPushButton("快速幂 base^exp mod mod")
        pow_btn.setObjectName("ghbtn")
        pow_btn.clicked.connect(lambda: self._do_basic("powmod"))
        btn_p.addWidget(pow_btn)
        btn_p.addStretch(1)
        layout.addLayout(btn_p)

        # euler_phi / 开方 / 素性
        row_o = QHBoxLayout()
        row_o.setSpacing(8)
        row_o.addWidget(self._label("欧拉函数 / 开方 / 素性：n"))
        self.basic_n = QLineEdit()
        row_o.addWidget(self.basic_n, stretch=1)
        layout.addLayout(row_o)
        btn_o = QHBoxLayout()
        btn_o.setSpacing(8)
        phi_btn = QPushButton("φ(n)")
        phi_btn.setObjectName("ghbtn")
        phi_btn.clicked.connect(lambda: self._do_basic("phi"))
        root_btn = QPushButton("√n（开方）")
        root_btn.setObjectName("ghbtn")
        root_btn.clicked.connect(lambda: self._do_basic("sqrt"))
        prime_btn = QPushButton("素性判定")
        prime_btn.setObjectName("ghbtn")
        prime_btn.clicked.connect(lambda: self._do_basic("prime"))
        btn_o.addWidget(phi_btn)
        btn_o.addWidget(root_btn)
        btn_o.addWidget(prime_btn)
        btn_o.addStretch(1)
        layout.addLayout(btn_o)

        # CRT
        layout.addWidget(self._label("CRT 中国剩余定理（余数一行一个、模数一行一个，等长）"))
        r5 = QHBoxLayout()
        r5.setSpacing(8)
        r5.addWidget(self._label("余数"))
        self.basic_rem = _io(height=64)
        r5.addWidget(self.basic_rem, stretch=1)
        r5.addWidget(self._label("模数"))
        self.basic_mods = _io(height=64)
        r5.addWidget(self.basic_mods, stretch=1)
        layout.addLayout(r5)
        btn_crt = QHBoxLayout()
        crt_btn = QPushButton("CRT 求解")
        crt_btn.setObjectName("ghbtn")
        crt_btn.clicked.connect(lambda: self._do_basic("crt"))
        clear_btn = QPushButton("清空")
        clear_btn.setObjectName("ghbtn")
        clear_btn.clicked.connect(self._clear_basic)
        btn_crt.addWidget(crt_btn)
        btn_crt.addWidget(clear_btn)
        btn_crt.addStretch(1)
        layout.addLayout(btn_crt)

        layout.addWidget(_section("结果"))
        self.basic_output = _io(readonly=True, height=120)
        layout.addWidget(self.basic_output)

        self.basic_status = _status()
        layout.addWidget(self.basic_status)
        return self._wrap(inner)

    # -------------------------------------------------------------- 小部件
    @staticmethod
    def _label(text: str) -> QLabel:
        label = QLabel(text)
        label.setObjectName("section")
        return label

    @staticmethod
    def _wrap(inner: QWidget) -> QScrollArea:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setWidget(inner)
        return scroll

    # -------------------------------------------------------------- 后台执行
    def _run_async(self, fn, on_ok, stop_btn: QPushButton | None = None,
                   run_btn: QPushButton | None = None) -> None:
        worker = _RsaWorker(fn, self)
        if run_btn is not None:
            run_btn.setEnabled(False)
        if stop_btn is not None:
            stop_btn.setEnabled(True)

        def done(payload, err):
            if run_btn is not None:
                run_btn.setEnabled(True)
            if stop_btn is not None:
                stop_btn.setEnabled(False)
            on_ok(payload, err)

        worker.done.connect(done)
        worker.finished.connect(lambda w=worker: (self._workers.discard(w),
                                                  w.deleteLater()))
        self._workers.add(worker)
        worker.start()

    def _stop_all(self) -> None:
        """停止所有在途任务（分解类耗时运算用）。"""
        # 当前实现无法真正中断纯 Python 分解，仅停止信号：这里等待已完成的任务
        for w in list(self._workers):
            if w.isRunning():
                w.wait(100)

    # -------------------------------------------------------------- 分解
    def _do_factor(self) -> None:
        text = self.factor_input.toPlainText().strip()
        if not text:
            _set_status(self.factor_status, False, "请先输入要分解的整数 n。")
            return
        use_f = self.factor_fermat.isChecked()
        use_r = self.factor_prho.isChecked()
        use_p = self.factor_pm1.isChecked()

        def task():
            n = rsa_attack.parse_int(text)
            return rsa_attack.factor(n, use_fermat=use_f, use_prho=use_r,
                                     use_pm1=use_p)

        def done(payload, err):
            if err:
                _set_status(self.factor_status, False, f"分解失败：{err}")
                return
            if not payload:
                _set_status(self.factor_status, True, "n = 1，无质因子。")
                self.factor_output.setPlainText("（无）")
                return
            lines = [str(f) for f in payload]
            self.factor_output.setPlainText("\n".join(lines))
            _set_status(self.factor_status, True,
                        f"分解完成：共 {len(payload)} 个质因子（含重数）。"
                        f" 乘积校验 = {_prod_str(payload)}")

        _set_status(self.factor_status, None, "正在分解…（大整数可能耗时）")
        self._run_async(task, done, self.factor_stop, self.factor_run)

    # -------------------------------------------------------------- RSA 恢复
    def _do_recover(self) -> None:
        p = self.rec_p.text().strip()
        q = self.rec_q.text().strip()
        e = self.rec_e.text().strip()
        if not (p and q and e):
            _set_status(self.rec_status, False, "恢复 d 需要 p、q、e 三个参数。")
            return

        def task():
            pi, qi, ei = (rsa_attack.parse_int(x) for x in (p, q, e))
            d = rsa_attack.rsa_recover_d(pi, qi, ei)
            pem = rsa_attack.rsa_private_key(pi, qi, ei)
            return d, pem

        def done(payload, err):
            if err:
                _set_status(self.rec_status, False, f"恢复失败：{err}")
                return
            d, pem = payload
            self.rec_output.setPlainText(
                f"私钥 d = {d}\n\n{pem}")
            _set_status(self.rec_status, True, "已恢复私钥 d 与 PEM 私钥。")

        _set_status(self.rec_status, None, "正在恢复…")
        self._run_async(task, done, None, self.rec_run)

    def _do_recover_pq(self) -> None:
        n = self.rec_n.text().strip()
        e = self.rec_e2.text().strip()
        d = self.rec_d.text().strip()
        if not (n and e and d):
            _set_status(self.rec_status, False, "反推 p、q 需要 n、e、d 三个参数。")
            return

        def task():
            return rsa_attack.rsa_recover_pq_from_ed(
                rsa_attack.parse_int(n), rsa_attack.parse_int(e),
                rsa_attack.parse_int(d))

        def done(payload, err):
            if err:
                _set_status(self.rec_status, False, f"反推失败：{err}")
                return
            p, q = payload
            self.rec_output.setPlainText(f"p = {p}\nq = {q}")
            _set_status(self.rec_status, True, "已由 n、e、d 反推出 p、q。")

        _set_status(self.rec_status, None, "正在反推 p、q…")
        self._run_async(task, done, None, self.rec_pq_run)

    # -------------------------------------------------------------- RSA 攻击
    def _do_attack(self, kind: str) -> None:
        if kind == "common":
            c1, c2, e1, e2, n = (self.atk_c1.text().strip(),
                                 self.atk_c2.text().strip(),
                                 self.atk_e1.text().strip(),
                                 self.atk_e2.text().strip(),
                                 self.atk_n.text().strip())
            if not all((c1, c2, e1, e2, n)):
                _set_status(self.atk_status, False,
                            "共模攻击需要 c1、c2、e1、e2、n。")
                return

            def task():
                return rsa_attack.attack_common_modulus(
                    *[rsa_attack.parse_int(x) for x in (c1, c2, e1, e2, n)])
            label = "共模攻击"
        elif kind == "low":
            c, e, n = (self.atk_c.text().strip(), self.atk_e.text().strip(),
                       self.atk_n2.text().strip())
            if not (c and e):
                _set_status(self.atk_status, False, "低指数攻击需要 c 与 e。")
                return

            def task():
                ci, ei = rsa_attack.parse_int(c), rsa_attack.parse_int(e)
                ni = rsa_attack.parse_int(n) if n else 1 << (ci.bit_length() * 2 + 16)
                return rsa_attack.attack_low_exponent(ci, ei, ni)
            label = "低指数攻击"
        elif kind == "wiener":
            n, e = self.atk_wn.text().strip(), self.atk_we.text().strip()
            if not (n and e):
                _set_status(self.atk_status, False, "Wiener 攻击需要 n 与 e。")
                return

            def task():
                return rsa_attack.attack_wiener(
                    rsa_attack.parse_int(n), rsa_attack.parse_int(e))
            label = "Wiener 攻击"
        else:  # hastad
            cs = self.atk_hc.toPlainText().strip()
            es = self.atk_he.toPlainText().strip()
            ns = self.atk_hn.toPlainText().strip()
            if not (cs and es and ns):
                _set_status(self.atk_status, False,
                            "Hastad 攻击需要密文、指数、模数列表。")
                return

            def task():
                c_list = [rsa_attack.parse_int(x) for x in cs.splitlines() if x.strip()]
                e_list = [rsa_attack.parse_int(x) for x in es.splitlines() if x.strip()]
                n_list = [rsa_attack.parse_int(x) for x in ns.splitlines() if x.strip()]
                return rsa_attack.attack_hastad(c_list, e_list, n_list)
            label = "Hastad 广播攻击"

        def done(payload, err):
            if err:
                _set_status(self.atk_status, False, f"{label}失败：{err}")
                return
            if payload is None:
                _set_status(self.atk_status, False, f"{label}未能恢复明文。")
                return
            self.atk_output.setPlainText(
                f"恢复的明文 m = {payload}\n\n"
                f"十六进制 = {hex(payload)}\n"
                f"文本（UTF-8）= {rsa_attack.int_to_text(payload)}")
            _set_status(self.atk_status, True, f"{label}成功。")

        _set_status(self.atk_status, None, f"正在执行{label}…")
        self._run_async(task, done, None, None)

    # -------------------------------------------------------------- 基础运算
    def _clear_basic(self) -> None:
        for w in (self.basic_a, self.basic_b, self.basic_a2, self.basic_m,
                  self.basic_base, self.basic_exp, self.basic_mod, self.basic_n):
            w.clear()
        self.basic_rem.clear()
        self.basic_mods.clear()
        self.basic_output.clear()
        _set_status(self.basic_status, None, "")

    def _do_basic(self, kind: str) -> None:
        try:
            if kind == "gcd":
                a, b = self.basic_a.text(), self.basic_b.text()
                if not (a and b):
                    raise rsa_attack.RsaError("gcd 需要 a、b 两个参数")
                result = rsa_attack.gcd(a, b)
                label = f"gcd({a}, {b})"
            elif kind == "lcm":
                a, b = self.basic_a.text(), self.basic_b.text()
                if not (a and b):
                    raise rsa_attack.RsaError("lcm 需要 a、b 两个参数")
                result = rsa_attack.lcm(a, b)
                label = f"lcm({a}, {b})"
            elif kind == "modinv":
                a, m = self.basic_a2.text(), self.basic_m.text()
                if not (a and m):
                    raise rsa_attack.RsaError("模逆需要 a、m 两个参数")
                result = rsa_attack.modinv(a, m)
                label = f"{a}⁻¹ mod {m}"
            elif kind == "powmod":
                base, exp, mod = (self.basic_base.text(), self.basic_exp.text(),
                                  self.basic_mod.text())
                if not (base and exp and mod):
                    raise rsa_attack.RsaError("快速幂需要 base、exp、mod 三个参数")
                result = rsa_attack.powmod(base, exp, mod)
                label = f"{base}^{exp} mod {mod}"
            elif kind == "phi":
                n = self.basic_n.text()
                if not n:
                    raise rsa_attack.RsaError("φ(n) 需要 n")
                result = rsa_attack.euler_phi(n)
                label = f"φ({n})"
            elif kind == "sqrt":
                n = self.basic_n.text()
                if not n:
                    raise rsa_attack.RsaError("开方需要 n")
                result = rsa_attack.integer_nth_root(rsa_attack.parse_int(n), 2)
                label = f"√{n}"
            elif kind == "prime":
                n = self.basic_n.text()
                if not n:
                    raise rsa_attack.RsaError("素性判定需要 n")
                result = rsa_attack.is_prime(rsa_attack.parse_int(n))
                label = f"is_prime({n})"
            elif kind == "crt":
                rem = self.basic_rem.toPlainText().strip()
                mods = self.basic_mods.toPlainText().strip()
                if not (rem and mods):
                    raise rsa_attack.RsaError("CRT 需要余数与模数列表")
                r_list = [rsa_attack.parse_int(x) for x in rem.splitlines() if x.strip()]
                m_list = [rsa_attack.parse_int(x) for x in mods.splitlines() if x.strip()]
                result = rsa_attack.crt(r_list, m_list)
                label = "CRT 解"
            else:
                return
        except rsa_attack.RsaError as exc:
            _set_status(self.basic_status, False, f"运算失败：{exc}")
            return
        except Exception as exc:  # noqa: BLE001
            _set_status(self.basic_status, False, f"运算失败：{exc}")
            return

        self.basic_output.setPlainText(f"{label} = {result}")
        _set_status(self.basic_status, True, f"{label} 计算完成。")

    # -------------------------------------------------------------- 生命周期
    def shutdown(self) -> None:
        for worker in list(self._workers):
            if worker.isRunning():
                worker.wait(3000)


def _prod_str(factors: list[int]) -> str:
    """乘积校验字符串（限长，避免超长数字刷屏）。"""
    prod = 1
    for f in factors:
        prod *= f
    s = str(prod)
    return s if len(s) <= 60 else s[:57] + "…"
