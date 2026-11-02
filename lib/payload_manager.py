# -*- coding: utf-8 -*-
"""Payload 管理器纯逻辑模块（Java / PHP / Python）。

功能：
- SQLite 数据库持久化 payload（名称 / 语言 / 代码 / 备注 / 时间戳）；
- 记录每种语言「编译 / 运行」所需解释器位置（Java 用 javac + java，
  PHP / Python 用各自的解释器，编译用 ``php -l`` / ``py_compile``）；
- 把 payload 源码写入独立构建目录，调用对应编译器 / 解释器产出编译结果；
- 每次编译 / 运行都记一条历史到 SQLite，供界面回溯。

本模块只做「数据 + 编译」逻辑，不导入任何 UI 模块。编译 / 运行通过
``subprocess`` 同步执行，界面层应放到后台线程（``QThread``）里调用。
"""

from __future__ import annotations

import re
import shutil
import sqlite3
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------
#: 支持的语言（键）与显示顺序
LANGUAGES: tuple[str, ...] = ("java", "php", "python")

#: 语言键 -> 显示名
LANGUAGE_NAMES: dict[str, str] = {
    "java": "Java",
    "php": "PHP",
    "python": "Python",
}

#: 每种语言需要的「工具角色」：(role, 显示名, 默认命令名)。
#: compiler 用于「编译」，runner 用于「运行」。PHP / Python 编译与运行共用
#: 同一个解释器，但 Java 编译用 javac、运行用 java，两者分开。
TOOL_ROLES: dict[str, tuple[tuple[str, str, str], ...]] = {
    "java": (("compiler", "javac 路径", "javac"),
             ("runner", "java 路径", "java")),
    "php": (("compiler", "php 路径", "php"),
            ("runner", "php 路径", "php")),
    "python": (("compiler", "python 路径", "python"),
               ("runner", "python 路径", "python")),
}

#: SQLite 数据库文件名（位于应用根目录下的 payload/ 目录）
DB_FILENAME = "payloads.db"

#: 构建目录名（payload 源码与编译产物都放在 payload/build/ 下）
BUILD_DIRNAME = "build"

#: 编译 / 运行超时（秒）
DEFAULT_TIMEOUT = 60

#: 找不到源码里的 public class 名时的兜底类名
DEFAULT_JAVA_CLASS = "Payload"

_JAVA_CLASS_RE = re.compile(r"\bpublic\s+(?:class|interface|enum)\s+([A-Za-z_$][\w$]*)")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS payloads (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    language    TEXT NOT NULL,
    code        TEXT NOT NULL DEFAULT '',
    note        TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS interpreters (
    language    TEXT NOT NULL,
    role        TEXT NOT NULL,
    path        TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (language, role)
);
CREATE TABLE IF NOT EXISTS history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    payload_id  INTEGER,
    language    TEXT NOT NULL,
    action      TEXT NOT NULL,
    ok          INTEGER NOT NULL DEFAULT 0,
    output      TEXT NOT NULL DEFAULT '',
    artifact    TEXT NOT NULL DEFAULT '',
    command     TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL
);
"""


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def app_root() -> Path:
    """应用根目录：打包后取 exe 所在目录，源码运行取项目根目录。"""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def db_path(root: Path | None = None) -> Path:
    """Payload SQLite 数据库路径（默认在应用根目录 payload/ 下）。"""
    base = root or app_root()
    directory = base / "payload"
    directory.mkdir(parents=True, exist_ok=True)
    return directory / DB_FILENAME


def build_dir(root: Path | None = None) -> Path:
    """编译 / 运行的工作目录（payload/build）。"""
    base = root or app_root()
    directory = base / "payload" / BUILD_DIRNAME
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def detect_command(name: str) -> str:
    """在 PATH 里探测命令的绝对路径；找不到返回空字符串。"""
    return shutil.which(name) or ""


#: store 配置节 ``payload_compiler`` -> 各语言的 tools 映射键。
#: (配置键, tools 角色) 的对应关系。
_CONFIG_TOOL_MAP = {
    "java": (("java_compiler", "compiler"), ("java_runner", "runner")),
    "php": (("php_path", "compiler"), ("php_path", "runner")),
    "python": (("python_path", "compiler"), ("python_path", "runner")),
}


def tools_from_config(cfg: dict) -> dict[str, dict[str, str]]:
    """把 ``payload_compiler`` 配置节转成 ``{language: {role: path}}``。

    ``cfg`` 为 store 里 ``payload_compiler`` 的字典（可能为 None / 空）。
    仅填了路径的键会被保留；留空的键靠 :func:`resolve_tool` 在编译 / 运行时
    回退到 PATH 自动探测。
    """
    section = cfg if isinstance(cfg, dict) else {}
    result: dict[str, dict[str, str]] = {}
    for language, pairs in _CONFIG_TOOL_MAP.items():
        tools: dict[str, str] = {}
        for config_key, role in pairs:
            value = str(section.get(config_key, "") or "").strip()
            if value:
                tools[role] = value
        if tools:
            result[language] = tools
    return result


def resolve_tool(path: str, command_name: str) -> str:
    """解析工具路径：显式给定则用之，否则回退 PATH 探测，再失败抛异常。"""
    explicit = str(path or "").strip()
    if explicit:
        return explicit
    detected = detect_command(command_name)
    if detected:
        return detected
    raise FileNotFoundError(
        f"未找到 {command_name}，请在「解释器配置」里指定其路径，或将其加入 PATH")


def java_class_name(source: str) -> str:
    """从 Java 源码里提取 public class 名（找不到用兜底名）。"""
    match = _JAVA_CLASS_RE.search(source or "")
    return match.group(1) if match else DEFAULT_JAVA_CLASS


# ---------------------------------------------------------------------------
# SQLite 数据层
# ---------------------------------------------------------------------------
@dataclass
class PayloadRecord:
    """一条 payload 记录（从数据库读出）。"""
    id: int
    name: str
    language: str
    code: str
    note: str
    created_at: str
    updated_at: str


class PayloadStore:
    """Payload SQLite 数据库封装（payload / 解释器 / 编译历史三张表）。"""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else db_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path))
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # -- 生命周期 ---------------------------------------------------------
    def close(self) -> None:
        try:
            self._conn.close()
        except sqlite3.Error:
            pass

    # -- payload CRUD -----------------------------------------------------
    def list_payloads(self, language: str | None = None,
                      keyword: str | None = None) -> list[PayloadRecord]:
        sql = ("SELECT id, name, language, code, note, created_at, updated_at "
               "FROM payloads")
        where: list[str] = []
        params: list = []
        if language:
            where.append("language = ?")
            params.append(language)
        if keyword and keyword.strip():
            where.append("(name LIKE ? OR note LIKE ? OR code LIKE ?)")
            like = f"%{keyword.strip()}%"
            params.extend((like, like, like))
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY updated_at DESC"
        rows = self._conn.execute(sql, params).fetchall()
        return [PayloadRecord(
            id=r["id"], name=r["name"], language=r["language"], code=r["code"],
            note=r["note"], created_at=r["created_at"], updated_at=r["updated_at"],
        ) for r in rows]

    def get_payload(self, payload_id: int) -> PayloadRecord | None:
        row = self._conn.execute(
            "SELECT id, name, language, code, note, created_at, updated_at "
            "FROM payloads WHERE id = ?", (payload_id,)).fetchone()
        if row is None:
            return None
        return PayloadRecord(
            id=row["id"], name=row["name"], language=row["language"],
            code=row["code"], note=row["note"],
            created_at=row["created_at"], updated_at=row["updated_at"])

    def upsert_payload(self, name: str, language: str, code: str,
                       note: str = "", payload_id: int | None = None) -> int:
        """新建或更新 payload，返回其 id。"""
        now = _now()
        if payload_id is None:
            cur = self._conn.execute(
                "INSERT INTO payloads (name, language, code, note, created_at, "
                "updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                (name, language, code, note, now, now))
        else:
            cur = self._conn.execute(
                "UPDATE payloads SET name = ?, language = ?, code = ?, note = ?, "
                "updated_at = ? WHERE id = ?",
                (name, language, code, note, now, payload_id))
        self._conn.commit()
        return payload_id if payload_id is not None else int(cur.lastrowid)

    def delete_payload(self, payload_id: int) -> None:
        self._conn.execute("DELETE FROM payloads WHERE id = ?", (payload_id,))
        self._conn.execute("DELETE FROM history WHERE payload_id = ?", (payload_id,))
        self._conn.commit()

    # -- 解释器配置 -------------------------------------------------------
    def set_interpreter(self, language: str, role: str, path: str) -> None:
        self._conn.execute(
            "INSERT INTO interpreters (language, role, path) VALUES (?, ?, ?) "
            "ON CONFLICT(language, role) DO UPDATE SET path = excluded.path",
            (language, role, str(path or "").strip()))
        self._conn.commit()

    def get_interpreters(self) -> dict[str, dict[str, str]]:
        """返回 {language: {role: path}}。"""
        result: dict[str, dict[str, str]] = {}
        for row in self._conn.execute("SELECT language, role, path FROM interpreters"):
            result.setdefault(row["language"], {})[row["role"]] = row["path"]
        return result

    # -- 编译 / 运行历史 ---------------------------------------------------
    def add_history(self, payload_id: int | None, language: str, action: str,
                    ok: bool, output: str, artifact: str = "",
                    command: str = "") -> None:
        self._conn.execute(
            "INSERT INTO history (payload_id, language, action, ok, output, "
            "artifact, command, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (payload_id, language, action, int(ok), output, artifact, command, _now()))
        self._conn.commit()

    def list_history(self, payload_id: int | None = None,
                     limit: int = 100) -> list[sqlite3.Row]:
        if payload_id is None:
            rows = self._conn.execute(
                "SELECT * FROM history ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM history WHERE payload_id = ? ORDER BY id DESC "
                "LIMIT ?", (payload_id, limit)).fetchall()
        return rows


# ---------------------------------------------------------------------------
# 编译 / 运行
# ---------------------------------------------------------------------------
def _write_source(source: str, workdir: Path, filename: str) -> Path:
    workdir.mkdir(parents=True, exist_ok=True)
    target = workdir / filename
    target.write_text(source or "", encoding="utf-8")
    return target


def _run_command(cmd: list[str], cwd: Path,
                 timeout: int = DEFAULT_TIMEOUT) -> dict:
    """执行子进程并统一返回结果 dict。"""
    try:
        proc = subprocess.run(
            cmd, cwd=str(cwd), capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=timeout)
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        return {
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "output": (stderr + stdout).strip() or "(无输出)",
            "command": " ".join(cmd),
        }
    except FileNotFoundError as exc:
        return {"ok": False, "returncode": -1,
                "output": f"解释器不存在: {exc}", "command": " ".join(cmd)}
    except subprocess.TimeoutExpired:
        return {"ok": False, "returncode": -1,
                "output": f"执行超时（>{timeout}s）", "command": " ".join(cmd)}


def compile_source(language: str, source: str, tools: dict[str, str],
                   workdir: Path | None = None,
                   timeout: int = DEFAULT_TIMEOUT) -> dict:
    """编译 payload 源码，返回结果 dict（含 ok / output / artifact / command）。

    - Java   ：``javac`` 产出 ``.class``；
    - PHP    ：``php -l`` 语法检查（PHP 为解释型，无独立编译产物）；
    - Python ：``python -m py_compile`` 产出 ``.pyc``（位于 __pycache__）。
    """
    wd = workdir or build_dir()
    if language not in LANGUAGES:
        return {"ok": False, "returncode": -1,
                "output": f"不支持的语言: {language}", "artifact": "", "command": ""}
    if not isinstance(tools, dict):
        tools = {}

    artifact = ""
    if language == "java":
        compiler = resolve_tool(tools.get("compiler", ""), "javac")
        cls = java_class_name(source)
        src = _write_source(source, wd, f"{cls}.java")
        result = _run_command([compiler, str(src)], wd, timeout)
        if result["ok"]:
            artifact = str(wd / f"{cls}.class")
    elif language == "php":
        compiler = resolve_tool(tools.get("compiler", ""), "php")
        src = _write_source(source, wd, "payload.php")
        result = _run_command([compiler, "-l", str(src)], wd, timeout)
    else:  # python
        compiler = resolve_tool(tools.get("compiler", ""), "python")
        src = _write_source(source, wd, "payload.py")
        result = _run_command([compiler, "-m", "py_compile", str(src)], wd, timeout)
        if result["ok"]:
            artifact = str(wd / "__pycache__" / "payload.cpython-*.pyc")

    result["artifact"] = artifact
    return result


def run_source(language: str, source: str, tools: dict[str, str],
               workdir: Path | None = None,
               timeout: int = DEFAULT_TIMEOUT) -> dict:
    """运行 payload，返回结果 dict（ok / output / command）。

    Java 会先 ``javac`` 再 ``java``；PHP / Python 直接用解释器执行。
    """
    wd = workdir or build_dir()
    if language not in LANGUAGES:
        return {"ok": False, "returncode": -1,
                "output": f"不支持的语言: {language}", "command": ""}
    if not isinstance(tools, dict):
        tools = {}

    if language == "java":
        javac = resolve_tool(tools.get("compiler", ""), "javac")
        java = resolve_tool(tools.get("runner", ""), "java")
        cls = java_class_name(source)
        src = _write_source(source, wd, f"{cls}.java")
        build = _run_command([javac, str(src)], wd, timeout)
        if not build["ok"]:
            build["output"] = "编译失败：\n" + build["output"]
            return build
        run = _run_command([java, "-cp", str(wd), cls], wd, timeout)
        return run

    if language == "php":
        runner = resolve_tool(tools.get("runner", ""), "php")
        src = _write_source(source, wd, "payload.php")
        return _run_command([runner, str(src)], wd, timeout)

    runner = resolve_tool(tools.get("runner", ""), "python")
    src = _write_source(source, wd, "payload.py")
    return _run_command([runner, str(src)], wd, timeout)
