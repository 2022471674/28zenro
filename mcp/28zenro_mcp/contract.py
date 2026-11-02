# -*- coding: utf-8 -*-
"""参数契约与分发核心。

三个概念
--------
:class:`Param`  一个参数的契约：名字 / 类型 / 是否必填 / 默认值 / 说明 / 取值域
:class:`Op`     一个操作：对应 ``lib`` 里的一个函数（默认同名转发）或自定义 handler
:class:`Group`  一个 MCP 工具：一组 op，工具名形如 ``cn_codec``，调用形如
                ``cn_codec(op="base64_encrypt", params={"data": "flag"})``

约定（摘要，完整版见 mcp/CONTRACT.md）
------------------------------------
1. op 名默认等于 lib 函数名；参数名默认等于 lib 形参名，不做改名；
2. ``params`` 里的未知键一律报 ``invalid_param``，不做静默丢弃；
3. lib 函数签名里的 ``log`` / ``progress`` / ``stop`` 由分发器自动注入，
   调用者无需也无法手工传；
4. 返回一律是 :mod:`envelope` 定义的统一信封。
"""

from __future__ import annotations

import inspect
import json
import threading
import time
import traceback
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from .bootstrap import Settings, log
from .envelope import ToolError, envelope_fail, envelope_ok, to_jsonable

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------
#: 参数类型（与 :meth:`Param.coerce` 一一对应）。
TYPES: dict[str, str] = {
    "str": "字符串",
    "int": "整数",
    "float": "浮点数",
    "bool": "布尔值",
    "list": "字符串数组（也接受换行 / 逗号分隔的字符串）",
    "dict": "对象（也接受 JSON 字符串）",
    "hex": "十六进制字符串，自动转 bytes",
    "any": "任意 JSON 值",
}

#: lib 函数里由分发器自动注入、不参与契约声明的参数。
AUTO_ARGS = ("log", "progress", "stop")

#: 风险等级：safe 纯计算 ｜ read 读文件 ｜ write 写文件 ｜ network 发起网络请求
#: intrusive 主动探测 / 爆破 ｜ long 可能长时间运行。
RISKS = ("safe", "read", "write", "network", "intrusive", "long")

_MISSING = object()


# ---------------------------------------------------------------------------
# Param
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Param:
    """单个参数契约。"""

    name: str
    type: str = "str"
    required: bool = False
    default: Any = _MISSING
    desc: str = ""
    choices: tuple[str, ...] = ()
    minimum: float | None = None
    maximum: float | None = None

    def __post_init__(self) -> None:
        if self.type not in TYPES:
            raise ValueError(f"参数 {self.name} 的类型 {self.type!r} 不受支持")
        if self.required and self.default is not _MISSING:
            raise ValueError(f"参数 {self.name} 既是必填又给了默认值")

    # -- 默认值 ------------------------------------------------------------
    def has_default(self) -> bool:
        return self.default is not _MISSING

    def effective_default(self) -> Any:
        return None if self.default is _MISSING else self.default

    # -- 类型转换 ----------------------------------------------------------
    def coerce(self, raw: Any) -> Any:
        """把外部输入转成契约类型；失败抛 :class:`ToolError`。"""
        try:
            value = self._coerce(raw)
        except ToolError:
            raise
        except (TypeError, ValueError) as exc:
            raise ToolError(
                "type_error",
                f"参数 {self.name} 应为 {self.type}（{TYPES[self.type]}），"
                f"收到 {type(raw).__name__}: {raw!r}",
                field=self.name,
            ) from exc
        if self.choices and value not in self.choices:
            raise ToolError(
                "range_error",
                f"参数 {self.name} 取值 {value!r} 不在允许范围内"
                f"（可选 {', '.join(map(str, self.choices))}）",
                field=self.name,
            )
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if self.minimum is not None and value < self.minimum:
                raise ToolError("range_error",
                                f"参数 {self.name} 不能小于 {self.minimum}",
                                field=self.name)
            if self.maximum is not None and value > self.maximum:
                raise ToolError("range_error",
                                f"参数 {self.name} 不能大于 {self.maximum}",
                                field=self.name)
        return value

    def _coerce(self, raw: Any) -> Any:
        kind = self.type
        if kind == "any":
            return raw
        if kind == "str":
            if isinstance(raw, str):
                return raw
            if isinstance(raw, (int, float)) and not isinstance(raw, bool):
                return str(raw)
            raise TypeError("expect str")
        if kind == "int":
            if isinstance(raw, bool):
                raise TypeError("bool 不是整数")
            if isinstance(raw, int):
                return raw
            if isinstance(raw, float):
                if not raw.is_integer():
                    raise TypeError("浮点有小数部分")
                return int(raw)
            text = str(raw).strip().replace("_", "")
            if not text:
                raise ValueError("空字符串")
            return int(text, 16) if text.lower().startswith("0x") else int(text, 10)
        if kind == "float":
            if isinstance(raw, bool):
                raise TypeError("bool 不是浮点数")
            if isinstance(raw, (int, float)):
                return float(raw)
            return float(str(raw).strip())
        if kind == "bool":
            if isinstance(raw, bool):
                return raw
            if isinstance(raw, (int, float)):
                return bool(raw)
            text = str(raw).strip().lower()
            if text in ("1", "true", "yes", "y", "on", "是", "真"):
                return True
            if text in ("0", "false", "no", "n", "off", "否", "假", ""):
                return False
            raise ValueError(f"无法识别的布尔值 {raw!r}")
        if kind == "list":
            if isinstance(raw, (list, tuple, set)):
                return [str(item) for item in raw]
            text = str(raw)
            parts: list[str] = []
            for chunk in text.replace("\r", "\n").replace("，", ",").replace("、", ",").split("\n"):
                parts.extend(chunk.replace(";", ",").replace("；", ",").split(","))
            return [part.strip() for part in parts if part.strip()]
        if kind == "dict":
            if isinstance(raw, dict):
                return dict(raw)
            value = json.loads(str(raw))
            if not isinstance(value, dict):
                raise ValueError("JSON 顶层不是对象")
            return value
        if kind == "hex":
            return parse_hex(raw, field=self.name)
        raise TypeError(f"未知类型 {kind}")

    # -- 导出 --------------------------------------------------------------
    def schema(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "name": self.name,
            "type": self.type,
            "required": self.required,
            "description": self.desc,
        }
        if self.has_default():
            payload["default"] = to_jsonable(self.default)
        if self.choices:
            payload["choices"] = list(self.choices)
        if self.minimum is not None:
            payload["minimum"] = self.minimum
        if self.maximum is not None:
            payload["maximum"] = self.maximum
        return payload


def parse_hex(raw: Any, *, field: str = "hex") -> bytes:
    """把十六进制文本转 bytes；容忍空白、``0x`` / ``\\x`` 前缀与常见分隔符。"""
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw)
    text = str(raw).strip()
    if text.startswith(("0x", "0X")):
        text = text[2:]
    text = text.replace("\\x", "").replace("\\X", "")
    for separator in (" ", "\t", "\r", "\n", ":", "-", "_", ","):
        text = text.replace(separator, "")
    if len(text) % 2:
        raise ToolError("type_error",
                        f"参数 {field} 的十六进制长度必须为偶数（当前 {len(text)}）",
                        field=field)
    try:
        return bytes.fromhex(text)
    except ValueError as exc:
        raise ToolError("type_error", f"参数 {field} 不是合法十六进制：{exc}",
                        field=field) from exc


# ---------------------------------------------------------------------------
# 参数构造快捷函数（op 表里用，越短越好）
# ---------------------------------------------------------------------------
def txt(name: str, required: bool = False, default: Any = "",
        desc: str = "", choices: Iterable[str] = ()) -> Param:
    return Param(name, "str", required, _MISSING if required else default,
                 desc, tuple(choices))


def num(name: str, required: bool = False, default: Any = 0, desc: str = "",
        minimum: float | None = None, maximum: float | None = None) -> Param:
    return Param(name, "int", required, _MISSING if required else default,
                 desc, (), minimum, maximum)


def flt(name: str, required: bool = False, default: Any = 0.0, desc: str = "",
        minimum: float | None = None, maximum: float | None = None) -> Param:
    return Param(name, "float", required, _MISSING if required else default,
                 desc, (), minimum, maximum)


def flag(name: str, required: bool = False, default: bool = False,
         desc: str = "") -> Param:
    return Param(name, "bool", required, _MISSING if required else default,
                 desc)


def arr(name: str, required: bool = False, default: Any = None,
        desc: str = "") -> Param:
    return Param(name, "list", required, _MISSING if required else default,
                 desc)


def obj(name: str, required: bool = False, default: Any = None,
        desc: str = "") -> Param:
    return Param(name, "dict", required, _MISSING if required else default,
                 desc)


def hexb(name: str, required: bool = True, default: Any = "",
         desc: str = "") -> Param:
    return Param(name, "hex", required, _MISSING if required else default,
                 desc)


def anyp(name: str, required: bool = False, default: Any = None,
         desc: str = "") -> Param:
    return Param(name, "any", required, _MISSING if required else default,
                 desc)


# ---------------------------------------------------------------------------
# Op
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Op:
    """一个操作契约。"""

    name: str
    summary: str
    params: tuple[Param, ...] = ()
    fn: Callable[..., Any] | None = None
    handler: Callable[[dict[str, Any], "Ctx"], Any] | None = None
    returns: str = ""
    risk: str = "safe"
    example: dict[str, Any] | None = None
    unpack: tuple[str, ...] = ()
    notes: str = ""
    module: str = ""

    def __post_init__(self) -> None:
        if self.fn is None and self.handler is None:
            raise ValueError(f"op {self.name} 既没有 fn 也没有 handler")
        if self.risk not in RISKS:
            raise ValueError(f"op {self.name} 的风险等级 {self.risk!r} 非法")
        names = [param.name for param in self.params]
        if len(names) != len(set(names)):
            raise ValueError(f"op {self.name} 存在重复参数名")

    # -- 展示 --------------------------------------------------------------
    def signature_text(self) -> str:
        parts = []
        for param in self.params:
            piece = param.name
            if not param.required and param.has_default():
                default = param.default
                piece += f"={default!r}" if not isinstance(default, str) else f'="{default}"'
            parts.append(piece if param.required else f"[{piece}]")
        return ", ".join(parts)

    def schema(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "name": self.name,
            "summary": self.summary,
            "module": self.module,
            "risk": self.risk,
            "params": [param.schema() for param in self.params],
            "returns": self.returns,
        }
        if self.example is not None:
            payload["example"] = self.example
        if self.unpack:
            payload["unpack"] = list(self.unpack)
        if self.notes:
            payload["notes"] = self.notes
        return payload


def make_op(fn: Callable[..., Any], summary: str,
            params: Iterable[Param] = (), **kwargs: Any) -> Op:
    """按「同名转发」约定构造 op：op 名 = 函数名，模块 = 函数所属模块。"""
    kwargs.setdefault("name", fn.__name__)
    kwargs.setdefault("module", fn.__module__)
    return Op(summary=summary, params=tuple(params), fn=fn, **kwargs)


def custom_op(name: str, handler: Callable[[dict[str, Any], "Ctx"], Any],
              summary: str, params: Iterable[Param] = (), *,
              module: str = "28zenro_mcp", **kwargs: Any) -> Op:
    """构造自定义 op（返回元组整形 / 线程轮询 / 配置注入等场景）。"""
    return Op(name=name, summary=summary, params=tuple(params),
              handler=handler, module=module, **kwargs)


# ---------------------------------------------------------------------------
# Group
# ---------------------------------------------------------------------------
@dataclass
class Group:
    """一个 MCP 工具（含若干 op）。"""

    name: str
    title: str
    summary: str
    ops: list[Op] = field(default_factory=list)
    guide: str = ""

    def __post_init__(self) -> None:
        if not self.name.startswith("cn_"):
            raise ValueError(f"工具名必须以 cn_ 前缀：{self.name}")
        seen: set[str] = set()
        for spec in self.ops:
            if spec.name in seen:
                raise ValueError(f"{self.name} 存在重复 op：{spec.name}")
            seen.add(spec.name)

    # -- 查询 --------------------------------------------------------------
    def op(self, name: str) -> Op | None:
        for spec in self.ops:
            if spec.name == name:
                return spec
        return None

    def op_names(self) -> list[str]:
        return [spec.name for spec in self.ops]

    def risks(self) -> list[str]:
        return sorted({spec.risk for spec in self.ops})

    # -- 展示 --------------------------------------------------------------
    def tool_description(self, limit: int = 3200) -> str:
        names = ", ".join(self.op_names())
        head = (f"{self.summary}\n\n调用约定：{self.name}(op=\"<操作名>\", "
                f"params={{...}})；用 cn_help(op=\"help\") 查看每个 op 的完整参数表。\n")
        body = f"\n可用 op（{len(self.ops)} 个）：{names}"
        text = head + (self.guide + "\n" if self.guide else "") + body
        if len(text) > limit:
            text = text[: limit - 20] + "…（见 cn_help）"
        return text

    def schema(self) -> dict[str, Any]:
        return {
            "tool": self.name,
            "title": self.title,
            "summary": self.summary,
            "guide": self.guide,
            "op_count": len(self.ops),
            "risks": self.risks(),
            "ops": [spec.schema() for spec in self.ops],
        }


# ---------------------------------------------------------------------------
# 运行上下文
# ---------------------------------------------------------------------------
@dataclass
class Ctx:
    """一次调用的上下文：配置、日志、停止信号。"""

    settings: Settings
    stop: threading.Event = field(default_factory=threading.Event)
    prefix: str = ""

    def log(self, message: str) -> None:
        log(f"{self.prefix}{message}")

    def progress(self, *args: Any) -> None:
        """兼容任意签名的进度回调（``progress(done, total)`` / ``progress(msg)``）。"""
        text = " ".join(str(arg) for arg in args if arg is not None)
        if text:
            self.log(text)

    def warn(self, message: str) -> None:
        self.log(f"[warn] {message}")


# ---------------------------------------------------------------------------
# 校验
# ---------------------------------------------------------------------------
def validate(spec: Op, raw: Any) -> dict[str, Any]:
    """按契约校验并转换参数，返回交给 handler / lib 函数的实参 dict。"""
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ToolError("type_error",
                        f"params 必须是对象（dict），收到 {type(raw).__name__}",
                        hint="例：cn_codec(op=\"base64_encrypt\", params={\"data\": \"flag\"})")
    allowed = {param.name for param in spec.params}
    unknown = [key for key in raw if key not in allowed]
    if unknown:
        raise ToolError(
            "invalid_param",
            f"未知参数：{', '.join(map(str, unknown))}",
            field=str(unknown[0]),
            hint=(f"{spec.name} 可用参数：{', '.join(sorted(allowed))}"
                  if allowed else f"{spec.name} 不接受任何参数"),
        )
    args: dict[str, Any] = {}
    for param in spec.params:
        if param.name in raw and raw[param.name] is not None:
            args[param.name] = param.coerce(raw[param.name])
        elif param.required:
            raise ToolError(
                "missing_param",
                f"缺少必填参数 {param.name}（{param.desc or TYPES[param.type]}）",
                field=param.name,
                hint=f"可用参数：{', '.join(sorted(allowed))}",
            )
        elif param.has_default():
            args[param.name] = param.default
    return args


# ---------------------------------------------------------------------------
# 分发
# ---------------------------------------------------------------------------
def _default_call(spec: Op, args: dict[str, Any], ctx: Ctx) -> Any:
    """按签名把声明参数 + 自动注入的 log/progress/stop 传给 lib 函数。"""
    assert spec.fn is not None
    try:
        sig = inspect.signature(spec.fn)
    except (TypeError, ValueError):  # pragma: no cover - 内置函数等
        return spec.fn(**args)
    kwargs = dict(args)
    injected = {"log": ctx.log, "progress": ctx.progress, "stop": ctx.stop}
    for name, value in injected.items():
        if name in sig.parameters and name not in kwargs:
            kwargs[name] = value
    return spec.fn(**kwargs)


def run_op(group: Group, op_name: Any, raw_params: Any, ctx: Ctx) -> dict[str, Any]:
    """执行一个 op，返回 :mod:`envelope` 信封。任何异常都不外泄。"""
    name = str(op_name or "").strip()
    started = time.perf_counter()
    spec = group.op(name) if name else None
    if spec is None:
        error = ToolError(
            "invalid_op",
            f"未知 op：{name!r}",
            hint=f"{group.name} 可用 op（{len(group.ops)} 个）："
                 + ", ".join(group.op_names()),
        )
        return envelope_fail(group.name, name or "?", error)
    try:
        args = validate(spec, raw_params)
    except ToolError as exc:
        return envelope_fail(group.name, spec.name, exc,
                             module=spec.module, risk=spec.risk)
    try:
        if spec.handler is not None:
            result = spec.handler(args, ctx)
        else:
            result = _default_call(spec, args, ctx)
    except Exception as exc:  # noqa: BLE001 - 一律转成信封
        elapsed = (time.perf_counter() - started) * 1000
        log(f"{group.name}/{spec.name} 失败：{type(exc).__name__}: {exc}")
        log("".join(traceback.format_exc(limit=6)).rstrip())
        return envelope_fail(group.name, spec.name, exc, module=spec.module,
                             risk=spec.risk, elapsed_ms=elapsed, params=args)
    elapsed = (time.perf_counter() - started) * 1000
    data: Any = to_jsonable(result)
    if spec.unpack:
        if isinstance(result, (tuple, list)) and len(result) == len(spec.unpack):
            data = {key: to_jsonable(item) for key, item in zip(spec.unpack, result)}
        else:  # 形态不符时保留原始（已序列化）结果，避免丢数据
            data = to_jsonable(result)
    return envelope_ok(group.name, spec.name, data, module=spec.module,
                       risk=spec.risk, elapsed_ms=elapsed, params=args)


# ---------------------------------------------------------------------------
# 审计：契约 vs 真实签名
# ---------------------------------------------------------------------------
def audit(groups: Iterable[Group]) -> list[dict[str, Any]]:
    """用 ``inspect.signature`` 对照 op 声明，返回问题列表（空表示一致）。"""
    issues: list[dict[str, Any]] = []
    for group in groups:
        for spec in group.ops:
            if not spec.summary:
                issues.append({"tool": group.name, "op": spec.name,
                               "issue": "缺少 summary"})
            if not spec.returns:
                issues.append({"tool": group.name, "op": spec.name,
                               "issue": "缺少 returns 说明"})
            if spec.handler is not None:
                if spec.fn is not None:
                    issues.append({"tool": group.name, "op": spec.name,
                                   "issue": "同时声明了 fn 与 handler"})
                continue
            assert spec.fn is not None
            try:
                sig = inspect.signature(spec.fn)
            except (TypeError, ValueError):
                continue
            names = set(sig.parameters)
            declared = {param.name for param in spec.params}
            for param in spec.params:
                if param.name not in names:
                    issues.append({
                        "tool": group.name, "op": spec.name, "param": param.name,
                        "issue": f"声明的参数不在 {spec.module}.{spec.fn.__name__} 签名中",
                    })
            for fname, fparam in sig.parameters.items():
                if fname in AUTO_ARGS or fname in declared:
                    continue
                if fparam.kind in (inspect.Parameter.VAR_POSITIONAL,
                                   inspect.Parameter.VAR_KEYWORD):
                    continue
                if fparam.default is inspect.Parameter.empty:
                    issues.append({
                        "tool": group.name, "op": spec.name, "param": fname,
                        "issue": f"lib 必填参数未在契约中声明（{spec.module}.{spec.fn.__name__}）",
                    })
    return issues


def describe(spec: Op) -> str:
    """把 op 渲染成一行文档（供 ``cn_help`` / CONTRACT.md 复用）。"""
    return f"{spec.name}({spec.signature_text()}) -> {spec.returns}"


def find_group(groups: Iterable[Group], tool: str) -> Group | None:
    for group in groups:
        if group.name == tool or group.name == f"cn_{tool}":
            return group
    return None


def find_op(groups: Iterable[Group], name: str) -> tuple[Group | None, Op | None]:
    for group in groups:
        spec = group.op(name)
        if spec is not None:
            return group, spec
    return None, None
