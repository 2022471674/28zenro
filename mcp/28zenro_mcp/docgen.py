# -*- coding: utf-8 -*-
"""文档生成：CONTRACT.md（人读）与契约 JSON（机器读）。

    python mcp/server.py --gen-docs        # 重新生成 mcp/CONTRACT.md
    python mcp/server.py --export out.json # 导出机器可读契约
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from . import __version__
from .bootstrap import PROJECT_ROOT
from .contract import Group, Param

RISK_LABELS = {
    "safe": "纯计算",
    "read": "只读文件",
    "write": "写文件",
    "network": "网络请求",
    "intrusive": "主动探测",
    "long": "可能耗时",
}


# ---------------------------------------------------------------------------
# 指南（资源 28zenro://guide 也用它）
# ---------------------------------------------------------------------------
def render_guide() -> str:
    lines = [
        "# 28zenro MCP 调用指南",
        "",
        "所有工具共用同一签名：",
        "",
        "```python",
        "cn_<group>(op=\"<操作名>\", params={...}) -> dict",
        "```",
        "",
        "## 推荐流程",
        "",
        "1. `cn_help(op=\"list\")` 拿全部工具与 op 名单；",
        "2. `cn_help(op=\"help\", params={\"op\": \"base64_encrypt\"})` 查参数表；",
        "3. 调用目标工具；",
        "4. 判读返回信封：`ok=true` 读 `data`，`ok=false` 读 `error.code` 与 `error.hint`。",
        "",
        "## 返回信封",
        "",
        "```json",
        '{"ok": true, "tool": "cn_codec", "op": "base64_encrypt",',
        ' "data": "ZmxhZw==",',
        ' "meta": {"module": "lib.base_codec", "risk": "safe",',
        '          "elapsed_ms": 0.4, "params": {"data": "flag"}}}',
        "```",
        "",
        "失败时 `data` 换成 `error`：`{code, message, field?, hint?, detail?}`。",
        "",
        "## 约定要点",
        "",
        "- op 名 = `lib` 函数名，参数名 = lib 形参名，不改名；",
        "- 未知参数直接报 `invalid_param`，不会静默忽略；",
        "- 数值 / 布尔 / 列表参数自动宽松转换（`\"3\"`→3、`\"true\"`→True、"
        "`\"a,b\"`→[a, b]）；",
        "- `hex` 类型参数自动把十六进制文本转 bytes（容忍空格 / `0x` / `\\x`）；",
        "- `log` / `progress` / `stop` 由服务端自动注入，调用者无需传；",
        "- 相对路径一律基于项目根 `CTFcrypto/`；",
        "- `meta.params` 对 password / secret / token / key / cookie 等键脱敏；",
        "- 单个结果超过 400k 字符时会被截断成预览（`meta.truncated=true`）；",
        "- 风险等级：safe / read / write / network / intrusive / long。",
        "",
        "## 工具组",
        "",
    ]
    from .ops import GROUPS
    for group in GROUPS:
        lines.append(f"- **{group.name}**（{group.title}，{len(group.ops)} 个 op）："
                     f"{group.summary}")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 契约 JSON
# ---------------------------------------------------------------------------
def contract_json(groups: Iterable[Group]) -> dict[str, Any]:
    return {
        "server": "28zenro-mcp",
        "version": __version__,
        "project_root": str(PROJECT_ROOT),
        "conventions": {
            "signature": "cn_<group>(op: str, params: dict | None = None) -> dict",
            "envelope": {
                "success": ["ok", "tool", "op", "data", "meta"],
                "failure": ["ok", "tool", "op", "error", "meta"],
                "meta": ["module", "risk", "elapsed_ms", "params",
                         "warnings", "truncated"],
            },
            "param_types": ["str", "int", "float", "bool", "list", "dict",
                            "hex", "any"],
            "error_codes": ["invalid_op", "invalid_param", "missing_param",
                            "type_error", "range_error", "lib_error", "timeout",
                            "network", "io", "unsupported", "internal"],
            "risks": ["safe", "read", "write", "network", "intrusive", "long"],
            "auto_injected_args": ["log", "progress", "stop"],
            "path_rule": "相对路径基于项目根 CTFcrypto/",
            "secret_masking": True,
            "result_truncation_chars": 400_000,
        },
        "tools": [group.schema() for group in groups],
    }


def export_json(groups: Iterable[Group], path: str | Path) -> Path:
    target = Path(path)
    if not target.is_absolute():
        target = PROJECT_ROOT / target
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(contract_json(groups), ensure_ascii=False, indent=2),
                      encoding="utf-8")
    return target


# ---------------------------------------------------------------------------
# CONTRACT.md
# ---------------------------------------------------------------------------
def _param_text(param: Param) -> str:
    pieces = [f"`{param.name}`"]
    if param.required:
        pieces.append("**必填**")
    else:
        default = param.default
        if isinstance(default, str):
            pieces.append(f"默认 `{default!r}`")
        elif default is None:
            pieces.append("默认 `null`")
        elif isinstance(default, (list, tuple, dict)):
            pieces.append(f"默认 `{json.dumps(default, ensure_ascii=False)}`")
        else:
            pieces.append(f"默认 `{default!r}`")
    pieces.append(f"`{param.type}`")
    if param.choices:
        pieces.append("可选 " + " / ".join(f"`{choice}`" for choice in param.choices))
    if param.minimum is not None or param.maximum is not None:
        pieces.append(f"范围 {param.minimum if param.minimum is not None else '-∞'}"
                      f"~{param.maximum if param.maximum is not None else '+∞'}")
    text = "，".join(pieces)
    if param.desc:
        text += f"：{param.desc}"
    return text


def _cell(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def render_contract(groups: Iterable[Group]) -> str:
    groups = list(groups)
    total = sum(len(group.ops) for group in groups)
    lines: list[str] = [
        f"# 28zenro MCP 方法契约（v{__version__}）",
        "",
        "> 本文件由 `python mcp/server.py --gen-docs` 从 `28zenro_mcp/ops/*.py` "
        "的 op 声明自动生成。**改契约请改代码，不要手改本文。**",
        "",
        f"工具组 {len(groups)} 个，op 合计 {total} 个。所有 op 均直接复用 "
        f"`{PROJECT_ROOT / 'lib'}` 下的纯逻辑函数，行为与 `python cli.py <tool> --json` 一致。",
        "",
        "## 1. 调用约定",
        "",
        "### 1.1 统一签名",
        "",
        "```python",
        "cn_<group>(op: str, params: dict | None = None) -> dict",
        "```",
        "",
        "- 工具名：`cn_` 前缀 + 分组名（见 §3）；",
        "- `op`：操作名，默认等于 `lib` 函数名；",
        "- `params`：参数对象，键名默认等于 `lib` 形参名；",
        "- 未知 op → `invalid_op`（hint 里带可用 op 清单）；",
        "- 未知参数 → `invalid_param`（不做静默丢弃）。",
        "",
        "### 1.2 返回信封",
        "",
        "成功：",
        "",
        "```json",
        "{",
        '  "ok": true,',
        '  "tool": "cn_codec",',
        '  "op": "base64_encrypt",',
        '  "data": "ZmxhZw==",',
        '  "meta": {',
        '    "module": "lib.base_codec",',
        '    "risk": "safe",',
        '    "elapsed_ms": 0.42,',
        '    "params": {"data": "flag"}',
        "  }",
        "}",
        "```",
        "",
        "失败：",
        "",
        "```json",
        "{",
        '  "ok": false,',
        '  "tool": "cn_codec",',
        '  "op": "base64_decrypt",',
        '  "error": {"code": "lib_error", "message": "Base64 解码失败：…"},',
        '  "meta": {"module": "lib.base_codec", "risk": "safe", "elapsed_ms": 0.3,',
        '           "params": {"data": "###"}}',
        "}",
        "```",
        "",
        "`meta` 字段：`module`（对应 lib 模块）、`risk`、`elapsed_ms`、`params`（脱敏回显）、"
        "`warnings`（可选）、`truncated`（结果被截断时出现）。",
        "",
        "### 1.3 错误码",
        "",
        "| code | 含义 |",
        "| --- | --- |",
        "| `invalid_op` | 未知 op |",
        "| `invalid_param` | 不认识的参数名 |",
        "| `missing_param` | 缺少必填参数 |",
        "| `type_error` | 参数类型不符 / 无法转换 |",
        "| `range_error` | 取值不在允许范围（choices / min / max） |",
        "| `lib_error` | lib 函数抛出的业务异常（如 Base64 输入非法） |",
        "| `timeout` | 超时 |",
        "| `network` | 连接 / DNS / 代理 / 证书等网络错误 |",
        "| `io` | 文件不存在、无权限等 |",
        "| `unsupported` | 环境不支持（如缺少 node / Pillow） |",
        "| `internal` | 未预期异常（stderr 有堆栈） |",
        "",
        "### 1.4 参数类型与宽松转换",
        "",
        "| type | JSON 输入 | 说明 |",
        "| --- | --- | --- |",
        "| `str` | string | 数字会被转成字符串 |",
        "| `int` | number / string | `\"3\"`、`\"0xff\"`、`3.0` 均可 |",
        "| `float` | number / string | `\"6.0\"` 可用 |",
        "| `bool` | bool / string / number | `true`/`\"true\"`/`\"1\"`/`\"是\"` 均为真 |",
        "| `list` | array / string | 字符串按换行 / 中英文逗号 / 分号切分 |",
        "| `dict` | object / string | 字符串按 JSON 解析 |",
        "| `hex` | string | 十六进制文本 → bytes，容忍空格 / `0x` / `\\x` / 冒号 / 逗号 |",
        "| `any` | 任意 | 原样透传给 lib |",
        "",
        "### 1.5 结果序列化",
        "",
        "- `bytes` → `{\"hex\": ..., \"length\": n, \"text\": \"…\"|\"null\", \"is_text\": bool}`；",
        "- `Path` → 绝对路径字符串；",
        "- `dataclass` → 优先 `to_dict()`，否则按字段展开；",
        "- `tuple` → 数组；声明了 `unpack` 的 op 会转成具名字典；",
        "- `set` → 排序后的数组；",
        "- 非有限浮点 → 字符串；其他未知对象 → `repr()` 截断。",
        "",
        "### 1.6 路径约定",
        "",
        "所有文件类参数（`path` / `out_path` / `carrier_path` / `zip_path` …）：",
        "",
        "- 绝对路径原样使用；",
        "- **相对路径基于项目根**（`" + str(PROJECT_ROOT) + "`），与宿主进程 CWD 无关；",
        "- 输出路径留空时回落到该工具的默认目录（`output/…` 或配置里的目录）。",
        "",
        "### 1.7 自动注入参数",
        "",
        "lib 函数签名里的 `log` / `progress` / `stop` 由分发器自动注入，调用者不需要也无法手工传：",
        "",
        "- `log(msg)` / `progress(*args)` → 写 stderr，前缀为 `cn_xxx/op `；",
        "- `stop` → 本次调用专属的 `threading.Event`（预留给未来取消能力）。",
        "",
        "### 1.8 脱敏与结果上限",
        "",
        "- `meta.params` 中匹配 `password / pwd / secret / token / api_key / "
        "authorization / cookie / private_key / salt` 等键一律显示 `***`；",
        "- 序列化结果超过 400,000 字符时，`data` 变成 "
        "`{truncated, chars, limit, preview, note}`，`meta.truncated=true`。",
        "",
        "### 1.9 风险等级",
        "",
        "| risk | 含义 |",
        "| --- | --- |",
    ]
    for risk, label in RISK_LABELS.items():
        lines.append(f"| `{risk}` | {label} |")
    lines += [
        "",
        "`network` / `intrusive` / `long` 类能力请只用于已授权目标，并先用小参数试探。",
        "",
        "### 1.10 线程型长任务",
        "",
        "压缩包爆破（`zip_crack`）与哈希爆破（`md5_crack`）在服务端同步执行，"
        "但都带 `max_seconds` 上限；到点会停止线程并返回 `status=stopped/timeout` "
        "与已收集的事件日志，不会让调用无限挂起。",
        "",
        "## 2. 快速示例",
        "",
        "```json",
        '{"tool": "cn_codec", "op": "base64_encrypt", "params": {"data": "flag"}}',
        '{"tool": "cn_crypto", "op": "md5_hex", "params": {"data": "flag"}}',
        '{"tool": "cn_crypto", "op": "factor", "params": {"n": 123456789}}',
        '{"tool": "cn_web", "op": "run", "params": {"target": "https://example.com", '
        '"with_robots": true}}',
        '{"tool": "cn_scan", "op": "port_scan", "params": {"host": "192.168.1.1", '
        '"ports": "80,443,1-1024"}}',
        "```",
        "",
        "## 3. 工具与 op 总表",
        "",
    ]

    for group in groups:
        lines += [
            f"### {group.name} —— {group.title}",
            "",
            group.summary,
            "",
        ]
        if group.guide:
            lines += [f"> {group.guide}", ""]
        lines += [
            "| op | 参数（`*` = 必填） | 返回 | 风险 |",
            "| --- | --- | --- | --- |",
        ]
        for spec in group.ops:
            params = ", ".join(
                f"`{param.name}{'*' if param.required else ''}`"
                for param in spec.params) or "—"
            lines.append(
                f"| `{spec.name}` | {_cell(params)} | {_cell(spec.returns)} | "
                f"`{spec.risk}` |")
        lines.append("")
        lines.append("<details><summary>参数详情</summary>")
        lines.append("")
        for spec in group.ops:
            lines.append(f"**`{spec.name}`**（{spec.module}）—— {spec.summary}")
            lines.append("")
            if spec.params:
                for param in spec.params:
                    lines.append(f"- {_param_text(param)}")
            else:
                lines.append("- 无参数")
            lines.append(f"- 返回：{spec.returns}")
            if spec.example is not None:
                lines.append(
                    f"- 示例：`{json.dumps(spec.example, ensure_ascii=False)}`")
            if spec.notes:
                lines.append(f"- 备注：{spec.notes}")
            lines.append("")
        lines.append("</details>")
        lines.append("")

    lines += _plugin_section()

    lines += [
        "## 5. 未暴露的方法",
        "",
        "以下 lib 能力**刻意**没有做成 MCP op，原因是它们依赖桌面 / 进程生命周期：",
        "",
        "| 模块 | 未暴露内容 | 原因 |",
        "| --- | --- | --- |",
        "| `lib.key_simulator` | 全部 | 向当前焦点窗口注入键盘事件，属于桌面交互，"
        "远程调用无意义且有风险 |",
        "| `lib.lan_share` | `ShareServer` / `ShareState` / `ShareRequestHandler` | "
        "需要在本进程托管 HTTP 服务与文件目录，属于 GUI 生命周期；"
        "客户端能力（channels/join/files/upload/download/leave）已暴露 |",
        "| 各模块 | `main(argv)` 入口 | 命令行入口，工具调用不需要 |",
        "| `lib.web_fuzz` 等 | 图形化辅助（`to_text` 已暴露，`row` 类转换未暴露） | "
        "面向界面表格的格式转换 |",
        "",
        "## 6. 环境依赖与配置",
        "",
        "- Python 3.10+（本项目在 3.12 上验证）；",
        "- 必需：`mcp`（MCP SDK）、`requests`；",
        "- 可选：`Pillow`（cn_image）、`PyYAML`（指纹规则）、`node`（JSFuck 解码）；",
        "- 插件依赖：各插件自带 `requirements.txt`（sqlmap 纯标准库；OneForAll 需 "
        "`fire`/`tldextract` 等；FileSensor 需 `scrapy`；flaskcookie 需 `flask` + "
        "`itsdangerous`；TruffleHog 是独立 exe）；",
        "- 配置：读取 `%APPDATA%/28zenro/config.json`（与 GUI/CLI 共享），"
        "**只读不写**；缺失时回退内置默认值；",
        "- 代理池：启动时把 `proxy_pool` 节装载进 `lib.proxy_pool` 全局单例，"
        "网络类工具自动复用；",
        "- 日志：全部写 stderr；stdio 传输下 stdout 只承载 MCP 协议帧。",
        "",
        "## 7. 自检",
        "",
        "```bash",
        "python mcp/server.py --selftest     # 契约审计 + 冒烟用例（含插件体检）",
        "python mcp/server.py --audit        # 只做契约 vs lib 签名审计",
        "python mcp/server.py --list         # 打印工具与 op 清单",
        "python mcp/server.py --gen-docs     # 重新生成本文件",
        "python mcp/server.py --export mcp/docs/ops.json   # 导出机器可读契约",
        "```",
        "",
        "审计规则：op 声明的每个参数都必须存在于真实 lib 函数签名；lib 的必填参数必须有声明；"
        "`log` / `progress` / `stop` 例外。",
        "",
    ]
    return "\n".join(lines)


def _plugin_section() -> list[str]:
    """§4 第三方插件：从 pluginkit 动态读取发现结果。"""
    lines = [
        "## 4. 第三方插件（`mcp/plugins/`）",
        "",
        "插件是独立的三方工具（完整源码 / 可执行文件），本项目只做**封装层**，"
        "不修改插件本身。统一遵守四条硬约定：",
        "",
        "1. **不走 shell**：参数以数组逐个透传，天然免疫命令注入；",
        "2. **隔离 stdin**：stdio 模式下父进程 stdin 是 MCP 协议通道，插件默认接 "
        "`DEVNULL`（sqlmap 会读 stdin 等回车，这一点尤其关键）；",
        "3. **超时上限**：每个 op 都有 `max_seconds`，到点终止子进程；",
        "4. **输出有界**：超长输出保留头尾并标记 `output_truncated`；"
        "结果稳定字段为 `success / returncode / duration_ms / stdout_tail / stderr_tail`。",
        "",
        "| 插件 | key | 类型 | 专用工具组 | 说明 |",
        "| --- | --- | --- | --- | --- |",
    ]
    try:
        from .pluginkit.runtime import PLUGINS
    except Exception:  # pragma: no cover - 插件层不可用
        PLUGINS = {}
    for key, plugin in sorted(PLUGINS.items()):
        lines.append(
            f"| {plugin.name} | `{key}` | {plugin.kind} | `cn_{key}` | "
            f"{_cell(plugin.notes or '—')} |")
    lines += [
        "",
        "通用入口：`cn_plugin`（`list` / `info` / `check` / `run`）。"
        "未做专用适配的新插件，直接 `cn_plugin(op=\"run\", "
        "params={\"plugin\": \"<key>\", \"args\": [...]})` 调用。",
        "",
        "### 4.1 新增插件",
        "",
        "1. 把工具放进 `mcp/plugins/<目录>/`；",
        "2. 想零代码接入 → 在目录里放 `plugin.json`：",
        "",
        "```json",
        "{",
        '  "key": "mytool",',
        '  "name": "MyTool",',
        '  "kind": "python",',
        '  "entry": "mytool.py",',
        '  "version_cmd": ["--version"],',
        '  "homepage": "https://example.com/mytool",',
        '  "notes": "一句话说明"',
        "}",
        "```",
        "",
        "3. 想要语义化 op → 在 `28zenro_mcp/pluginkit/` 加 `<插件>.py` 导出 "
        "`GROUP`，并把模块名加进该包的 `_MODULES`。",
        "",
        "### 4.2 插件风险",
        "",
        "插件多为主动探测 / 爆破类工具（sqlmap、OneForAll、FileSensor），"
        "风险等级在 `meta.risk` 中标为 `intrusive` / `network` / `long`，"
        "**仅可用于已授权目标**；TruffleHog 扫描结果里可能含真实密钥，注意外泄。",
        "",
    ]
    return lines


def write_contract(groups: Iterable[Group], path: str | Path) -> Path:
    target = Path(path)
    if not target.is_absolute():
        target = PROJECT_ROOT / "mcp" / target
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_contract(list(groups)), encoding="utf-8")
    return target
