# 28zenro MCP Server

基于本项目 `lib/` 的 **255 个方法** + `mcp/plugins/` 下的 **5 个第三方工具**，
构建的 MCP (Model Context Protocol) 服务器。把密码学、编解码、Web 信息收集、
扫描爆破、图片隐写、大模型、以及 sqlmap / TruffleHog / OneForAll 等三方工具
统一包装成 **16 个工具（279 个 op）**，供 Claude Desktop / Cursor /
Cherry Studio / 自研 Agent 调用。

- 文档：[CONTRACT.md](CONTRACT.md)（方法契约，全部 op 的参数 / 返回 / 风险）
- 机器可读契约：[docs/ops.json](docs/ops.json)（`python mcp/server.py --export` 生成）
- 旧入口 `../mcp_server.py` 只覆盖 17 个 Web 工具；本目录是**全量重写版**，
  两套互不依赖，可并存。

## 目录结构

```
mcp/
├── server.py                 # 入口：python mcp/server.py [--http|--list|--selftest…]
├── CONTRACT.md               # 方法契约（自动生成，勿手改）
├── mcp.json                  # 宿主配置示例
├── requirements.txt
├── docs/ops.json             # 机器可读契约
├── plugins/                  # 第三方工具（原样存放）
│   ├── sqlmap-master/  trufflehog/  OneForAll/
│   └── FileSensor/  flask-session-cookie-manager-master/
├── 28zenro_mcp/           # 真正的 Python 包
│   ├── bootstrap.py          # 路径注入 / 只读配置 / 代理池 / stderr 日志
│   ├── envelope.py           # 统一返回信封 / 序列化 / 脱敏 / 大纲保护
│   ├── contract.py           # Param / Op / Group / 校验 / 分发 / 审计
│   ├── ops/                  # 内置 op 声明（唯一事实来源）
│   │   ├── codec.py  data.py  crypto.py  image.py  web.py
│   │   ├── scan.py   attack.py  llm.py   misc.py    help.py
│   │   └── _helpers.py       # 路径解析 / 配置默认值 / 线程任务轮询
│   ├── pluginkit/            # 第三方插件封装层
│   │   ├── runtime.py        # 插件发现 + 受控子进程（无 shell / stdin 隔离 / 超时）
│   │   ├── generic.py        # cn_plugin 通用入口
│   │   └── sqlmap.py  trufflehog.py  oneforall.py
│   │       flaskcookie.py  filesensor.py
│   ├── app.py                # FastMCP 组装（工具 + 资源）
│   ├── cli.py                # 命令行实现
│   ├── docgen.py             # CONTRACT.md / ops.json 生成
│   └── selftest.py           # 契约审计 + 冒烟用例（含插件体检）
└── tests/                    # unittest：契约 / 分发 / 插件 / stdio 端到端
```

> `mcp/` 目录**故意没有 `__init__.py`**。PyPI 上的 MCP SDK 包名就叫 `mcp`，
> 如果这里也做成包，`import mcp.server.fastmcp` 会被本地目录遮蔽。真正的包是
> `mcp/28zenro_mcp/`。

## 快速开始

```bash
# 1) 依赖
pip install -r mcp/requirements.txt

# 2) 自检（契约审计 + 冒烟用例，不需要联网）
python mcp/server.py --selftest

# 3) stdio 模式（宿主以子进程拉起，最常用）
python mcp/server.py

# 4) HTTP 模式（streamable-http，便于远程调试）
#    注意：这个进程必须一直开着，宿主才连得上；Ctrl+C 即停止服务
python mcp/server.py --http --port 8000
#    endpoint: http://127.0.0.1:8000/mcp
#    Windows 也可直接双击 start_http.cmd（默认端口 8000，可传参改端口）

# 其他只读命令
python mcp/server.py --list          # 工具与 op 清单
python mcp/server.py --show base64_encrypt
python mcp/server.py --audit         # 契约 vs lib 签名
python mcp/server.py --gen-docs      # 重新生成 CONTRACT.md
python mcp/server.py --export        # 重新生成 docs/ops.json
```

> ⚠️ **stdio 与 HTTP 是两种互斥的启动方式**
> `python mcp/server.py`（不带参数）= stdio：进程只读写标准输入输出，
> **不监听任何端口**，此时去连 `http://127.0.0.1:8000/mcp` 一定报
> “目标服务拒绝连接”。要用 HTTP 连接器，必须用 `--http` / `start_http.cmd`
> 启动，并让它保持在运行状态。

## 在 GUI 里查看 / 管理已注册工具

状态管理页（侧边栏「MCP 服务」→「工具注册」标签页）直接读取
``28zenro_mcp.ops`` 的注册表展示**全部工具组与 op 明细**（17 组 / 288 op，
含插件）：

- 左列勾选 = 注册、取消勾选 = 禁用该工具组；``cn_help`` 是宿主的发现 /
  契约入口，固定注册不可禁用；
- 右侧表格列出选中组的 op 名称、风险等级、返回与说明；
- 「保存注册配置」写入共享 ``config.json`` 的 ``mcp_server.disabled_groups``，
  服务端在 ``build_app`` 注册时按此名单过滤（stdio / HTTP 生效一致，
  保存后需重启服务生效）；
- 也可手工编辑 ``config.json`` 的 ``mcp_server.disabled_groups``（如
  `["cn_attack"]`）。

## 宿主配置

### 方式 A：stdio（推荐，宿主自己拉起进程，无需端口）

`mcp/mcp.json` 可直接抄进 Claude Desktop / Cursor 的配置：

```json
{
  "mcpServers": {
    "28zenro": {
      "command": "python",
      "args": ["D:/Code/pythonCode/CTFcrypto/mcp/server.py"],
      "env": { "PYTHONIOENCODING": "utf-8" }
    }
  }
}
```

- **Claude Desktop**：`%APPDATA%\Claude\claude_desktop_config.json`
- **Cursor**：`%USERPROFILE%\.cursor\mcp.json`
- **Cherry Studio / 其他**：类型选 stdio，命令 `python`，
  参数填 `<项目根>/mcp/server.py`

### 方式 B：HTTP 连接器（需要先手动启动服务）

1. 启动并**保持运行**（另开一个终端）：

   ```powershell
   cd D:\Code\pythonCode\CTFcrypto\mcp
   .\start_http.cmd            # 或：python .\server.py --http --port 8000
   ```

   启动成功会打印：
   `[28zenro] 以 streamable-http 启动：http://127.0.0.1:8000/mcp`

2. 在宿主里填 MCP URL：`http://127.0.0.1:8000/mcp`
   （传输类型 streamable-http；回环地址可直接用 http）

3. 停止服务：在那个终端按 `Ctrl+C`。

> 常见坑：只运行了 `python .\server.py`（stdio 模式）就去连 HTTP URL，
> 必然「目标服务拒绝连接」。判断依据看启动日志最后一行是
> `以 stdio 启动` 还是 `以 streamable-http 启动`。

## 调用约定

所有工具签名完全一致（这是本服务的核心约定）：

```python
cn_<group>(op: str, params: dict | None = None) -> dict
```

```jsonc
// 请求
{"name": "cn_codec", "arguments": {"op": "base64_encrypt", "params": {"data": "flag"}}}

// 成功
{"ok": true, "tool": "cn_codec", "op": "base64_encrypt", "data": "ZmxhZw==",
 "meta": {"module": "lib.base_codec", "risk": "safe", "elapsed_ms": 0.4,
          "params": {"data": "flag"}}}

// 失败
{"ok": false, "tool": "cn_codec", "op": "base64_decrypt",
 "error": {"code": "lib_error", "message": "Base64 解码失败：…"},
 "meta": {...}}
```

要点（完整见 [CONTRACT.md](CONTRACT.md) §1）：

| 约定 | 内容 |
| --- | --- |
| op 名 | 默认等于 `lib` 函数名 |
| 参数名 | 默认等于 `lib` 形参名，不改名 |
| 未知参数 | 直接 `invalid_param`，不静默丢弃 |
| 宽松转换 | `"3"`→3、`"true"`→True、`"a,b"`→[a,b]、`"0xff"`→255 |
| `hex` 类型 | 十六进制文本 → bytes（容忍空格 / `0x` / `\x`） |
| 自动注入 | `log` / `progress` / `stop` 由服务端注入，调用者不传 |
| 路径 | 相对路径**基于项目根**（`CTFcrypto/`），与宿主 CWD 无关 |
| 脱敏 | `meta.params` 里 password / secret / token / key / cookie → `***` |
| 大纲保护 | 单次结果 > 400k 字符时返回 `preview` + `meta.truncated` |
| 风险等级 | `safe` / `read` / `write` / `network` / `intrusive` / `long` |
| 错误码 | `invalid_op` `invalid_param` `missing_param` `type_error` `range_error` `lib_error` `timeout` `network` `io` `unsupported` `internal` |

## 工具组一览

| 工具 | op 数 | 内容 |
| --- | ---: | --- |
| `cn_help` | 5 | 发现 / 契约查询 / 审计 / 版本 / 导出 |
| `cn_codec` | 67 | Base16/32/64/58/62/85/91/92、UU/XXencode、凯撒、猪圈、ROT、进制互转、URL/QP/HTML/Unicode 转义、ASCII、编码转换、Brainfuck/Ook!/jother/JSFuck |
| `cn_data` | 17 | JSON 美化/压缩/分析/摊平/构建、文件↔十六进制、文本对比与去重 |
| `cn_crypto` | 64 | MD5/SHA/SHA3、哈希长度扩展、SM2/SM3/SM4、RSA 分解与攻击、JWT、密文识别 |
| `cn_image` | 14 | 图片↔Base64、LSB 隐写（容量/嵌入/提取/盲猜）、可见水印 |
| `cn_web` | 22 | Web Fuzz、JSFinder、指纹识别、历史收录、CIDR 扫描、DNS |
| `cn_scan` | 13 | 目录爆破、端口扫描、参数 Fuzz、源码泄露、多地 Ping |
| `cn_attack` | 24 | SSTI、MySQL 指纹/爆破、公众号凭证、ZIP 解压/伪加密/CRC/爆破、哈希爆破 |
| `cn_llm` | 7 | 模型列表、对话、向量、OCR、中英互译 |
| `cn_misc` | 22 | 番茄钟、代理池、局域网共享客户端 |
| `cn_plugin` | 4 | 第三方插件：发现 / 详情 / 体检 / 受控直调 |
| `cn_sqlmap` | 7 | sqlmap：注入探测、dbs/tables/columns/dump、tamper 枚举 |
| `cn_trufflehog` | 4 | TruffleHog：Git / 目录 / Docker 密钥扫描（NDJSON 解析） |
| `cn_oneforall` | 4 | OneForAll：子域名收集 + 结果解析 + 历史结果 |
| `cn_flaskcookie` | 3 | Flask session cookie 解码 / 签发（Flask 3.x 原生回退） |
| `cn_filesensor` | 2 | FileSensor：敏感文件探测 + 命中解析 |

## 第三方插件（`mcp/plugins/`）

插件是独立的三方工具，本项目只做**封装层**（不改插件源码）。已发现 5 个：

| 插件 | key | 类型 | 专用工具组 | 能力 |
| --- | --- | --- | --- | --- |
| TruffleHog 3.99 | `trufflehog` | exe | `cn_trufflehog` | Git / 目录 / Docker 密钥扫描 |
| sqlmap 1.8.9 | `sqlmap` | python | `cn_sqlmap` | SQL 注入检测与取数 |
| OneForAll 0.4.5 | `oneforall` | python | `cn_oneforall` | 子域名收集 |
| Flask Session Cookie Manager | `flaskcookie` | python | `cn_flaskcookie` | session cookie 编解码 |
| FileSensor 0.2 | `filesensor` | python | `cn_filesensor` | 敏感文件探测 |

封装层遵守四条硬约定：

1. **不走 shell**：`argv` 是数组逐个透传，含空格 / `$()` / `;` 的参数只是普通字符串；
2. **隔离 stdin**：stdio 模式下父进程 stdin 是 MCP 协议通道，插件默认接 `DEVNULL`
   （sqlmap 会读 stdin 等回车，这条尤其关键）；
3. **超时上限**：每个 op 都有 `max_seconds`，到点终止；
4. **输出有界 + 结构化**：超长输出保留头尾（`output_truncated`），
   统一返回 `success / returncode / duration_ms / stdout_tail / stderr_tail`，
   适配器再补业务字段。

```jsonc
// 密钥扫描：结果已解析成 findings（detector / verified / 文件行号）
{"tool": "cn_trufflehog", "op": "scan_filesystem", "params": {"path": "output/src"}}

// SQL 注入：逐步取数（每次调用独立 output/sqlmap/<目标>-<时间>/）
{"tool": "cn_sqlmap", "op": "scan", "params": {"url": "http://t/item.php?id=1", "level": 2}}
{"tool": "cn_sqlmap", "op": "dbs",  "params": {"url": "http://t/item.php?id=1"}}
{"tool": "cn_sqlmap", "op": "dump", "params": {"url": "http://t/item.php?id=1", "db": "app", "table": "users"}}

// 子域名收集：结束后自动解析 results/ 导出
{"tool": "cn_oneforall", "op": "run",
 "params": {"target": "example.com", "brute": false, "alive": true, "max_seconds": 600}}

// Flask cookie：decode 给 secret 才验签；encode 需要 SECRET_KEY
{"tool": "cn_flaskcookie", "op": "decode",
 "params": {"cookie": "eyJ1c2VyIjoiYWRtaW4ifQ.xxx.yyy", "secret": "s3cr3t"}}
{"tool": "cn_flaskcookie", "op": "encode",
 "params": {"secret": "s3cr3t", "structure": {"user": "admin", "role": "admin"}}}

// 未做专用适配的新插件 → 通用受控直调
{"tool": "cn_plugin", "op": "run",
 "params": {"plugin": "trufflehog", "args": ["git", "https://github.com/o/r", "--json"]}}
```

插件实现细节：

- 发现逻辑在 [runtime.py](28zenro_mcp/pluginkit/runtime.py)：内置 5 个 spec +
  自动扫描 `plugins/*/plugin.json` 清单，新增工具可零代码接入；
- 每个插件一个适配器：[sqlmap.py](28zenro_mcp/pluginkit/sqlmap.py)、
  [trufflehog.py](28zenro_mcp/pluginkit/trufflehog.py)、
  [oneforall.py](28zenro_mcp/pluginkit/oneforall.py)、
  [flaskcookie.py](28zenro_mcp/pluginkit/flaskcookie.py)、
  [filesensor.py](28zenro_mcp/pluginkit/filesensor.py)；
- `cn_flaskcookie` 会先调插件 CLI；若返回 `[Encoding error]` / `[Decoding error]`
  （Flask 3.x 不兼容），自动回退到 `itsdangerous` 原生实现，返回里 `source=native`；
- `cn_trufflehog` 必须带 `--no-update`（否则自更新失败会直接退出），
  结果从 **stdout** 的 NDJSON 解析，日志在 stderr；
- `cn_plugin(op="check")` 可一次跑完全部插件的版本体检。

> ⚠️ 插件多为主动探测能力（sqlmap / OneForAll / FileSensor），
> `meta.risk` 标为 `intrusive` / `network` / `long`，**仅可用于已授权目标**。
> TruffleHog 的扫描结果可能包含真实密钥，注意不要外泄。

## 典型调用

```jsonc
// 编码
{"tool": "cn_codec", "op": "base64_decrypt", "params": {"data": "ZmxhZw=="}}

// 哈希 / RSA
{"tool": "cn_crypto", "op": "md5_hex", "params": {"data": "flag"}}
{"tool": "cn_crypto", "op": "factor", "params": {"n": 123456789}}
{"tool": "cn_crypto", "op": "sm4_ecb_encrypt",
 "params": {"data": "flag", "key": "0123456789abcdeffedcba9876543210"}}

// 隐写
{"tool": "cn_image", "op": "detect_params", "params": {"stego_path": "output/stego.png"}}

// Web
{"tool": "cn_web", "op": "web_fuzz", "params": {"target": "https://example.com", "with_robots": true}}
{"tool": "cn_scan", "op": "port_scan", "params": {"host": "192.168.1.1", "ports": "80,443,1-1024"}}

// 压缩包 / 哈希爆破（都有 max_seconds 上限）
{"tool": "cn_attack", "op": "zip_crack", "params": {"zip_path": "challenge.zip", "max_seconds": 120}}
{"tool": "cn_attack", "op": "md5_crack",
 "params": {"hash_value": "e10adc3949ba59abbe56e057f20f883e", "min_len": 1, "max_len": 6,
            "charset": "digits", "max_seconds": 60}}
```

## 与 GUI / CLI 的关系

- 配置：只读 `%APPDATA%/28zenro/config.json`（与 GUI、CLI 共享），**从不写回**；
- 代理池：启动时把 `proxy_pool` 节装载进 `lib.proxy_pool` 全局单例；
- 行为：与 `python cli.py <tool> --json` 完全一致（同一个 `lib.*` 函数）；
- 日志：全部写 stderr；stdio 模式下 stdout 只承载协议帧。

## 开发：新增一个 op

1. 在 `28zenro_mcp/ops/<组>.py` 里加一行声明（默认同名转发，无需写 handler）：

   ```python
   make_op(base_codec.base64_encrypt, "Base64 编码：文本 -> Base64 字符串。",
           [txt("data", required=True, desc="待编码文本")],
           returns="str：Base64 字符串", example={"data": "flag"}),
   ```

2. 需要返回元组整形 / 线程轮询 / 配置注入时用 `custom_op(...)` 写 handler；
3. `python mcp/server.py --selftest`：契约审计会用 `inspect.signature` 对照
   真实 lib 函数，参数写错会直接报出来；
4. `python mcp/server.py --gen-docs` 更新文档，`--export` 更新 JSON 契约。

新增一个工具组：新建 `ops/<名字>.py` 导出 `GROUP`，再把模块名加进
`ops/__init__.py` 的 `_MODULES` 即可（按模块容错导入，某个组挂了不影响其他组）。

## 测试

```bash
python -m unittest discover -s mcp/tests -v     # 56 个用例
python mcp/server.py --selftest                 # 55 项自检（含插件体检）
```

- `tests/test_contract.py`：命名唯一、字段完整、**契约与 lib 签名零漂移**；
- `tests/test_dispatch.py`：信封 / 校验 / 宽松转换 / 脱敏 / 序列化 / 路径；
- `tests/test_plugins.py`：插件发现、适配器、**无 shell / stdin 隔离 / 未知插件**
  等安全约束、Flask cookie 原生回退；
- `tests/test_stdio.py`：真的以子进程启动服务，走完 `initialize → tools/list →
  tools/call → resources/list`。

## 常见问题

**连接验证失败：目标服务拒绝连接（HTTP 连接器）**
九成是「用 stdio 模式启动了服务，却去连 HTTP URL」。检查启动日志最后一行：

- `以 stdio 启动` → 没有监听端口，HTTP URL 必然连不上；
  要么改用 stdio 方式接入（推荐），要么改用
  `python mcp/server.py --http` / `start_http.cmd` 重新启动；
- `以 streamable-http 启动：http://127.0.0.1:8000/mcp` → 端点正常，
  确认 URL 带 `/mcp` 后缀、端口一致、进程没有被关掉。

自检端点是否活着（自带探针，纯标准库，不依赖 mcp SDK）：

```powershell
python mcp/tests/probe_http.py                  # 默认 127.0.0.1:8000
python mcp/tests/probe_http.py --port 8765      # 换端口
python mcp/tests/probe_http.py --url http://127.0.0.1:8000/mcp
```

正常输出示例：

```
→ 探测 http://127.0.0.1:8000/mcp
[ok] initialize：serverName=28zenro version=… protocol=2025-06-18 session=…
[ok] tools/list：10 个工具 → cn_help, cn_codec, …
[ok] tools/call：cn_help/version → 10 个工具 / 255 个 op，python 3.12.6
```

> 想用 curl 手测的话，PowerShell 下 `-d '{...}'` 的引号会被吞掉导致 400，
> 请把 JSON 存成文件后用 `--data-binary "@body.json"`，或直接用上面的探针。

**为什么 `import mcp` 还是 SDK？**
`mcp/` 目录没有 `__init__.py`，Python 会把已安装的 `mcp` 包当作正式包优先解析，
本地目录只是普通目录。实现都在 `28zenro_mcp/`。

**Windows 控制台输出乱码 / 报 UnicodeEncodeError？**
CLI 模式已自动把 stdout/stderr 切到 UTF-8；stdio 模式下 MCP SDK 自己也用 UTF-8
包装 `sys.stdout.buffer`。

**没装 Pillow / PyYAML / node 会怎样？**
对应的整个工具组会被跳过（启动时 stderr 有告警），其余工具照常工作；
`cn_help(op="version")` 能看到实际加载的组。

**爆破类工具会不会把调用卡死？**
`zip_crack` / `md5_crack` 都带 `max_seconds`，到点自动停止并返回当前状态；
网络类工具有各自的 `timeout`。目录/端口/参数爆破请先用小范围参数试探。

**授权提醒**
`network` / `intrusive` 类 op（子域名爆破、网段扫描、目录/端口/参数爆破、
SSTI、MySQL 爆破等）仅可用于**已获授权**的目标。
