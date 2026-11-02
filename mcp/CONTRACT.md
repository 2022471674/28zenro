# 28zenro MCP 方法契约（v1.0.0）

> 本文件由 `python mcp/server.py --gen-docs` 从 `28zenro_mcp/ops/*.py` 的 op 声明自动生成。**改契约请改代码，不要手改本文。**

工具组 17 个，op 合计 289 个。所有 op 均直接复用 `D:\Code\pythonCode\CTFcrypto\lib` 下的纯逻辑函数，行为与 `python cli.py <tool> --json` 一致。

## 1. 调用约定

### 1.1 统一签名

```python
cn_<group>(op: str, params: dict | None = None) -> dict
```

- 工具名：`cn_` 前缀 + 分组名（见 §3）；
- `op`：操作名，默认等于 `lib` 函数名；
- `params`：参数对象，键名默认等于 `lib` 形参名；
- 未知 op → `invalid_op`（hint 里带可用 op 清单）；
- 未知参数 → `invalid_param`（不做静默丢弃）。

### 1.2 返回信封

成功：

```json
{
  "ok": true,
  "tool": "cn_codec",
  "op": "base64_encrypt",
  "data": "ZmxhZw==",
  "meta": {
    "module": "lib.base_codec",
    "risk": "safe",
    "elapsed_ms": 0.42,
    "params": {"data": "flag"}
  }
}
```

失败：

```json
{
  "ok": false,
  "tool": "cn_codec",
  "op": "base64_decrypt",
  "error": {"code": "lib_error", "message": "Base64 解码失败：…"},
  "meta": {"module": "lib.base_codec", "risk": "safe", "elapsed_ms": 0.3,
           "params": {"data": "###"}}
}
```

`meta` 字段：`module`（对应 lib 模块）、`risk`、`elapsed_ms`、`params`（脱敏回显）、`warnings`（可选）、`truncated`（结果被截断时出现）。

### 1.3 错误码

| code | 含义 |
| --- | --- |
| `invalid_op` | 未知 op |
| `invalid_param` | 不认识的参数名 |
| `missing_param` | 缺少必填参数 |
| `type_error` | 参数类型不符 / 无法转换 |
| `range_error` | 取值不在允许范围（choices / min / max） |
| `lib_error` | lib 函数抛出的业务异常（如 Base64 输入非法） |
| `timeout` | 超时 |
| `network` | 连接 / DNS / 代理 / 证书等网络错误 |
| `io` | 文件不存在、无权限等 |
| `unsupported` | 环境不支持（如缺少 node / Pillow） |
| `internal` | 未预期异常（stderr 有堆栈） |

### 1.4 参数类型与宽松转换

| type | JSON 输入 | 说明 |
| --- | --- | --- |
| `str` | string | 数字会被转成字符串 |
| `int` | number / string | `"3"`、`"0xff"`、`3.0` 均可 |
| `float` | number / string | `"6.0"` 可用 |
| `bool` | bool / string / number | `true`/`"true"`/`"1"`/`"是"` 均为真 |
| `list` | array / string | 字符串按换行 / 中英文逗号 / 分号切分 |
| `dict` | object / string | 字符串按 JSON 解析 |
| `hex` | string | 十六进制文本 → bytes，容忍空格 / `0x` / `\x` / 冒号 / 逗号 |
| `any` | 任意 | 原样透传给 lib |

### 1.5 结果序列化

- `bytes` → `{"hex": ..., "length": n, "text": "…"|"null", "is_text": bool}`；
- `Path` → 绝对路径字符串；
- `dataclass` → 优先 `to_dict()`，否则按字段展开；
- `tuple` → 数组；声明了 `unpack` 的 op 会转成具名字典；
- `set` → 排序后的数组；
- 非有限浮点 → 字符串；其他未知对象 → `repr()` 截断。

### 1.6 路径约定

所有文件类参数（`path` / `out_path` / `carrier_path` / `zip_path` …）：

- 绝对路径原样使用；
- **相对路径基于项目根**（`D:\Code\pythonCode\CTFcrypto`），与宿主进程 CWD 无关；
- 输出路径留空时回落到该工具的默认目录（`output/…` 或配置里的目录）。

### 1.7 自动注入参数

lib 函数签名里的 `log` / `progress` / `stop` 由分发器自动注入，调用者不需要也无法手工传：

- `log(msg)` / `progress(*args)` → 写 stderr，前缀为 `cn_xxx/op `；
- `stop` → 本次调用专属的 `threading.Event`（预留给未来取消能力）。

### 1.8 脱敏与结果上限

- `meta.params` 中匹配 `password / pwd / secret / token / api_key / authorization / cookie / private_key / salt` 等键一律显示 `***`；
- 序列化结果超过 400,000 字符时，`data` 变成 `{truncated, chars, limit, preview, note}`，`meta.truncated=true`。

### 1.9 风险等级

| risk | 含义 |
| --- | --- |
| `safe` | 纯计算 |
| `read` | 只读文件 |
| `write` | 写文件 |
| `network` | 网络请求 |
| `intrusive` | 主动探测 |
| `long` | 可能耗时 |

`network` / `intrusive` / `long` 类能力请只用于已授权目标，并先用小参数试探。

### 1.10 线程型长任务

压缩包爆破（`zip_crack`）与哈希爆破（`md5_crack`）在服务端同步执行，但都带 `max_seconds` 上限；到点会停止线程并返回 `status=stopped/timeout` 与已收集的事件日志，不会让调用无限挂起。

## 2. 快速示例

```json
{"tool": "cn_codec", "op": "base64_encrypt", "params": {"data": "flag"}}
{"tool": "cn_crypto", "op": "md5_hex", "params": {"data": "flag"}}
{"tool": "cn_crypto", "op": "factor", "params": {"n": 123456789}}
{"tool": "cn_web", "op": "run", "params": {"target": "https://example.com", "with_robots": true}}
{"tool": "cn_scan", "op": "port_scan", "params": {"host": "192.168.1.1", "ports": "80,443,1-1024"}}
```

## 3. 工具与 op 总表

### cn_help —— 元工具：发现 / 契约 / 自检

工具发现与契约查询：list（全部工具与 op）、help（单个 op 的参数表）、audit（契约与 lib 签名一致性自检）、version、export（全量契约 JSON）。

> 任何不确定 op 名或参数时，先调 cn_help(op="list")，再 cn_help(op="help")。

| op | 参数（`*` = 必填） | 返回 | 风险 |
| --- | --- | --- | --- |
| `list` | `with_params` | dict：{tool_count, op_count, tools: [{tool, title, summary, ops}]} | `safe` |
| `help` | `op`, `tool` | dict：op 契约（参数表 / 返回 / 风险 / 示例）或工具 schema | `safe` |
| `audit` | — | dict：{ok, issue_count, issues, checked_ops} | `safe` |
| `version` | — | dict：版本与环境信息 | `safe` |
| `export` | — | dict：{server, conventions, tools: [...]} | `safe` |

<details><summary>参数详情</summary>

**`list`**（cn_help）—— 列出全部工具与 op 名称（工具发现入口）。

- `with_params`，默认 `False`，`bool`：是否连同每个 op 的完整参数表一起返回（体积大）
- 返回：dict：{tool_count, op_count, tools: [{tool, title, summary, ops}]}

**`help`**（cn_help）—— 查询某个 op 的完整参数表（推荐按 op 名查）。

- `op`，默认 `''`，`str`：op 名称，如 ``base64_encrypt``
- `tool`，默认 `''`，`str`：工具名，如 ``cn_codec``（与 op 二选一）
- 返回：dict：op 契约（参数表 / 返回 / 风险 / 示例）或工具 schema

**`audit`**（cn_help）—— 契约审计：核对声明的参数与 lib 真实函数签名是否一致。

- 无参数
- 返回：dict：{ok, issue_count, issues, checked_ops}

**`version`**（cn_help）—— 返回服务版本、运行环境、lib 模块清单与统计。

- 无参数
- 返回：dict：版本与环境信息

**`export`**（cn_help）—— 导出完整契约（机器可读 JSON），可用于自动生成客户端代码或文档。

- 无参数
- 返回：dict：{server, conventions, tools: [...]}

</details>

### cn_codec —— 编解码 / 进制 / 深奥语言

文本与编码互转：Base16/32/64/58/62/85/91/92、UUencode、XXencode、凯撒与猪圈、ROT13/47/N、任意进制互转、URL / QP / HTML / Unicode 转义、ASCII 码点、编码转换、Brainfuck / Ook! / jother / JSFuck。

> 全部为纯计算 op，无副作用。解码类 op 输入非法时返回 ok=false，错误码为 lib_error，message 里带原因。

| op | 参数（`*` = 必填） | 返回 | 风险 |
| --- | --- | --- | --- |
| `base16_encrypt` | `data*` | str：Base16 大写字符串 | `safe` |
| `base16_decrypt` | `data*` | str：解码后的文本 | `safe` |
| `base32_encrypt` | `data*` | str：Base32 字符串 | `safe` |
| `base32_decrypt` | `data*` | str：解码后的文本 | `safe` |
| `base64_encrypt` | `data*` | str：Base64 字符串 | `safe` |
| `base64_decrypt` | `data*` | str：解码后的文本 | `safe` |
| `base64_urlsafe_encrypt` | `data*` | str：URL 安全 Base64 字符串 | `safe` |
| `base64_urlsafe_decrypt` | `data*` | str：解码后的文本 | `safe` |
| `base85_encrypt` | `data*`, `variant` | str：Base85 字符串 | `safe` |
| `base85_decrypt` | `data*`, `variant` | str：解码后的文本 | `safe` |
| `base58_encrypt` | `data*` | str：Base58 字符串 | `safe` |
| `base58_decrypt` | `data*` | str：解码后的文本 | `safe` |
| `base62_encrypt` | `data*` | str：Base62 字符串 | `safe` |
| `base62_decrypt` | `data*` | str：解码后的文本 | `safe` |
| `base91_encrypt` | `data*` | str：Base91 字符串 | `safe` |
| `base91_decrypt` | `data*` | str：解码后的文本 | `safe` |
| `base92_encrypt` | `data*` | str：Base92 字符串 | `safe` |
| `base92_decrypt` | `data*` | str：解码后的文本 | `safe` |
| `uuencode_encrypt` | `data*` | str：uuencode 文本 | `safe` |
| `uuencode_decrypt` | `data*` | str：解码后的文本 | `safe` |
| `xxencode_encrypt` | `data*` | str：xxencode 文本 | `safe` |
| `xxencode_decrypt` | `data*` | str：解码后的文本 | `safe` |
| `caesar_encrypt` | `data*`, `shift*` | str：密文 | `safe` |
| `caesar_decrypt` | `data*`, `shift*` | str：明文 | `safe` |
| `pigpen_encrypt` | `data*` | str：猪圈符号密文 | `safe` |
| `pigpen_decrypt` | `data*` | str：明文 | `safe` |
| `rot13_encrypt` | `data*` | str：ROT13 结果 | `safe` |
| `rot13_decrypt` | `data*` | str：ROT13 结果 | `safe` |
| `rot47_encrypt` | `data*` | str：ROT47 结果 | `safe` |
| `rot47_decrypt` | `data*` | str：ROT47 结果 | `safe` |
| `rot_n` | `data*`, `shift*` | str：ROT-N 结果 | `safe` |
| `convert` | `data*`, `from_base*`, `to_base*`, `upper` | str：目标进制字符串 | `safe` |
| `bin_to_oct` | `data*` | str：八进制字符串 | `safe` |
| `bin_to_dec` | `data*` | str：十进制字符串 | `safe` |
| `bin_to_hex` | `data*` | str：十六进制字符串 | `safe` |
| `oct_to_bin` | `data*` | str：二进制字符串 | `safe` |
| `oct_to_dec` | `data*` | str：十进制字符串 | `safe` |
| `oct_to_hex` | `data*` | str：十六进制字符串 | `safe` |
| `dec_to_bin` | `data*` | str：二进制字符串 | `safe` |
| `dec_to_oct` | `data*` | str：八进制字符串 | `safe` |
| `dec_to_hex` | `data*` | str：十六进制字符串 | `safe` |
| `hex_to_bin` | `data*` | str：二进制字符串 | `safe` |
| `hex_to_oct` | `data*` | str：八进制字符串 | `safe` |
| `hex_to_dec` | `data*` | str：十进制字符串 | `safe` |
| `url_encode` | `data*` | str：URL 编码结果 | `safe` |
| `url_decode` | `data*` | str：解码结果 | `safe` |
| `url_encode_full` | `data*` | str：全编码结果 | `safe` |
| `str_to_ascii` | `data*` | str：码点序列 | `safe` |
| `ascii_to_str` | `data*` | str：还原文本 | `safe` |
| `to_lower` | `data*` | str：小写文本 | `safe` |
| `to_upper` | `data*` | str：大写文本 | `safe` |
| `text_count` | `data*`, `labels` | str：多行统计报告（``标签: 数值``） | `safe` |
| `quoted_printable_encode` | `data*` | str：QP 文本 | `safe` |
| `quoted_printable_decode` | `data*` | str：还原文本 | `safe` |
| `html_entity_encode` | `data*` | str：实体文本 | `safe` |
| `html_entity_decode` | `data*` | str：还原文本 | `safe` |
| `unicode_escape_encode` | `data*` | str：转义文本 | `safe` |
| `unicode_escape_decode` | `data*` | str：还原文本 | `safe` |
| `gbk_to_utf16` | `data*` | str：UTF-16LE 十六进制串 | `safe` |
| `utf16_to_gbk` | `data*` | str：GBK 十六进制串 | `safe` |
| `brainfuck_exec` | `program*`, `input_text` | str：程序输出 | `safe` |
| `ook_to_brainfuck` | `program*` | str：等价 Brainfuck 源码 | `safe` |
| `ook_exec` | `program*`, `input_text` | str：程序输出 | `safe` |
| `jother_to_brainfuck` | `program*` | str：等价 Brainfuck 源码 | `safe` |
| `jother_exec` | `program*`, `input_text` | str：程序输出 | `safe` |
| `jsfuck_encode` | `js_code*` | str：JSFuck 代码 | `safe` |
| `jsfuck_decode` | `jsfuck_code*` | str：还原的 JS 代码 | `safe` |

<details><summary>参数详情</summary>

**`base16_encrypt`**（lib.base_codec）—— Base16（十六进制）编码：文本 -> 十六进制大写字符串。

- `data`，**必填**，`str`：待编码文本
- 返回：str：Base16 大写字符串
- 示例：`{"data": "flag"}`

**`base16_decrypt`**（lib.base_codec）—— Base16（十六进制）解码：十六进制字符串 -> 文本。

- `data`，**必填**，`str`：Base16 字符串（大小写均可）
- 返回：str：解码后的文本

**`base32_encrypt`**（lib.base_codec）—— Base32 编码：文本 -> Base32 字符串。

- `data`，**必填**，`str`：待编码文本
- 返回：str：Base32 字符串
- 示例：`{"data": "flag"}`

**`base32_decrypt`**（lib.base_codec）—— Base32 解码：Base32 字符串 -> 文本。

- `data`，**必填**，`str`：Base32 字符串
- 返回：str：解码后的文本

**`base64_encrypt`**（lib.base_codec）—— Base64 编码：文本 -> Base64 字符串。

- `data`，**必填**，`str`：待编码文本
- 返回：str：Base64 字符串
- 示例：`{"data": "flag"}`

**`base64_decrypt`**（lib.base_codec）—— Base64 解码：Base64 字符串 -> 文本。

- `data`，**必填**，`str`：Base64 字符串
- 返回：str：解码后的文本
- 示例：`{"data": "ZmxhZw=="}`

**`base64_urlsafe_encrypt`**（lib.base_codec）—— Base64 URL 安全编码：``+`` / ``/`` 换成 ``-`` / ``_``，常用于 URL 与 JWT。

- `data`，**必填**，`str`：待编码文本
- 返回：str：URL 安全 Base64 字符串

**`base64_urlsafe_decrypt`**（lib.base_codec）—— Base64 URL 安全解码。

- `data`，**必填**，`str`：URL 安全 Base64 字符串
- 返回：str：解码后的文本

**`base85_encrypt`**（lib.base_codec）—— Base85 编码（variant：b85 = RFC1924/Git，a85 = Adobe Ascii85）。

- `data`，**必填**，`str`：待编码文本
- `variant`，默认 `'b85'`，`str`，可选 `b85` / `a85`：Base85 变体
- 返回：str：Base85 字符串

**`base85_decrypt`**（lib.base_codec）—— Base85 解码（variant：b85 / a85）。

- `data`，**必填**，`str`：Base85 字符串
- `variant`，默认 `'b85'`，`str`，可选 `b85` / `a85`：Base85 变体
- 返回：str：解码后的文本

**`base58_encrypt`**（lib.base_codec）—— Base58 编码（Bitcoin 字母表，去掉了 0OIl）。

- `data`，**必填**，`str`：待编码文本
- 返回：str：Base58 字符串

**`base58_decrypt`**（lib.base_codec）—— Base58 解码（Bitcoin 字母表）。

- `data`，**必填**，`str`：Base58 字符串
- 返回：str：解码后的文本

**`base62_encrypt`**（lib.base_codec）—— Base62 编码（0-9A-Za-z）。

- `data`，**必填**，`str`：待编码文本
- 返回：str：Base62 字符串

**`base62_decrypt`**（lib.base_codec）—— Base62 解码（0-9A-Za-z）。

- `data`，**必填**，`str`：Base62 字符串
- 返回：str：解码后的文本

**`base91_encrypt`**（lib.base_codec）—— Base91 编码（basE91 标准字母表）。

- `data`，**必填**，`str`：待编码文本
- 返回：str：Base91 字符串

**`base91_decrypt`**（lib.base_codec）—— Base91 解码（basE91 标准字母表）。

- `data`，**必填**，`str`：Base91 字符串
- 返回：str：解码后的文本

**`base92_encrypt`**（lib.base_codec）—— Base92 编码（92 个可打印 ASCII 字符）。

- `data`，**必填**，`str`：待编码文本
- 返回：str：Base92 字符串

**`base92_decrypt`**（lib.base_codec）—— Base92 解码（92 个可打印 ASCII 字符）。

- `data`，**必填**，`str`：Base92 字符串
- 返回：str：解码后的文本

**`uuencode_encrypt`**（lib.base_codec）—— UUencode 编码（输出含 begin / end 包裹）。

- `data`，**必填**，`str`：待编码文本
- 返回：str：uuencode 文本

**`uuencode_decrypt`**（lib.base_codec）—— UUencode 解码。

- `data`，**必填**，`str`：uuencode 文本
- 返回：str：解码后的文本

**`xxencode_encrypt`**（lib.base_codec）—— XXencode 编码（字母表 ``+ - 0-9 A-Z a-z``）。

- `data`，**必填**，`str`：待编码文本
- 返回：str：xxencode 文本

**`xxencode_decrypt`**（lib.base_codec）—— XXencode 解码。

- `data`，**必填**，`str`：xxencode 文本
- 返回：str：解码后的文本

**`caesar_encrypt`**（lib.char_codec）—— 凯撒加密：字母表右移 shift 位，非字母原样保留。

- `data`，**必填**，`str`：明文
- `shift`，**必填**，`int`：右移位数（可为负）
- 返回：str：密文
- 示例：`{"data": "flag", "shift": 3}`

**`caesar_decrypt`**（lib.char_codec）—— 凯撒解密：对密文反向移位 shift 位。

- `data`，**必填**，`str`：密文
- `shift`，**必填**，`int`：加密时使用的位移
- 返回：str：明文

**`pigpen_encrypt`**（lib.char_codec）—— 猪圈密码加密：英文字母替换为猪圈符号，其余字符原样。

- `data`，**必填**，`str`：明文
- 返回：str：猪圈符号密文

**`pigpen_decrypt`**（lib.char_codec）—— 猪圈密码解密：猪圈符号还原为大写字母。

- `data`，**必填**，`str`：猪圈符号密文
- 返回：str：明文

**`rot13_encrypt`**（lib.rot_codec）—— ROT13：字母位移 13 位（自逆）。

- `data`，**必填**，`str`：文本
- 返回：str：ROT13 结果
- 示例：`{"data": "synt"}`

**`rot13_decrypt`**（lib.rot_codec）—— ROT13 解密（与加密相同）。

- `data`，**必填**，`str`：文本
- 返回：str：ROT13 结果

**`rot47_encrypt`**（lib.rot_codec）—— ROT47：可打印 ASCII（33~126）位移 47 位（自逆）。

- `data`，**必填**，`str`：文本
- 返回：str：ROT47 结果

**`rot47_decrypt`**（lib.rot_codec）—— ROT47 解密（与加密相同）。

- `data`，**必填**，`str`：文本
- 返回：str：ROT47 结果

**`rot_n`**（lib.rot_codec）—— ROT-N：字母表位移任意位数（自逆，位移 26 的倍数还原原文）。

- `data`，**必填**，`str`：文本
- `shift`，**必填**，`int`：位移位数
- 返回：str：ROT-N 结果

**`convert`**（lib.number_base_codec）—— 任意进制互转（2~16 进制，可自定义大小写）。

- `data`，**必填**，`str`：待转换数值文本
- `from_base`，**必填**，`int`，范围 2~16：源进制（2~16）
- `to_base`，**必填**，`int`，范围 2~16：目标进制（2~16）
- `upper`，默认 `True`，`bool`：true=输出大写字母，false=小写
- 返回：str：目标进制字符串
- 示例：`{"data": "ff", "from_base": 16, "to_base": 10}`

**`bin_to_oct`**（lib.number_base_codec）—— 2 进制 -> 8 进制。

- `data`，**必填**，`str`：二进制字符串
- 返回：str：八进制字符串

**`bin_to_dec`**（lib.number_base_codec）—— 2 进制 -> 10 进制。

- `data`，**必填**，`str`：二进制字符串
- 返回：str：十进制字符串

**`bin_to_hex`**（lib.number_base_codec）—— 2 进制 -> 16 进制。

- `data`，**必填**，`str`：二进制字符串
- 返回：str：十六进制字符串

**`oct_to_bin`**（lib.number_base_codec）—— 8 进制 -> 2 进制。

- `data`，**必填**，`str`：八进制字符串
- 返回：str：二进制字符串

**`oct_to_dec`**（lib.number_base_codec）—— 8 进制 -> 10 进制。

- `data`，**必填**，`str`：八进制字符串
- 返回：str：十进制字符串

**`oct_to_hex`**（lib.number_base_codec）—— 8 进制 -> 16 进制。

- `data`，**必填**，`str`：八进制字符串
- 返回：str：十六进制字符串

**`dec_to_bin`**（lib.number_base_codec）—— 10 进制 -> 2 进制。

- `data`，**必填**，`str`：十进制字符串
- 返回：str：二进制字符串

**`dec_to_oct`**（lib.number_base_codec）—— 10 进制 -> 8 进制。

- `data`，**必填**，`str`：十进制字符串
- 返回：str：八进制字符串

**`dec_to_hex`**（lib.number_base_codec）—— 10 进制 -> 16 进制。

- `data`，**必填**，`str`：十进制字符串
- 返回：str：十六进制字符串

**`hex_to_bin`**（lib.number_base_codec）—— 16 进制 -> 2 进制。

- `data`，**必填**，`str`：十六进制字符串
- 返回：str：二进制字符串

**`hex_to_oct`**（lib.number_base_codec）—— 16 进制 -> 8 进制。

- `data`，**必填**，`str`：十六进制字符串
- 返回：str：八进制字符串

**`hex_to_dec`**（lib.number_base_codec）—— 16 进制 -> 10 进制。

- `data`，**必填**，`str`：十六进制字符串
- 返回：str：十进制字符串

**`url_encode`**（lib.string_codec）—— URL 编码：非 ``A-Za-z0-9_.-~`` 字符按 UTF-8 百分号转义。

- `data`，**必填**，`str`：待编码文本
- 返回：str：URL 编码结果

**`url_decode`**（lib.string_codec）—— URL 解码：``%XX`` 还原为 UTF-8 文本。

- `data`，**必填**，`str`：URL 编码文本
- 返回：str：解码结果

**`url_encode_full`**（lib.string_codec）—— URL 全编码：每个 UTF-8 字节都写成 ``%XX``。

- `data`，**必填**，`str`：待编码文本
- 返回：str：全编码结果

**`str_to_ascii`**（lib.string_codec）—— 字符串转 ASCII 码：逐字符十进制码点，空格分隔。

- `data`，**必填**，`str`：文本
- 返回：str：码点序列
- 示例：`{"data": "flag"}`

**`ascii_to_str`**（lib.string_codec）—— ASCII 码转字符串：接受十进制或 ``0x`` 十六进制码点。

- `data`，**必填**，`str`：码点序列，如 ``102 108 97 103``
- 返回：str：还原文本

**`to_lower`**（lib.string_codec）—— 大写转小写（Unicode 规则，保留空白与换行）。

- `data`，**必填**，`str`：文本
- 返回：str：小写文本

**`to_upper`**（lib.string_codec）—— 小写转大写（Unicode 规则，保留空白与换行）。

- `data`，**必填**，`str`：文本
- 返回：str：大写文本

**`text_count`**（lib.string_codec）—— 文本字数统计：总字符 / 不含空白 / 单词 / 字母 / 数字 / 汉字 / 行数。

- `data`，**必填**，`str`：待统计文本
- `labels`，默认 `{"total": "总字符数", "no_space": "不含空白字符数", "words": "单词数", "letters": "字母数", "digits": "数字数", "cjk": "汉字数", "lines": "行数"}`，`dict`：标签映射，键固定为 total/no_space/words/letters/digits/cjk/lines
- 返回：str：多行统计报告（``标签: 数值``）

**`quoted_printable_encode`**（lib.string_codec）—— Quoted-printable 编码（``=XX`` 转义，行宽 ≤ 76）。

- `data`，**必填**，`str`：待编码文本
- 返回：str：QP 文本

**`quoted_printable_decode`**（lib.string_codec）—— Quoted-printable 解码。

- `data`，**必填**，`str`：QP 文本
- 返回：str：还原文本

**`html_entity_encode`**（lib.string_codec）—— HTML 实体编码：``< > & "`` 与全部非 ASCII 字符转实体。

- `data`，**必填**，`str`：待编码文本
- 返回：str：实体文本

**`html_entity_decode`**（lib.string_codec）—— HTML 实体解码：命名实体与数字实体（``&#20013;`` / ``&#x4e2d;``）均支持。

- `data`，**必填**，`str`：实体文本
- 返回：str：还原文本

**`unicode_escape_encode`**（lib.string_codec）—— Unicode 转义编码：非 ASCII 写成 ``\uXXXX`` / ``\UXXXXXXXX``。

- `data`，**必填**，`str`：待编码文本
- 返回：str：转义文本

**`unicode_escape_decode`**（lib.string_codec）—— Unicode 转义解码：``\uXXXX`` / ``\UXXXXXXXX`` 还原。

- `data`，**必填**，`str`：转义文本
- 返回：str：还原文本

**`gbk_to_utf16`**（lib.string_codec）—— 编码转换 GBK -> UTF-16LE：输入 GBK 字节的十六进制串，输出 UTF-16LE 字节的十六进制串。

- `data`，**必填**，`str`：GBK 字节的十六进制串
- 返回：str：UTF-16LE 十六进制串

**`utf16_to_gbk`**（lib.string_codec）—— 编码转换 UTF-16LE -> GBK：输入 UTF-16LE 字节的十六进制串，输出 GBK 字节的十六进制串。

- `data`，**必填**，`str`：UTF-16LE 字节的十六进制串
- 返回：str：GBK 十六进制串

**`brainfuck_exec`**（lib.esolang）—— 执行 Brainfuck 程序，返回标准输出。

- `program`，**必填**，`str`：Brainfuck 源码
- `input_text`，默认 `''`，`str`：程序的标准输入（对应 ``,`` 指令）
- 返回：str：程序输出
- 备注：有指令步数上限保护；死循环会被截断。

**`ook_to_brainfuck`**（lib.esolang）—— Ook! 程序 -> Brainfuck 程序（纯翻译不执行）。

- `program`，**必填**，`str`：Ook! 源码
- 返回：str：等价 Brainfuck 源码

**`ook_exec`**（lib.esolang）—— 执行 Ook! 程序（先翻译为 Brainfuck）。

- `program`，**必填**，`str`：Ook! 源码
- `input_text`，默认 `''`，`str`：标准输入
- 返回：str：程序输出

**`jother_to_brainfuck`**（lib.esolang）—— jother 程序 -> Brainfuck 程序（纯翻译不执行）。

- `program`，**必填**，`str`：jother 源码
- 返回：str：等价 Brainfuck 源码

**`jother_exec`**（lib.esolang）—— 执行 jother 程序（提取 Brainfuck 指令后执行）。

- `program`，**必填**，`str`：jother 源码
- `input_text`，默认 `''`，`str`：标准输入
- 返回：str：程序输出

**`jsfuck_encode`**（lib.esolang）—— JS 代码 -> JSFuck（仅 ``[]()!+`` 六种字符）。

- `js_code`，**必填**，`str`：待编码 JS 代码
- 返回：str：JSFuck 代码

**`jsfuck_decode`**（lib.esolang）—— JSFuck -> JS 代码（需要系统 ``node`` 可执行）。

- `jsfuck_code`，**必填**，`str`：JSFuck 代码
- 返回：str：还原的 JS 代码
- 备注：依赖宿主环境中的 node；缺失时报 unsupported。

</details>

### cn_data —— 数据处理：JSON / 十六进制文件 / 文本对比去重

JSON 美化·压缩·结构分析·摊平·构建；文件↔十六进制互转（流式）；文本差异对比（字符/词/行粒度）；文本去重与统计。

> 路径类 op 的相对路径基于项目根，不依赖宿主进程 CWD；写文件的 op 风险等级为 write，会在 meta.risk 里标明。

| op | 参数（`*` = 必填） | 返回 | 风险 |
| --- | --- | --- | --- |
| `format_json` | `data*`, `indent` | str：格式化后的 JSON | `safe` |
| `minify_json` | `data*` | str：单行 JSON | `safe` |
| `analyze_json` | `data*`, `limit` | str：纯文本结构报告 | `safe` |
| `loads_json` | `data*` | dict：{value: 解析结果, duplicate_keys: [重复键名]} | `safe` |
| `rows_from_json` | `data*` | dict：{root_type, rows} | `safe` |
| `build_json` | `root`, `entries*`, `indent` | str：构建出的 JSON 文本 | `safe` |
| `bytes_to_hex` | `data*`, `separator`, `prefix`, `uppercase`, `bytes_per_line` | str：十六进制文本 | `safe` |
| `hex_to_bytes` | `text*`, `separator` | dict：{hex, length, text, is_text} | `safe` |
| `unescape` | `text*` | str：还原后的文本 | `safe` |
| `file_to_hex` | `path*`, `separator`, `prefix`, `uppercase`, `bytes_per_line`, `limit` | dict：{path, rel, size, hex, truncated} | `read` |
| `write_hex_file` | `path*`, `out_path`, `separator`, `prefix`, `uppercase`, `bytes_per_line` | dict：{src, out, out_rel, size, lines} | `write` |
| `hex_to_file` | `text*`, `out_path`, `separator` | dict：{out, out_rel, size} | `write` |
| `hex_file_to_file` | `src_path*`, `out_path`, `separator` | dict：{src, out, out_rel, size} | `write` |
| `compare` | `left*`, `right*`, `mode`, `ignore_case`, `ignore_space` | dict：{equal, similarity, blocks, removed, added, replaced, mode, left_length, right_length, left[], right[]} | `safe` |
| `dedupe` | `data*`, `unit`, `order`, `ignore_case` | str：去重后的文本 | `safe` |
| `dedupe_stats` | `data*`, `unit`, `ignore_case`, `labels` | str：多行统计报告 | `safe` |
| `split_units` | `text*`, `unit` | list[str]：单元列表 | `safe` |

<details><summary>参数详情</summary>

**`format_json`**（lib.json_tool）—— JSON 美化：按 indent 缩进，中文原样保留（不转 \uXXXX）。

- `data`，**必填**，`str`：JSON 文本
- `indent`，默认 `2`，`int`，范围 0~8：缩进空格数
- 返回：str：格式化后的 JSON
- 示例：`{"data": "{\"a\":1}"}`

**`minify_json`**（lib.json_tool）—— JSON 压缩：去掉全部非必要空白，输出单行。

- `data`，**必填**，`str`：JSON 文本
- 返回：str：单行 JSON

**`analyze_json`**（lib.json_tool）—— JSON 结构报告：根类型 / 规模 / 最大深度 / 重复键 / 逐条值路径。

- `data`，**必填**，`str`：JSON 文本
- `limit`，默认 `500`，`int`，范围 1~+∞：值路径最多列出多少条
- 返回：str：纯文本结构报告

**`loads_json`**（lib.json_tool）—— 解析 JSON 并检出重复键。

- `data`，**必填**，`str`：JSON 文本
- 返回：dict：{value: 解析结果, duplicate_keys: [重复键名]}

**`rows_from_json`**（lib.json_tool）—— 把 JSON 摊平成 ``(根类型, [[键名, 值类型, 值文本], …])``，便于表格化。

- `data`，**必填**，`str`：JSON 文本
- 返回：dict：{root_type, rows}

**`build_json`**（lib.json_tool）—— 按行构建 JSON：entries 为 ``[[键, 类型, 值文本], …]``。

- `root`，默认 `'object'`，`str`，可选 `object` / `array`：根类型：object / array
- `entries`，**必填**，`any`：[[键名, 值类型, 值文本], …]；类型支持 str/int/float/bool/null/object/array
- `indent`，默认 `2`，`int`，范围 0~8：缩进空格数
- 返回：str：构建出的 JSON 文本

**`bytes_to_hex`**（lib.file_hex_codec）—— 字节串（十六进制输入） -> 十六进制文本，可加分隔符 / 前缀 / 每行字节数。

- `data`，**必填**，`str`：字节串的十六进制表示
- `separator`，默认 `''`，`str`：字节间分隔符，如空格或 ``\n``
- `prefix`，默认 `''`，`str`：每个字节的前缀，如 ``0x``
- `uppercase`，默认 `True`，`bool`：输出大写十六进制
- `bytes_per_line`，默认 `0`，`int`，范围 0~+∞：每行字节数，0 表示不换行
- 返回：str：十六进制文本
- 示例：`{"data": "666c6167", "separator": " "}`

**`hex_to_bytes`**（lib.file_hex_codec）—— 十六进制文本 -> 字节串（输出 hex / length / text）。

- `text`，**必填**，`str`：十六进制文本，可含 0x / \x 前缀与分隔符
- `separator`，默认 `null`，`str`：自定义分隔符（默认自动识别）
- 返回：dict：{hex, length, text, is_text}

**`unescape`**（lib.file_hex_codec）—— 把 ``\n`` / ``\r`` / ``\t`` / ``\0`` / ``\\`` 转义还原为真实字符。

- `text`，**必填**，`str`：含转义序列的文本
- 返回：str：还原后的文本

**`file_to_hex`**（lib.file_hex_codec）—— 读取文件并渲染为十六进制文本（流式，内存占用与文件大小无关）。

- `path`，**必填**，`str`：源文件路径（相对路径基于项目根）
- `separator`，默认 `''`，`str`：字节间分隔符
- `prefix`，默认 `''`，`str`：每个字节的前缀
- `uppercase`，默认 `True`，`bool`：输出大写十六进制
- `bytes_per_line`，默认 `0`，`int`，范围 0~+∞：每行字节数，0 表示不换行
- `limit`，默认 `null`，`int`，范围 1~+∞：最多读取的字节数（默认全读）
- 返回：dict：{path, rel, size, hex, truncated}

**`write_hex_file`**（lib.file_hex_codec）—— 把文件转成十六进制文本文件（流式写出）。

- `path`，**必填**，`str`：源文件路径
- `out_path`，默认 `''`，`str`：输出文件路径；留空则同在源文件旁加 .hex 后缀
- `separator`，默认 `''`，`str`：字节间分隔符
- `prefix`，默认 `''`，`str`：每个字节的前缀
- `uppercase`，默认 `True`，`bool`：输出大写十六进制
- `bytes_per_line`，默认 `0`，`int`，范围 0~+∞：每行字节数，0 表示不换行
- 返回：dict：{src, out, out_rel, size, lines}

**`hex_to_file`**（lib.file_hex_codec）—— 把十六进制文本解码并写出为二进制文件。

- `text`，**必填**，`str`：十六进制文本
- `out_path`，默认 `''`，`str`：输出文件路径；留空写入 output/decoded.bin
- `separator`，默认 `null`，`str`：自定义分隔符（默认自动识别）
- 返回：dict：{out, out_rel, size}

**`hex_file_to_file`**（lib.file_hex_codec）—— 把十六进制文本文件解码为二进制文件（等价 ``xxd -r -p``）。

- `src_path`，**必填**，`str`：十六进制文本文件路径
- `out_path`，默认 `''`，`str`：输出二进制文件路径；留空则在源文件旁加 .bin
- `separator`，默认 `null`，`str`：自定义分隔符（默认自动识别）
- 返回：dict：{src, out, out_rel, size}

**`compare`**（lib.text_diff）—— 文本差异对比：返回两侧分段（equal / removed / added / replaced）、相似度与增删改统计。

- `left`，**必填**，`str`：文本 A
- `right`，**必填**，`str`：文本 B
- `mode`，默认 `'char'`，`str`，可选 `char` / `word` / `line`：对比粒度
- `ignore_case`，默认 `False`，`bool`：忽略大小写
- `ignore_space`，默认 `False`，`bool`：忽略空白字符
- 返回：dict：{equal, similarity, blocks, removed, added, replaced, mode, left_length, right_length, left[], right[]}
- 示例：`{"left": "flag{abc}", "right": "flag{abd}", "mode": "char"}`

**`dedupe`**（lib.text_dedup）—— 文本去重：按行 / 词 / 字符去重，可保持原序或升序 / 降序排列。

- `data`，**必填**，`str`：原始文本
- `unit`，默认 `'line'`，`str`，可选 `line` / `word` / `char`：去重粒度
- `order`，默认 `'keep'`，`str`，可选 `keep` / `asc` / `desc`：输出顺序：keep / asc / desc
- `ignore_case`，默认 `False`，`bool`：大小写不敏感比较
- 返回：str：去重后的文本

**`dedupe_stats`**（lib.text_dedup）—— 文本去重统计：返回总单元数 / 去重后数量等报告，不改写原文。

- `data`，**必填**，`str`：原始文本
- `unit`，默认 `'line'`，`str`，可选 `line` / `word` / `char`：统计粒度
- `ignore_case`，默认 `False`，`bool`：大小写不敏感比较
- `labels`，默认 `null`，`dict`：统计标签映射（键为 total/unique/duplicate 等，缺省用内置中文标签）
- 返回：str：多行统计报告

**`split_units`**（lib.text_dedup）—— 把文本按指定粒度切成单元列表（只切分，不去重）。

- `text`，**必填**，`str`：原始文本
- `unit`，默认 `'line'`，`str`，可选 `line` / `word` / `char`：切分粒度
- 返回：list[str]：单元列表

</details>

### cn_crypto —— 哈希 / 国密(SM) / RSA / JWT / 密码识别

MD5/SHA/SHA3 摘要与哈希长度扩展；SM3/SM4/SM2 全套国密；RSA 分解与常见攻击（共模、低指数、Wiener、Håstad、CRT）；JWT 解析/签发/弱密钥爆破/算法混淆；密文自动识别 Fuzz。

> 字节级参数（key / iv / z / signing_input）用十六进制传；明文参数按 UTF-8，需要原始字节时加 data_hex=true。大整数直接传十进制或 0x 前缀，返回的大整数是 JSON number（可能很长）。

| op | 参数（`*` = 必填） | 返回 | 风险 |
| --- | --- | --- | --- |
| `md5_hex` | `data*` | str：MD5 十六进制 | `safe` |
| `sha1_hex` | `data*` | str：SHA-1 十六进制 | `safe` |
| `sha256_hex` | `data*` | str：SHA-256 十六进制 | `safe` |
| `sha512_hex` | `data*` | str：SHA-512 十六进制 | `safe` |
| `sha3_256_hex` | `data*` | str：SHA3-256 十六进制 | `safe` |
| `hash_by_name` | `name*`, `data*` | str：摘要十六进制 | `safe` |
| `length_extend` | `algo*`, `original_hash*`, `append*`, `secret_len*` | dict：{digest, payload, padding, secret_len, algo} | `safe` |
| `length_extend_full` | `algo*`, `original_hash*`, `original_data*`, `append*`, `secret_len*` | dict：{digest, payload, padding, secret_len, algo} | `safe` |
| `sm3_hash` | `data*`, `data_hex` | dict：{hex, length, text, is_text} | `safe` |
| `sm3_hex` | `data*`, `data_hex` | str：SM3 十六进制 | `safe` |
| `sm3_kdf` | `z*`, `klen*` | dict：{hex, length, text, is_text} | `safe` |
| `parse_hex` | `text*` | dict：{hex, length, text, is_text} | `safe` |
| `sm4_ecb_encrypt` | `data*`, `data_hex`, `key*`, `padding` | dict：{hex, length, text, is_text} | `safe` |
| `sm4_ecb_decrypt` | `data*`, `data_hex`, `key*`, `padding` | dict：{hex, length, text, is_text} | `safe` |
| `sm4_cbc_encrypt` | `data*`, `data_hex`, `key*`, `iv*`, `padding` | dict：{hex, length, text, is_text} | `safe` |
| `sm4_cbc_decrypt` | `data*`, `data_hex`, `key*`, `iv*`, `padding` | dict：{hex, length, text, is_text} | `safe` |
| `sm2_generate_keypair` | — | dict：{private_key, public_key}（均为十六进制） | `safe` |
| `sm2_public_from_private` | `private_key*` | str：128 位十六进制公钥 | `safe` |
| `sm2_encrypt` | `data*`, `data_hex`, `public_key*`, `mode` | dict：{hex, length, text, is_text} | `safe` |
| `sm2_decrypt` | `data*`, `private_key*`, `mode` | dict：{hex, length, text, is_text} | `safe` |
| `sm2_sign` | `data*`, `data_hex`, `private_key*`, `public_key`, `user_id` | str：签名（r\|\|s） | `safe` |
| `sm2_verify` | `data*`, `data_hex`, `signature*`, `public_key*`, `user_id` | bool：验签结果 | `safe` |
| `parse_int` | `value*` | int：解析结果 | `safe` |
| `gcd` | `a*`, `b*` | int：gcd(a, b) | `safe` |
| `lcm` | `a*`, `b*` | int：lcm(a, b) | `safe` |
| `extended_gcd` | `a*`, `b*` | dict：{g, x, y} | `safe` |
| `modinv` | `a*`, `m*` | int：逆元 | `safe` |
| `powmod` | `base*`, `exp*`, `mod*` | int：结果 | `safe` |
| `euler_phi` | `n*` | int：φ(n) | `long` |
| `integer_nth_root` | `n*`, `k*` | int：根 | `safe` |
| `is_perfect_power` | `n*`, `k*` | bool：是否完全 k 次幂 | `safe` |
| `is_prime` | `n*` | bool：是否素数 | `safe` |
| `next_prime` | `n*` | int：素数 | `safe` |
| `factor_trial` | `n*`, `limit` | list[int]：质因子（含重数） | `long` |
| `factor_fermat` | `n*` | dict：{p, q} 或 null | `long` |
| `factor_prho` | `n*` | list[int]：质因子 | `long` |
| `factor_pm1` | `n*`, `bound` | int\|null：找到的因子 | `long` |
| `factor` | `n*`, `use_fermat`, `use_prho`, `use_pm1` | list[int]：质因子（升序） | `long` |
| `rsa_recover_d` | `p*`, `q*`, `e*` | int：私钥 d | `safe` |
| `rsa_private_key` | `p*`, `q*`, `e*` | str：PEM 私钥文本 | `safe` |
| `rsa_recover_pq_from_ed` | `n*`, `e*`, `d*` | dict：{p, q} | `safe` |
| `attack_common_modulus` | `c1*`, `c2*`, `e1*`, `e2*`, `n*` | int：明文 m（配合 int_to_text 还原） | `safe` |
| `attack_low_exponent` | `c*`, `e*`, `n*` | int：明文 m | `safe` |
| `attack_wiener` | `n*`, `e*` | int\|null：私钥 d | `safe` |
| `attack_hastad` | `ciphertexts*`, `exponents*`, `n*` | int：明文 m | `safe` |
| `int_to_bytes` | `n*` | dict：{hex, length, text, is_text} | `safe` |
| `int_to_text` | `n*` | str：文本 | `safe` |
| `text_to_int` | `text*` | int：整数 | `safe` |
| `crt` | `remainders*`, `moduli*` | int：最小非负解 | `safe` |
| `parse` | `token*` | dict：{header, payload, signature(hex), header_raw, payload_raw, signature_raw, algorithm, extra} | `safe` |
| `verify` | `token*`, `key` | bool：是否通过校验 | `safe` |
| `create` | `header*`, `payload*`, `key`, `algorithm` | str：JWT 字符串 | `safe` |
| `resign` | `token*`, `key`, `algorithm` | str：新 JWT | `safe` |
| `sign` | `algorithm*`, `signing_input*`, `key` | dict：{hex, length, text, is_text} | `safe` |
| `hs_bruteforce` | `token*`, `candidates*` | str\|null：命中的密钥 | `long` |
| `alg_confusion_rs_to_hs` | `payload*`, `public_key_pem*`, `hs_alg` | str：伪造的 JWT | `safe` |
| `inject_header` | `token*`, `extra_header*`, `key`, `algorithm` | str：新 JWT | `safe` |
| `now_timestamp` | — | int：Unix 时间戳 | `safe` |
| `b64url_encode` | `data*` | str：Base64URL 字符串 | `safe` |
| `b64url_decode` | `text*` | dict：{hex, length, text, is_text} | `safe` |
| `pretty` | `obj*` | str：美化 JSON | `safe` |
| `coerce_claim_value` | `text*` | 任意：转换后的值 | `safe` |
| `run` | `text*`, `key`, `offset`, `targets`, `dedupe` | dict：{hits: [{method, text, score}], tried, ...} | `long` |
| `readability` | `text*` | float：0~1 | `safe` |

<details><summary>参数详情</summary>

**`md5_hex`**（lib.hash_codec）—— 计算 MD5 摘要（32 位小写十六进制）。

- `data`，**必填**，`str`：待摘要文本
- 返回：str：MD5 十六进制
- 示例：`{"data": "flag"}`

**`sha1_hex`**（lib.hash_codec）—— 计算 SHA-1 摘要（40 位小写十六进制）。

- `data`，**必填**，`str`：待摘要文本
- 返回：str：SHA-1 十六进制

**`sha256_hex`**（lib.hash_codec）—— 计算 SHA-256 摘要（64 位小写十六进制）。

- `data`，**必填**，`str`：待摘要文本
- 返回：str：SHA-256 十六进制

**`sha512_hex`**（lib.hash_codec）—— 计算 SHA-512 摘要（128 位小写十六进制）。

- `data`，**必填**，`str`：待摘要文本
- 返回：str：SHA-512 十六进制

**`sha3_256_hex`**（lib.hash_codec）—— 计算 SHA3-256 摘要（64 位小写十六进制）。

- `data`，**必填**，`str`：待摘要文本
- 返回：str：SHA3-256 十六进制

**`hash_by_name`**（lib.hash_codec）—— 按算法名计算摘要（md5 / sha1 / sha256 / sha512 / sha3_256）。

- `name`，**必填**，`str`：算法名
- `data`，**必填**，`str`：待摘要文本
- 返回：str：摘要十六进制

**`length_extend`**（lib.hash_ext）—— 哈希长度扩展攻击：已知原始摘要与 secret 长度，构造 ``append`` 之后的有效摘要。

- `algo`，**必填**，`str`，可选 `md5` / `sha1` / `sha256`：算法
- `original_hash`，**必填**，`str`：原始摘要（十六进制）
- `append`，**必填**，`str`：追加内容（原始 ASCII，不做 URL 编码）
- `secret_len`，**必填**，`int`，范围 0~+∞：未知 secret 的字节长度
- 返回：dict：{digest, payload, padding, secret_len, algo}
- 备注：payload 为可直接拼进请求的伪造后缀片段。

**`length_extend_full`**（lib.hash_ext）—— 哈希长度扩展（完整版）：显式给出原始 data，自动计算 padding 并返回伪造 payload。

- `algo`，**必填**，`str`，可选 `md5` / `sha1` / `sha256`：算法
- `original_hash`，**必填**，`str`：原始摘要（十六进制）
- `original_data`，**必填**，`str`：原始消息（不含 secret 部分）
- `append`，**必填**，`str`：追加内容
- `secret_len`，**必填**，`int`，范围 0~+∞：未知 secret 的字节长度
- 返回：dict：{digest, payload, padding, secret_len, algo}

**`sm3_hash`**（lib.gm_codec）—— 计算 SM3 摘要（输出 bytes：hex + length + text）。

- `data`，**必填**，`str`：待摘要文本或十六进制字节
- `data_hex`，默认 `False`，`bool`：data 是否为十六进制字节串
- 返回：dict：{hex, length, text, is_text}

**`sm3_hex`**（lib.gm_codec）—— 计算 SM3 摘要，返回 64 位小写十六进制。

- `data`，**必填**，`str`：待摘要文本或十六进制字节
- `data_hex`，默认 `False`，`bool`：data 是否为十六进制字节串
- 返回：str：SM3 十六进制
- 示例：`{"data": "abc"}`

**`sm3_kdf`**（lib.gm_codec）—— 基于 SM3 的密钥派生函数 KDF(Z, klen)。

- `z`，**必填**，`hex`：共享秘密 Z 的十六进制
- `klen`，**必填**，`int`，范围 1~+∞：输出字节数
- 返回：dict：{hex, length, text, is_text}

**`parse_hex`**（lib.gm_codec）—— 把十六进制文本解析为 bytes。

- `text`，**必填**，`str`：十六进制文本
- 返回：dict：{hex, length, text, is_text}

**`sm4_ecb_encrypt`**（lib.gm_codec）—— SM4-ECB 加密（key 必须 16 字节）。

- `data`，**必填**，`str`：明文文本或十六进制字节
- `data_hex`，默认 `False`，`bool`：data 是否为十六进制字节串
- `key`，**必填**，`hex`：16 字节密钥的十六进制（32 位）
- `padding`，默认 `True`，`bool`：是否使用 PKCS#7 填充
- 返回：dict：{hex, length, text, is_text}

**`sm4_ecb_decrypt`**（lib.gm_codec）—— SM4-ECB 解密（密文按十六进制传入）。

- `data`，**必填**，`str`：密文的十六进制
- `data_hex`，默认 `True`，`bool`：按十六进制解析 data（密文默认 true）
- `key`，**必填**，`hex`：16 字节密钥的十六进制（32 位）
- `padding`，默认 `True`，`bool`：是否使用 PKCS#7 填充
- 返回：dict：{hex, length, text, is_text}

**`sm4_cbc_encrypt`**（lib.gm_codec）—— SM4-CBC 加密（key / iv 均 16 字节）。

- `data`，**必填**，`str`：明文文本或十六进制字节
- `data_hex`，默认 `False`，`bool`：data 是否为十六进制字节串
- `key`，**必填**，`hex`：16 字节密钥的十六进制
- `iv`，**必填**，`hex`：16 字节 IV 的十六进制
- `padding`，默认 `True`，`bool`：是否使用 PKCS#7 填充
- 返回：dict：{hex, length, text, is_text}

**`sm4_cbc_decrypt`**（lib.gm_codec）—— SM4-CBC 解密。

- `data`，**必填**，`str`：密文的十六进制
- `data_hex`，默认 `True`，`bool`：按十六进制解析 data（密文默认 true）
- `key`，**必填**，`hex`：16 字节密钥的十六进制
- `iv`，**必填**，`hex`：16 字节 IV 的十六进制
- `padding`，默认 `True`，`bool`：是否使用 PKCS#7 填充
- 返回：dict：{hex, length, text, is_text}

**`sm2_generate_keypair`**（lib.gm_codec）—— 生成 SM2 密钥对。

- 无参数
- 返回：dict：{private_key, public_key}（均为十六进制）

**`sm2_public_from_private`**（lib.gm_codec）—— 由 SM2 私钥推导公钥。

- `private_key`，**必填**，`str`：64 位十六进制私钥
- 返回：str：128 位十六进制公钥

**`sm2_encrypt`**（lib.gm_codec）—— SM2 公钥加密（输出 C1C3C2 或 C1C2C3）。

- `data`，**必填**，`str`：明文文本或十六进制字节
- `data_hex`，默认 `False`，`bool`：data 是否为十六进制字节串
- `public_key`，**必填**，`str`：公钥十六进制（04|X|Y 或 X|Y）
- `mode`，默认 `'C1C3C2'`，`str`，可选 `C1C3C2` / `C1C2C3`：密文排列方式
- 返回：dict：{hex, length, text, is_text}

**`sm2_decrypt`**（lib.gm_codec）—— SM2 私钥解密（密文十六进制，兼容带 / 不带 04 前缀）。

- `data`，**必填**，`str`：密文的十六进制
- `private_key`，**必填**，`str`：私钥十六进制
- `mode`，默认 `'C1C3C2'`，`str`，可选 `C1C3C2` / `C1C2C3`：密文排列方式
- 返回：dict：{hex, length, text, is_text}

**`sm2_sign`**（lib.gm_codec）—— SM2 签名（SM3 摘要），返回 r||s 的 128 位十六进制。

- `data`，**必填**，`str`：待签数据文本或十六进制
- `data_hex`，默认 `False`，`bool`：data 是否为十六进制字节串
- `private_key`，**必填**，`str`：私钥十六进制
- `public_key`，默认 `''`，`str`：公钥十六进制；留空则用默认公钥计算 ZA
- `user_id`，默认 `'1234567812345678'`，`str`：SM2 用户标识（UTF-8）
- 返回：str：签名（r||s）

**`sm2_verify`**（lib.gm_codec）—— SM2 验签。

- `data`，**必填**，`str`：原始数据文本或十六进制
- `data_hex`，默认 `False`，`bool`：data 是否为十六进制字节串
- `signature`，**必填**，`str`：签名（r||s 的 128 位十六进制）
- `public_key`，**必填**，`str`：公钥十六进制
- `user_id`，默认 `'1234567812345678'`，`str`：SM2 用户标识（UTF-8）
- 返回：bool：验签结果

**`parse_int`**（lib.rsa_attack）—— 解析整数：支持十进制与 0x 十六进制字符串。

- `value`，**必填**，`any`：数字或数字字符串
- 返回：int：解析结果

**`gcd`**（lib.rsa_attack）—— 最大公约数。

- `a`，**必填**，`int`：整数 a
- `b`，**必填**，`int`：整数 b
- 返回：int：gcd(a, b)

**`lcm`**（lib.rsa_attack）—— 最小公倍数。

- `a`，**必填**，`int`：整数 a
- `b`，**必填**，`int`：整数 b
- 返回：int：lcm(a, b)

**`extended_gcd`**（lib.rsa_attack）—— 扩展欧几里得：a*x + b*y = gcd(a, b)。

- `a`，**必填**，`int`：整数 a
- `b`，**必填**，`int`：整数 b
- 返回：dict：{g, x, y}

**`modinv`**（lib.rsa_attack）—— 模逆元 a⁻¹ mod m（不存在时报错）。

- `a`，**必填**，`int`：底数
- `m`，**必填**，`int`：模数
- 返回：int：逆元

**`powmod`**（lib.rsa_attack）—— 快速幂取模 base^exp mod m。

- `base`，**必填**，`int`：底数
- `exp`，**必填**，`int`：指数
- `mod`，**必填**，`int`：模数
- 返回：int：结果

**`euler_phi`**（lib.rsa_attack）—— 欧拉函数 φ(n)（试除分解，n 不要过大）。

- `n`，**必填**，`int`：正整数
- 返回：int：φ(n)
- 备注：对超大 n 会较慢；大数请先 factor。

**`integer_nth_root`**（lib.rsa_attack）—— 整数 k 次方根（向下取整）。

- `n`，**必填**，`int`：被开方数
- `k`，**必填**，`int`，范围 1~+∞：次数
- 返回：int：根

**`is_perfect_power`**（lib.rsa_attack）—— 判断 n 是否为某整数的 k 次幂。

- `n`，**必填**，`int`：整数
- `k`，**必填**，`int`，范围 1~+∞：次数
- 返回：bool：是否完全 k 次幂

**`is_prime`**（lib.rsa_attack）—— 确定性素性判定（Miller-Rabin）。

- `n`，**必填**，`int`：待判定整数
- 返回：bool：是否素数

**`next_prime`**（lib.rsa_attack）—— 大于等于 n 的最小素数。

- `n`，**必填**，`int`：起点
- 返回：int：素数

**`factor_trial`**（lib.rsa_attack）—— 试除法分解（只试除到 limit）。

- `n`，**必填**，`int`：待分解整数
- `limit`，默认 `1000000`，`int`，范围 1~+∞：试除上限
- 返回：list[int]：质因子（含重数）

**`factor_fermat`**（lib.rsa_attack）—— Fermat 分解（p、q 接近时有效，失败返回 null）。

- `n`，**必填**，`int`：待分解整数
- 返回：dict：{p, q} 或 null

**`factor_prho`**（lib.rsa_attack）—— Pollard's rho（Brent）分解，返回升序质因子。

- `n`，**必填**，`int`：待分解整数
- 返回：list[int]：质因子

**`factor_pm1`**（lib.rsa_attack）—— Pollard's p-1 分解（p-1 为小素数幂积时有效）。

- `n`，**必填**，`int`：待分解整数
- `bound`，默认 `100000`，`int`，范围 1~+∞：光滑界
- 返回：int|null：找到的因子

**`factor`**（lib.rsa_attack）—— 综合分解：试除 → Fermat → rho → p-1。

- `n`，**必填**，`int`：待分解整数
- `use_fermat`，默认 `True`，`bool`：启用 Fermat
- `use_prho`，默认 `True`，`bool`：启用 Pollard's rho
- `use_pm1`，默认 `True`，`bool`：启用 Pollard's p-1
- 返回：list[int]：质因子（升序）

**`rsa_recover_d`**（lib.rsa_attack）—— 由 p、q、e 恢复私钥 d。

- `p`，**必填**，`int`：素数 p
- `q`，**必填**，`int`：素数 q
- `e`，**必填**，`int`：公钥指数 e
- 返回：int：私钥 d

**`rsa_private_key`**（lib.rsa_attack）—— 由 p、q、e 生成 PKCS#1 PEM 私钥。

- `p`，**必填**，`int`：素数 p
- `q`，**必填**，`int`：素数 q
- `e`，**必填**，`int`：公钥指数 e
- 返回：str：PEM 私钥文本

**`rsa_recover_pq_from_ed`**（lib.rsa_attack）—— 由 n、e、d 反推 p、q。

- `n`，**必填**，`int`：模数 n
- `e`，**必填**，`int`：公钥指数
- `d`，**必填**，`int`：私钥指数
- 返回：dict：{p, q}

**`attack_common_modulus`**（lib.rsa_attack）—— 共模攻击：同一 m、同一 n、不同 e 得到 c1 / c2。

- `c1`，**必填**，`int`：密文 c1
- `c2`，**必填**，`int`：密文 c2
- `e1`，**必填**，`int`：指数 e1
- `e2`，**必填**，`int`：指数 e2
- `n`，**必填**，`int`：公共模数 n
- 返回：int：明文 m（配合 int_to_text 还原）

**`attack_low_exponent`**（lib.rsa_attack）—— 低加密指数攻击：c = m^e 且 m^e < n（无模约简）时直接开 e 次方。

- `c`，**必填**，`int`：密文 c
- `e`，**必填**，`int`：指数 e
- `n`，**必填**，`int`：模数 n
- 返回：int：明文 m

**`attack_wiener`**（lib.rsa_attack）—— Wiener 攻击：d 较小时用连分数恢复 d（失败返回 null）。

- `n`，**必填**，`int`：模数 n
- `e`，**必填**，`int`：指数 e
- 返回：int|null：私钥 d

**`attack_hastad`**（lib.rsa_attack）—— Håstad 广播攻击：同一 m、相同 e、不同 n 的密文列表。

- `ciphertexts`，**必填**，`list`：密文列表（十进制或 0x 十六进制）
- `exponents`，**必填**，`list`：指数列表（通常每个都是 3）
- `n`，**必填**，`int`：模数 n
- 返回：int：明文 m

**`int_to_bytes`**（lib.rsa_attack）—— 整数 -> 最小长度大端字节串。

- `n`，**必填**，`int`：非负整数
- 返回：dict：{hex, length, text, is_text}

**`int_to_text`**（lib.rsa_attack）—— 整数 -> UTF-8 文本（失败回退十六进制）。

- `n`，**必填**，`int`：非负整数
- 返回：str：文本

**`text_to_int`**（lib.rsa_attack）—— 文本 -> 整数（UTF-8 大端）。

- `text`，**必填**，`str`：文本
- 返回：int：整数

**`crt`**（lib.rsa_attack）—— 中国剩余定理：解 x ≡ r_i (mod m_i)，返回最小非负解。

- `remainders`，**必填**，`list`：余数列表
- `moduli`，**必填**，`list`：模数列表（两两互素）
- 返回：int：最小非负解

**`parse`**（lib.jwt_codec）—— 解析 JWT（不校验签名），返回 header / payload / 原始分段。

- `token`，**必填**，`str`：JWT 字符串
- 返回：dict：{header, payload, signature(hex), header_raw, payload_raw, signature_raw, algorithm, extra}

**`verify`**（lib.jwt_codec）—— 校验 JWT 签名。

- `token`，**必填**，`str`：JWT 字符串
- `key`，默认 `''`，`str`：HMAC 密钥或 PEM 公钥
- 返回：bool：是否通过校验

**`create`**（lib.jwt_codec）—— 创建并签名 JWT。

- `header`，**必填**，`dict`：header 对象，如 {"alg":"HS256","typ":"JWT"}
- `payload`，**必填**，`dict`：payload 对象
- `key`，默认 `null`，`str`：签名密钥；alg=none 时留空
- `algorithm`，默认 `'HS256'`，`str`，可选 `HS256` / `HS384` / `HS512` / `RS256` / `RS384` / `RS512` / `ES256` / `ES384` / `ES512` / `none`：签名算法
- 返回：str：JWT 字符串

**`resign`**（lib.jwt_codec）—— 重签 JWT：保留 header / payload，可换算法或密钥。

- `token`，**必填**，`str`：原 JWT
- `key`，默认 `null`，`str`：新密钥；留空沿用空密钥
- `algorithm`，默认 `null`，`str`，可选 `HS256` / `HS384` / `HS512` / `RS256` / `RS384` / `RS512` / `ES256` / `ES384` / `ES512` / `none`：新算法；留空沿用原算法
- 返回：str：新 JWT

**`sign`**（lib.jwt_codec）—— 对任意 signing_input 按算法签名（底层能力）。

- `algorithm`，**必填**，`str`，可选 `HS256` / `HS384` / `HS512` / `RS256` / `RS384` / `RS512` / `ES256` / `ES384` / `ES512` / `none`：签名算法
- `signing_input`，**必填**，`hex`：待签字节的十六进制
- `key`，默认 `''`，`str`：密钥 / PEM
- 返回：dict：{hex, length, text, is_text}

**`hs_bruteforce`**（lib.jwt_codec）—— HS256 弱密钥爆破：遍历候选密钥，用 HMAC 验签找出正确密钥。

- `token`，**必填**，`str`：JWT 字符串
- `candidates`，**必填**，`list`：候选密钥列表
- 返回：str|null：命中的密钥

**`alg_confusion_rs_to_hs`**（lib.jwt_codec）—— 算法混淆攻击：用 RSA 公钥 PEM 伪造 HS256 令牌。

- `payload`，**必填**，`dict`：payload 对象
- `public_key_pem`，**必填**，`str`：RSA 公钥 PEM 文本
- `hs_alg`，默认 `'HS256'`，`str`，可选 `HS256` / `HS384` / `HS512`：HMAC 算法
- 返回：str：伪造的 JWT

**`inject_header`**（lib.jwt_codec）—— 注入 header 字段（kid / jku 等）并重签。

- `token`，**必填**，`str`：原 JWT
- `extra_header`，**必填**，`dict`：要注入的 header 字段
- `key`，默认 `null`，`str`：签名密钥；留空沿用空密钥
- `algorithm`，默认 `null`，`str`，可选 `HS256` / `HS384` / `HS512` / `RS256` / `RS384` / `RS512` / `ES256` / `ES384` / `ES512` / `none`：新算法；留空沿用原算法
- 返回：str：新 JWT

**`now_timestamp`**（lib.jwt_codec）—— 当前 Unix 秒（填 iat / exp 用）。

- 无参数
- 返回：int：Unix 时间戳

**`b64url_encode`**（lib.jwt_codec）—— Base64URL 编码（输入十六进制字节）。

- `data`，**必填**，`hex`：原始字节的十六进制
- 返回：str：Base64URL 字符串

**`b64url_decode`**（lib.jwt_codec）—— Base64URL 解码（输出 bytes）。

- `text`，**必填**，`str`：Base64URL 字符串
- 返回：dict：{hex, length, text, is_text}

**`pretty`**（lib.jwt_codec）—— 把对象美化为缩进 JSON（中文不转义）。

- `obj`，**必填**，`any`：任意 JSON 值
- 返回：str：美化 JSON

**`coerce_claim_value`**（lib.jwt_codec）—— 把字符串声明值转成合适的 JSON 类型。

- `text`，**必填**，`str`：声明值文本
- 返回：任意：转换后的值

**`run`**（lib.cipher_fuzz）—— 把 lib 里所有可解密方法跑一遍，按「可读性」降序返回候选明文。

- `text`，**必填**，`str`：待识别密文
- `key`，默认 `''`，`str`：需要密钥的方法（如凯撒）使用的密钥 / 位移
- `offset`，默认 `null`，`int`，范围 -64~64：ROT 类方法的固定位移；留空自动遍历
- `targets`，默认 `[]`，`list`：限定只跑指定方法名（留空跑全部）
- `dedupe`，默认 `True`，`bool`：结果去重
- 返回：dict：{hits: [{method, text, score}], tried, ...}
- 备注：对超长密文会自动截断分析；结果按得分排序。

**`readability`**（lib.cipher_fuzz）—— 给一段输出打「像不像明文」的分（0~1）。

- `text`，**必填**，`str`：待评分文本
- 返回：float：0~1

</details>

### cn_image —— 图片：Base64 / LSB 隐写 / 可见水印

图片 ↔ Base64；LSB 隐写容量计算、嵌入、提取、参数盲猜；可见文字水印（含平铺）。依赖 Pillow。

> 图片类 op 需要 Pillow；缺失时报 unsupported 并提示安装。相对路径基于项目根；写文件的 op 风险等级为 write。

| op | 参数（`*` = 必填） | 返回 | 风险 |
| --- | --- | --- | --- |
| `image_to_base64` | `image_path*`, `data_uri` | dict：{path, rel, size, base64, chars} | `read` |
| `decode_base64_image` | `text*` | dict：{image: {hex,length,text}, extension} | `safe` |
| `base64_to_image` | `text*`, `out_path` | dict：{out, out_rel, size, extension} | `write` |
| `capacity` | `carrier_path*`, `channels` | dict：{path, bits, bytes, chars_hint, channels} | `read` |
| `capacity_text` | `carrier_path*`, `channels` | str：容量说明 | `read` |
| `embed` | `carrier_path*`, `secret*`, `output_path`, `channels`, `bit`, `offset`, `order`, `framing` | dict：{carrier, out, out_rel, secret_chars, channels, bit, offset, order, framing} | `write` |
| `extract` | `stego_path*`, `output_path`, `channels`, `bit`, `offset`, `order`, `framing` | dict：{stego, text, chars[, out, out_rel]} | `read` |
| `detect_params` | `stego_path*`, `channels_presets`, `bits`, `offsets`, `orders`, `framings`, `limit`, `min_score` | list[dict]：候选参数与提取片段 | `long` |
| `describe_params` | `channels`, `bit`, `offset`, `order`, `framing` | str：参数描述 | `safe` |
| `read_secret` | `secret_input*` | str：秘密文本 | `read` |
| `add_visible_watermark` | `carrier_path*`, `watermark_text*`, `output_path`, `position`, `font_size`, `color`, `font_path` | dict：{carrier, out, out_rel, position, font_size, color} | `write` |
| `parse_color` | `text*` | dict：{r, g, b, a} | `safe` |
| `resolve_output_dir` | `raw` | str：绝对目录路径 | `safe` |
| `out_path` | `filename*`, `raw` | str：绝对文件路径 | `safe` |

<details><summary>参数详情</summary>

**`image_to_base64`**（lib.image_codec）—— 把图片文件编码为 Base64 文本（可选 data URI 前缀）。

- `image_path`，**必填**，`str`：图片路径（相对项目根或绝对）
- `data_uri`，默认 `False`，`bool`：是否加 ``data:image/...;base64,`` 前缀
- 返回：dict：{path, rel, size, base64, chars}

**`decode_base64_image`**（lib.image_codec）—— 把 Base64 文本解码为图片字节，返回建议扩展名。

- `text`，**必填**，`str`：Base64 文本（可含 data URI 前缀）
- 返回：dict：{image: {hex,length,text}, extension}

**`base64_to_image`**（lib.image_codec）—— 把 Base64 文本解码并写出为图片文件。

- `text`，**必填**，`str`：Base64 文本
- `out_path`，默认 `''`，`str`：输出路径；留空写入 output/image.<ext>
- 返回：dict：{out, out_rel, size, extension}

**`capacity`**（lib.lsb）—— 计算载体图片可写入的隐写位数（按通道）。

- `carrier_path`，**必填**，`str`：载体图片路径
- `channels`，默认 `'RGB'`，`str`：RGB / RGBA / R / G / B / A / RB / GB 等通道组合
- 返回：dict：{path, bits, bytes, chars_hint, channels}

**`capacity_text`**（lib.lsb）—— 用人类可读文本描述载体容量。

- `carrier_path`，**必填**，`str`：载体图片路径
- `channels`，默认 `'RGB'`，`str`：RGB / RGBA / R / G / B / A / RB / GB 等通道组合
- 返回：str：容量说明

**`embed`**（lib.lsb）—— LSB 隐写：把秘密信息写入载体图片（secret 既可以是文本，也可以是文本文件路径）。

- `carrier_path`，**必填**，`str`：载体图片路径
- `secret`，**必填**，`str`：秘密文本；若该字符串是存在的文件路径则读文件内容
- `output_path`，默认 `''`，`str`：输出图片路径；留空写入 output/<名字>_stego.<原后缀>
- `channels`，默认 `'RGB'`，`str`：RGB / RGBA / R / G / B / A / RB / GB 等通道组合
- `bit`，默认 `0`，`int`，范围 0~7：使用字节的第几位（0 = LSB）
- `offset`，默认 `0`，`int`，范围 0~+∞：起始位偏移
- `order`，默认 `'column'`，`str`，可选 `column` / `row`：扫描顺序
- `framing`，默认 `'marker'`，`str`，可选 `marker` / `length`：帧格式：marker（末尾 FF）/ length（长度头）
- 返回：dict：{carrier, out, out_rel, secret_chars, channels, bit, offset, order, framing}

**`extract`**（lib.lsb）—— LSB 隐写提取（可选同时写入文本文件）。

- `stego_path`，**必填**，`str`：隐写图片路径
- `output_path`，默认 `''`，`str`：提取结果另存的文本路径；留空只返回文本
- `channels`，默认 `'RGB'`，`str`：RGB / RGBA / R / G / B / A / RB / GB 等通道组合
- `bit`，默认 `0`，`int`，范围 0~7：使用字节的第几位
- `offset`，默认 `0`，`int`，范围 0~+∞：起始位偏移
- `order`，默认 `'column'`，`str`，可选 `column` / `row`：扫描顺序
- `framing`，默认 `'auto'`，`str`，可选 `marker` / `length` / `auto`：帧格式：auto / marker / length
- 返回：dict：{stego, text, chars[, out, out_rel]}

**`detect_params`**（lib.lsb）—— LSB 参数盲猜：遍历通道 / 位 / 偏移 / 顺序 / 帧格式组合，按得分排序返回候选。

- `stego_path`，**必填**，`str`：可疑图片路径
- `channels_presets`，默认 `["RGB", "RGBA", "R", "G", "B", "A", "RB", "GB"]`，`list`：候选通道组合
- `bits`，默认 `[0, 1, 2, 3, 4, 5, 6, 7]`，`list`：候选位下标
- `offsets`，默认 `[0, 1, 2, 4, 8, 16, 32, 64, 128, 256]`，`list`：候选起始偏移
- `orders`，默认 `["column", "row"]`，`list`：候选扫描顺序
- `framings`，默认 `["length", "marker"]`，`list`：候选帧格式
- `limit`，默认 `8`，`int`，范围 1~+∞：最多返回候选数
- `min_score`，默认 `4.0`，`int`：最低得分阈值
- 返回：list[dict]：候选参数与提取片段

**`describe_params`**（lib.lsb）—— 把 LSB 参数渲染成一句可读描述。

- `channels`，默认 `'RGB'`，`str`：RGB / RGBA / R / G / B / A / RB / GB 等通道组合
- `bit`，默认 `0`，`int`，范围 0~7：位下标
- `offset`，默认 `0`，`int`，范围 0~+∞：起始偏移
- `order`，默认 `'column'`，`str`，可选 `column` / `row`：扫描顺序
- `framing`，默认 `'marker'`，`str`，可选 `marker` / `length`：帧格式
- 返回：str：参数描述

**`read_secret`**（lib.lsb）—— 读取秘密输入：若为存在的文件路径则返回文件文本，否则原样返回。

- `secret_input`，**必填**，`str`：秘密文本或文件路径
- 返回：str：秘密文本

**`add_visible_watermark`**（lib.watermark）—— 在图片上叠加可见文字水印（可平铺）。

- `carrier_path`，**必填**，`str`：载体图片路径
- `watermark_text`，**必填**，`str`：水印文字
- `output_path`，默认 `''`，`str`：输出路径；留空写入配置的输出目录
- `position`，默认 `'bottom-right'`，`str`，可选 `top-left` / `top-right` / `bottom-left` / `bottom-right` / `tile`：水印位置
- `font_size`，默认 `30`，`int`，范围 6~400：字号（像素）
- `color`，默认 `'255,255,255,128'`，`str`：RGBA 颜色，形如 ``255,255,255,128``（末位透明度 0-255）
- `font_path`，默认 `''`，`str`：自定义字体文件路径；留空用内置字体
- 返回：dict：{carrier, out, out_rel, position, font_size, color}

**`parse_color`**（lib.watermark）—— 解析 ``R,G,B,A`` 颜色字符串。

- `text`，**必填**，`str`：形如 ``255,255,255,128``
- 返回：dict：{r, g, b, a}

**`resolve_output_dir`**（lib.watermark）—— 解析水印输出目录（相对路径基于项目根，返回绝对路径）。

- `raw`，默认 `''`，`str`：用户填写的目录；留空用配置默认值
- 返回：str：绝对目录路径

**`out_path`**（lib.watermark）—— 在输出目录下拼出完整文件路径。

- `filename`，**必填**，`str`：文件名
- `raw`，默认 `''`，`str`：自定义输出目录；留空用配置默认值
- 返回：str：绝对文件路径

</details>

### cn_web —— Web 信息收集：Fuzz / JSFinder / 指纹 / 收录 / 网段 / DNS

一站式 Web Fuzz；JS 链接与子域名提取；observer_ward 风格指纹识别；历史收录查询；CIDR 网段 Web 主机发现；DNS 记录解析与子域名爆破。

> 网络类 op 默认复用 config.json 的全局代理池；只对已授权目标使用。长任务（brute_subdomains / httpscan）建议先用小范围参数试探。

| op | 参数（`*` = 必填） | 返回 | 风险 |
| --- | --- | --- | --- |
| `web_fuzz` | `target*`, `timeout`, `with_robots`, `with_sitemap`, `with_hostsearch`, `with_subdomain_brute`, `subdomain_dict`, `subdomain_interval`, `subdomain_use_proxy` | dict：{target, status, headers, security, cookies, title, meta, tech, links, scripts, forms, comments, emails, phones, ips, ...} | `network` |
| `to_text` | `result*` | str：文本报告 | `safe` |
| `extract_url` | `js_text*` | list[str]：提取到的链接 | `safe` |
| `process_url` | `base_url*`, `re_url*` | str：绝对 URL | `safe` |
| `find_subdomain` | `urls*`, `main_url*` | list[str]：子域名（保序去重） | `safe` |
| `find_by_url` | `url*`, `cookie`, `timeout` | list[str]\|null：链接列表 | `network` |
| `find_by_url_deep` | `url*`, `cookie`, `timeout`, `max_links` | list[str]\|null：链接列表 | `network` |
| `jsfinder` | `url*`, `cookie`, `deep`, `timeout`, `max_links` | dict：{urls, subdomains} | `network` |
| `fingerprint` | `target*`, `timeout`, `rules` | dict：{target, matches: [{name, product, version, ...}], ...} | `network` |
| `fingerprint_to_text` | `result*` | str：文本报告 | `safe` |
| `load_rules` | `directories` | list[dict]：规则列表 | `read` |
| `favicon_hashes` | `data*` | dict：{mmh3, md5} | `safe` |
| `query_hostsearch` | `domain*`, `timeout` | dict：{domain, subdomains, ips, ...} | `network` |
| `normalize_domain` | `raw*` | str：纯域名 | `safe` |
| `expand_ips` | `target*` | list[str]：IP 列表 | `safe` |
| `scan_ip` | `ip*`, `timeout`, `https` | dict\|null：{ip, url, status, server, title} | `network` |
| `httpscan` | `target*`, `threads`, `timeout`, `https` | list[dict]：存活主机结果 | `intrusive` |
| `resolve_dns` | `host*`, `use_proxy`, `timeout` | dict：{host, records: [{type, values, note}], ...} | `network` |
| `resolve_record` | `host*`, `rtype*`, `use_proxy`, `timeout` | dict：{type, values, note} | `network` |
| `brute_subdomains` | `base_domain*`, `dict_path`, `interval`, `use_proxy`, `timeout` | dict：{base_domain, count, results, note} | `intrusive` |
| `load_subdomain_words` | `dict_path` | list[str]：词条列表 | `read` |
| `dns_normalize_domain` | `raw*` | str：纯域名 | `safe` |

<details><summary>参数详情</summary>

**`web_fuzz`**（lib.web_fuzz）—— 一站式 Web 信息收集：状态码 / 响应头 / 安全头 / Cookie / 标题 / meta / 技术栈 / 链接 / 脚本 / 表单 / 注释 / 邮箱 / 手机号 / IP，可选附带 robots.txt、sitemap.xml、历史收录、子域名字典爆破。

- `target`，**必填**，`str`：目标 URL 或域名
- `timeout`，默认 `8.0`，`float`，范围 1~120：单次请求超时（秒）
- `with_robots`，默认 `False`，`bool`：顺带抓 robots.txt
- `with_sitemap`，默认 `False`，`bool`：顺带抓 sitemap.xml
- `with_hostsearch`，默认 `False`，`bool`：顺带查历史收录
- `with_subdomain_brute`，默认 `False`，`bool`：顺带做子域名字典爆破（慢）
- `subdomain_dict`，默认 `null`，`str`：子域名字典路径；留空用内置字典
- `subdomain_interval`，默认 `0.3`，`float`，范围 0~10：子域名查询间隔（秒）
- `subdomain_use_proxy`，默认 `False`，`bool`：子域名查询是否走代理
- 返回：dict：{target, status, headers, security, cookies, title, meta, tech, links, scripts, forms, comments, emails, phones, ips, ...}
- 示例：`{"target": "https://example.com"}`

**`to_text`**（lib.web_fuzz）—— 把 Web Fuzz 结果渲染为纯文本报告。

- `result`，**必填**，`any`：web_fuzz.run 的返回 dict
- 返回：str：文本报告

**`extract_url`**（lib.jsfinder）—— 从 JS / HTML 文本中提取链接（保序去重）。

- `js_text`，**必填**，`str`：JS 或 HTML 文本
- 返回：list[str]：提取到的链接

**`process_url`**（lib.jsfinder）—— 把相对链接补全为绝对 URL。

- `base_url`，**必填**，`str`：基准 URL
- `re_url`，**必填**，`str`：待补全的链接
- 返回：str：绝对 URL

**`find_subdomain`**（lib.jsfinder）—— 从 URL 列表里提取主域名下的全部子域名。

- `urls`，**必填**，`list`：URL 列表
- `main_url`，**必填**，`str`：主 URL
- 返回：list[str]：子域名（保序去重）

**`find_by_url`**（lib.jsfinder）—— 抓取页面与全部 script（内嵌 + 外链）提取同域链接。

- `url`，**必填**，`str`：目标页面 URL
- `cookie`，默认 `''`，`str`：Cookie 头
- `timeout`，默认 `5`，`int`，范围 1~+∞：请求超时（秒）
- 返回：list[str]|null：链接列表

**`find_by_url_deep`**（lib.jsfinder）—— 深度模式：跟进页面 ``<a>`` 链接递归收集。

- `url`，**必填**，`str`：目标页面 URL
- `cookie`，默认 `''`，`str`：Cookie 头
- `timeout`，默认 `5`，`int`，范围 1~+∞：请求超时（秒）
- `max_links`，默认 `50`，`int`，范围 1~500：最多跟进的链接数
- 返回：list[str]|null：链接列表

**`jsfinder`**（lib.jsfinder）—— JSFinder 主入口：返回 URL 列表与子域名列表。

- `url`，**必填**，`str`：目标页面 URL
- `cookie`，默认 `''`，`str`：Cookie 头
- `deep`，默认 `False`，`bool`：深度模式（跟进链接，更慢更全）
- `timeout`，默认 `5`，`int`，范围 1~+∞：请求超时（秒）
- `max_links`，默认 `50`，`int`，范围 1~+∞：深度模式最多跟进链接数
- 返回：dict：{urls, subdomains}

**`fingerprint`**（lib.fingerprint）—— Web 指纹识别（observer_ward 风格）：识别产品 / 组件 / 厂商 / 版本。

- `target`，**必填**，`str`：目标 URL
- `timeout`，默认 `8.0`，`float`，范围 1~+∞：请求超时（秒）
- `rules`，默认 `null`，`any`：自定义规则列表；留空用 ``dict/fingerprints`` 内置规则
- 返回：dict：{target, matches: [{name, product, version, ...}], ...}

**`fingerprint_to_text`**（lib.fingerprint）—— 把指纹识别结果渲染为纯文本报告。

- `result`，**必填**，`any`：fingerprint.run 的返回 dict
- 返回：str：文本报告

**`load_rules`**（lib.fingerprint）—— 加载指纹规则目录（或单个 YAML 文件）。

- `directories`，默认 `null`，`list`：规则目录 / 文件列表；留空用内置目录
- 返回：list[dict]：规则列表

**`favicon_hashes`**（lib.fingerprint）—— 计算 favicon 的 mmh3 与 md5 双哈希（与 shodan 一致）。

- `data`，**必填**，`hex`：favicon 原始字节的十六进制
- 返回：dict：{mmh3, md5}

**`query_hostsearch`**（lib.hostsearch）—— 查询域名历史收录（hackertarget）。

- `domain`，**必填**，`str`：域名（可带协议前缀）
- `timeout`，默认 `8.0`，`float`，范围 1~+∞：请求超时（秒）
- 返回：dict：{domain, subdomains, ips, ...}

**`normalize_domain`**（lib.hostsearch）—— 规范化域名：去掉协议 / 路径 / 端口。

- `raw`，**必填**，`str`：原始域名或 URL
- 返回：str：纯域名

**`expand_ips`**（lib.httpscan）—— 把 CIDR（如 192.168.1.0/24）或单个 IP 展开为 IP 列表。

- `target`，**必填**，`str`：CIDR 或 IP
- 返回：list[str]：IP 列表

**`scan_ip`**（lib.httpscan）—— 探测单个 IP 上的 Web 服务（无 Web 服务返回 null）。

- `ip`，**必填**，`str`：目标 IP
- `timeout`，默认 `5`，`int`，范围 1~+∞：超时（秒）
- `https`，默认 `False`，`bool`：是否走 https
- 返回：dict|null：{ip, url, status, server, title}

**`httpscan`**（lib.httpscan）—— 多线程扫描网段，返回存活 Web 主机列表。

- `target`，**必填**，`str`：CIDR 或 IP
- `threads`，默认 `10`，`int`，范围 1~200：并发线程数
- `timeout`，默认 `5`，`int`，范围 1~+∞：单主机超时（秒）
- `https`，默认 `False`，`bool`：是否走 https
- 返回：list[dict]：存活主机结果
- 备注：网段扫描请只用于已授权目标。

**`resolve_dns`**（lib.dns_tool）—— DNS 解析：返回 A / AAAA / CNAME / MX / TXT / NS 等记录。

- `host`，**必填**，`str`：域名
- `use_proxy`，默认 `False`，`bool`：是否走 SOCKS5 代理做远程 DNS
- `timeout`，默认 `8.0`，`float`，范围 1~+∞：查询超时（秒）
- 返回：dict：{host, records: [{type, values, note}], ...}

**`resolve_record`**（lib.dns_tool）—— 查询单条 DNS 记录类型。

- `host`，**必填**，`str`：域名
- `rtype`，**必填**，`str`，可选 `A` / `AAAA` / `CNAME` / `MX` / `TXT` / `NS` / `SOA`：记录类型
- `use_proxy`，默认 `False`，`bool`：是否走 SOCKS5 代理
- `timeout`，默认 `8.0`，`float`，范围 1~+∞：查询超时（秒）
- 返回：dict：{type, values, note}

**`brute_subdomains`**（lib.dns_tool）—— 子域名字典爆破：逐个拼 ``词条.主域名`` 做 DNS A 查询。

- `base_domain`，**必填**，`str`：主域名
- `dict_path`，默认 `null`，`str`：子域名字典路径；留空用内置字典
- `interval`，默认 `0.3`，`float`，范围 0~10：每次查询间隔（秒）
- `use_proxy`，默认 `False`，`bool`：是否走代理
- `timeout`，默认 `8.0`，`float`，范围 1~+∞：单次查询超时（秒）
- 返回：dict：{base_domain, count, results, note}
- 备注：字典较大时耗时较长；建议先用小字典试探。

**`load_subdomain_words`**（lib.dns_tool）—— 读取子域名字典（去空行 / 注释 / 去重）。

- `dict_path`，默认 `null`，`str`：字典路径；留空用内置字典
- 返回：list[str]：词条列表

**`dns_normalize_domain`**（lib.dns_tool）—— 规范化域名：去协议 / 路径 / 端口（DNS 模块版本）。

- `raw`，**必填**，`str`：原始域名或 URL
- 返回：str：纯域名

</details>

### cn_requester —— HTTP 请求器：常量 / 循环（Burp 风格）+ 密码学载荷

自定义 URL / 方法 / 查询参数 / 请求头 / 请求体的 HTTP 请求发送器（不抓包）。常量模式发一次；循环模式按 Sniper / Battering ram / Pitchfork / Cluster bomb 批量替换载荷位置，载荷可用密码学接口批量生成。

> 载荷位置写 {{payload}}；载荷按字面发送，不会被二次 URL 编码。先 plan 看总量，再用 loop 发送；只对已授权目标使用。crypto_list 可查全部密码学载荷生成器。

| op | 参数（`*` = 必填） | 返回 | 风险 |
| --- | --- | --- | --- |
| `send` | `url`, `method`, `query`, `headers`, `body`, `body_kind`, `scheme`, `spec`, `timeout`, `redirects`, `verify`, `workers`, `delay`, `payload` | dict：{mode, total, done, responses: [{index, status, length, url, ...}]} | `network` |
| `loop` | `url`, `method`, `query`, `headers`, `body`, `body_kind`, `scheme`, `spec`, `timeout`, `redirects`, `verify`, `workers`, `delay`, `attack`, `payloads`, `per_location`, `crypto`, `crypto_params` | dict：{mode, attack, total, done, responses: [{payloads, status, ...}]} | `intrusive` |
| `plan` | `url`, `method`, `query`, `headers`, `body`, `body_kind`, `scheme`, `spec`, `mode`, `attack`, `payloads`, `per_location`, `crypto`, `crypto_params` | dict：{slots, total_requests, sample_requests, warning} | `safe` |
| `compose` | `url`, `method`, `query`, `headers`, `body`, `body_kind`, `scheme`, `spec`, `values` | dict：{method, url, headers, body, query, request_dump} | `safe` |
| `crypto_list` | — | dict：{count, groups, ops: [...]} | `safe` |
| `crypto_transform` | `data*`, `op*`, `params` | dict：{op, label, count, outputs, text, errors} | `safe` |
| `url_safe` | `text*` | str：安全化后的文本 | `safe` |
| `split_payloads` | `text*` | list[str]：载荷列表 | `safe` |
| `to_text` | `result*` | str：文本报告 | `safe` |

<details><summary>参数详情</summary>

**`send`**（lib.http_requester）—— 常量模式：发一次请求，把 {{payload}} 全部换成 payload 的值。

- `url`，默认 `''`，`str`：目标 URL（可含 {{payload}}）
- `method`，默认 `'GET'`，`str`：请求方法，任意字符串（GET/POST/PUT…）
- `query`，默认 `null`，`any`：查询参数：``"a=1&b=2"`` 字符串或 {"a": "1"} 对象
- `headers`，默认 `null`，`any`：请求头：``"X-A: 1\nX-B: 2"`` 字符串或 {"X-A": "1"}
- `body`，默认 `null`，`any`：请求体：字符串 / 对象 / [{name,value}] 列表
- `body_kind`，默认 `''`，`str`，可选 `none` / `form` / `json` / `text`：请求体类型
- `scheme`，默认 `'http'`，`str`，可选 `http` / `https`：URL 缺协议头时补的协议
- `spec`，默认 `null`，`dict`：或直接给完整请求对象（键同上述 url/method/query/headers/body）
- `timeout`，默认 `15.0`，`float`，范围 1~300：单次请求超时（秒）
- `redirects`，默认 `False`，`bool`：是否跟随重定向
- `verify`，默认 `False`，`bool`：是否校验证书
- `workers`，默认 `1`，`int`，范围 1~32：并发数（循环模式）
- `delay`，默认 `0.0`，`float`，范围 0~60：每次请求间隔（秒）
- `payload`，默认 `''`，`str`：常量值，替换请求里所有 {{payload}}
- 返回：dict：{mode, total, done, responses: [{index, status, length, url, ...}]}
- 示例：`{"url": "https://example.com/api", "method": "POST", "query": {"token": "{{payload}}"}, "body": "data={{payload}}", "body_kind": "form", "payload": "aGVsbG8+"}`
- 备注：载荷按字面发送，不会被二次 URL 编码。

**`loop`**（lib.http_requester）—— 循环模式：按攻击类型批量替换载荷位置后逐个发请求。

- `url`，默认 `''`，`str`：目标 URL（可含 {{payload}}）
- `method`，默认 `'GET'`，`str`：请求方法，任意字符串（GET/POST/PUT…）
- `query`，默认 `null`，`any`：查询参数：``"a=1&b=2"`` 字符串或 {"a": "1"} 对象
- `headers`，默认 `null`，`any`：请求头：``"X-A: 1\nX-B: 2"`` 字符串或 {"X-A": "1"}
- `body`，默认 `null`，`any`：请求体：字符串 / 对象 / [{name,value}] 列表
- `body_kind`，默认 `''`，`str`，可选 `none` / `form` / `json` / `text`：请求体类型
- `scheme`，默认 `'http'`，`str`，可选 `http` / `https`：URL 缺协议头时补的协议
- `spec`，默认 `null`，`dict`：或直接给完整请求对象（键同上述 url/method/query/headers/body）
- `timeout`，默认 `15.0`，`float`，范围 1~300：单次请求超时（秒）
- `redirects`，默认 `False`，`bool`：是否跟随重定向
- `verify`，默认 `False`，`bool`：是否校验证书
- `workers`，默认 `1`，`int`，范围 1~32：并发数（循环模式）
- `delay`，默认 `0.0`，`float`，范围 0~60：每次请求间隔（秒）
- `attack`，默认 `'sniper'`，`str`，可选 `sniper` / `batteringram` / `pitchfork` / `clusterbomb`：攻击类型
- `payloads`，默认 `''`，`str`：通用载荷列表（每行一个）
- `per_location`，默认 `null`，`dict`：按位置给载荷：{位置键: '每行一个' 或 [载荷…]}
- `crypto`，默认 `''`，`str`：先用该密码学生成器变换 payloads（见 crypto_list）
- `crypto_params`，默认 `null`，`dict`：密码学生成器的参数，如 {"key": "…"}
- 返回：dict：{mode, attack, total, done, responses: [{payloads, status, ...}]}
- 示例：`{"url": "https://example.com/api", "method": "POST", "body": "cipher={{payload}}", "body_kind": "form", "attack": "sniper", "payloads": "flag\nadmin", "crypto": "crypto.base64"}`
- 备注：载荷位置：query / header / body / url；亦可用单位置键（如 query:0:0）精确指定。主动批量请求请只用于已授权目标；建议先用 plan 看总量。

**`plan`**（lib.http_requester）—— 只计算不发送：返回载荷位置、总请求数与样例报文 URL。

- `url`，默认 `''`，`str`：目标 URL（可含 {{payload}}）
- `method`，默认 `'GET'`，`str`：请求方法，任意字符串（GET/POST/PUT…）
- `query`，默认 `null`，`any`：查询参数：``"a=1&b=2"`` 字符串或 {"a": "1"} 对象
- `headers`，默认 `null`，`any`：请求头：``"X-A: 1\nX-B: 2"`` 字符串或 {"X-A": "1"}
- `body`，默认 `null`，`any`：请求体：字符串 / 对象 / [{name,value}] 列表
- `body_kind`，默认 `''`，`str`，可选 `none` / `form` / `json` / `text`：请求体类型
- `scheme`，默认 `'http'`，`str`，可选 `http` / `https`：URL 缺协议头时补的协议
- `spec`，默认 `null`，`dict`：或直接给完整请求对象（键同上述 url/method/query/headers/body）
- `mode`，默认 `'loop'`，`str`，可选 `const` / `loop`：模式
- `attack`，默认 `'sniper'`，`str`，可选 `sniper` / `batteringram` / `pitchfork` / `clusterbomb`：攻击类型
- `payloads`，默认 `''`，`str`：通用载荷列表（每行一个）
- `per_location`，默认 `null`，`dict`：按位置给载荷
- `crypto`，默认 `''`，`str`：先用该密码学生成器变换 payloads
- `crypto_params`，默认 `null`，`dict`：密码学生成器参数
- 返回：dict：{slots, total_requests, sample_requests, warning}

**`compose`**（lib.http_requester）—— 只组装报文不发送：返回最终 URL / 请求头 / 请求体 / Burp 风格报文。

- `url`，默认 `''`，`str`：目标 URL（可含 {{payload}}）
- `method`，默认 `'GET'`，`str`：请求方法，任意字符串（GET/POST/PUT…）
- `query`，默认 `null`，`any`：查询参数：``"a=1&b=2"`` 字符串或 {"a": "1"} 对象
- `headers`，默认 `null`，`any`：请求头：``"X-A: 1\nX-B: 2"`` 字符串或 {"X-A": "1"}
- `body`，默认 `null`，`any`：请求体：字符串 / 对象 / [{name,value}] 列表
- `body_kind`，默认 `''`，`str`，可选 `none` / `form` / `json` / `text`：请求体类型
- `scheme`，默认 `'http'`，`str`，可选 `http` / `https`：URL 缺协议头时补的协议
- `spec`，默认 `null`，`dict`：或直接给完整请求对象（键同上述 url/method/query/headers/body）
- `values`，默认 `null`，`list`：按载荷位置顺序给出的载荷值列表
- 返回：dict：{method, url, headers, body, query, request_dump}
- 备注：最适合用来确认「已编码的密文有没有被再编码」。

**`crypto_list`**（lib.crypto_interface）—— 列出全部密码学载荷生成器（可用于 loop 的 crypto 参数）。

- 无参数
- 返回：dict：{count, groups, ops: [...]}

**`crypto_transform`**（lib.crypto_interface）—— 用密码学生成器把多行明文批量变换成载荷。

- `data`，**必填**，`str`：明文，每行一个
- `op`，**必填**，`str`：生成器 id，如 crypto.base64
- `params`，默认 `null`，`dict`：生成器参数，如 {"shift": 3}
- 返回：dict：{op, label, count, outputs, text, errors}
- 示例：`{"data": "flag\nhello", "op": "crypto.base64"}`

**`url_safe`**（lib.http_requester）—— 最小 URL 安全化：只编码空格 / 非 ASCII / 保留 % + = 等。

- `text`，**必填**，`str`：原文
- 返回：str：安全化后的文本

**`split_payloads`**（lib.http_requester）—— 把多行文本切成载荷列表（忽略空行）。

- `text`，**必填**，`str`：多行文本
- 返回：list[str]：载荷列表

**`to_text`**（lib.http_requester）—— 把 loop / send 的结果渲染成纯文本报告。

- `result`，**必填**，`any`：loop / send 的返回 dict
- 返回：str：文本报告

</details>

### cn_scan —— 扫描：目录 / 端口 / 参数 / 泄露 / 多地 Ping

目录爆破；端口扫描（表达式 / 字典 / 代理轮换）；参数发现 Fuzz；.git/.svn/.DS_Store 源码泄露检测；多地 Ping 探活。

> 全部为主动探测能力，仅用于已授权目标。耗时 op 请先小范围试探：目录爆破用小字典、端口扫描用常见端口、参数 Fuzz 用 small 字典。

| op | 参数（`*` = 必填） | 返回 | 风险 |
| --- | --- | --- | --- |
| `scan` | `target*`, `out_dir`, `dict_dir`, `words`, `threads`, `timeout`, `interval`, `headers` | dict：{target, hits: [{url, status, length, ...}], requests, elapsed, ...} | `intrusive` |
| `list_dict_files` | `dict_dir` | list[str]：字典文件路径 | `read` |
| `load_words` | `dict_dir`, `files` | dict：{words, files: [[文件名, 词条数], …]} | `read` |
| `default_dict_dir` | — | str：字典目录路径 | `safe` |
| `port_scan` | `host*`, `ports`, `threads`, `timeout`, `retries`, `use_proxy`, `service_names`, `verify_proxies`, `out_dir` | dict：{host, open: [{port, service, banner, ms}], ...} | `intrusive` |
| `parse_ports` | `text*`, `limit` | list[int]：端口列表 | `safe` |
| `load_all_dicts` | `directory` | dict：{端口: 服务名} | `read` |
| `run` | `target*`, `method`, `wordlist`, `include`, `headers`, `timeout`, `threads`, `chunks`, `delay`, `rate_limit` | dict：{target, method, found_params, total_requests, elapsed, ...} | `intrusive` |
| `to_text` | `result*` | str：文本报告 | `safe` |
| `leak_scan` | `target*`, `kinds`, `threads`, `timeout`, `out_dir` | dict：{target, out_dir, count, results: [...]} | `intrusive` |
| `normalize_target` | `raw*` | str：规范化后的 URL | `safe` |
| `ping` | `host*`, `base_url`, `api_id`, `api_key`, `dy`, `headers`, `timeout` | dict：{host, nodes: [{node, ip, ms, ...}], error} | `network` |
| `ping_batch` | `hosts*`, `base_url`, `api_id`, `api_key`, `dy`, `headers`, `timeout` | list[dict]：每个目标的 Ping 报告 | `network` |

<details><summary>参数详情</summary>

**`scan`**（lib.dir_scan）—— 目录爆破：按字典逐条探测目标路径（合并 ``dict/Contents`` 全部字典）。

- `target`，**必填**，`str`：目标 URL
- `out_dir`，默认 `null`，`str`：结果输出目录；留空不落盘
- `dict_dir`，默认 `null`，`str`：字典目录；留空用 ``dict/Contents``
- `words`，默认 `null`，`list`：自定义词条列表（给了就不再读字典）
- `threads`，默认 `16`，`int`，范围 1~200：并发线程数
- `timeout`，默认 `6.0`，`float`，范围 1~+∞：单请求超时（秒）
- `interval`，默认 `30.0`，`float`，范围 0~+∞：每轮之间的间隔（秒）
- `headers`，默认 `''`，`str`：自定义请求头，多行 ``Key: Value``
- 返回：dict：{target, hits: [{url, status, length, ...}], requests, elapsed, ...}
- 备注：耗时工具；建议先用小字典 + 短超时试探。

**`list_dict_files`**（lib.dir_scan）—— 列出字典目录下的全部字典文件。

- `dict_dir`，默认 `null`，`str`：字典目录；留空用 ``dict/Contents``
- 返回：list[str]：字典文件路径

**`load_words`**（lib.dir_scan）—— 读取字典目录下全部字典，合并去重。

- `dict_dir`，默认 `null`，`str`：字典目录；留空用内置目录
- `files`，默认 `null`，`list`：只读指定文件列表
- 返回：dict：{words, files: [[文件名, 词条数], …]}

**`default_dict_dir`**（lib.dir_scan）—— 返回内置目录字典的绝对路径。

- 无参数
- 返回：str：字典目录路径

**`port_scan`**（lib.port_scan）—— 端口扫描：端口来源支持表达式（``80,443,1-1024``）、内置字典名（``常见端口.txt`` / ``全端口1-1024.txt`` / ``高危端口.txt``）或字典文件路径。

- `host`，**必填**，`str`：目标主机（IP 或域名）
- `ports`，默认 `'常见端口.txt'`，`str`：端口表达式 / 字典名 / 字典路径；all 表示 1-65535
- `threads`，默认 `24`，`int`，范围 1~256：并发线程数
- `timeout`，默认 `6.0`，`float`，范围 0.5~+∞：单端口超时（秒）
- `retries`，默认 `3`，`int`，范围 1~10：失败重试次数
- `use_proxy`，默认 `False`，`bool`：是否轮换全局代理池
- `service_names`，默认 `True`，`bool`：是否用字典补充服务名
- `verify_proxies`，默认 `True`，`bool`：扫描前先验证代理可用性
- `out_dir`，默认 `null`，`str`：结果输出目录；留空不落盘
- 返回：dict：{host, open: [{port, service, banner, ms}], ...}

**`parse_ports`**（lib.port_scan）—— 解析端口表达式（``80`` / ``80,443`` / ``1-1024`` / 空格换行分隔）。

- `text`，**必填**，`str`：端口表达式
- `limit`，默认 `65536`，`int`，范围 1~+∞：最多返回多少个端口
- 返回：list[int]：端口列表

**`load_all_dicts`**（lib.port_scan）—— 合并端口字典目录下全部字典为 ``{端口: 服务名}``。

- `directory`，默认 `null`，`str`：字典目录；留空用内置 ``dict/Ports``
- 返回：dict：{端口: 服务名}

**`run`**（lib.param_fuzz）—— 参数发现：对目标接口做参数爆破（GET / POST / JSON / XML）。

- `target`，**必填**，`str`：目标 URL
- `method`，默认 `'GET'`，`str`，可选 `GET` / `POST` / `JSON` / `XML`：请求方法
- `wordlist`，默认 `'small'`，`str`：字典名（small / medium / large）或文件路径
- `include`，默认 `''`，`str`：每次请求固定携带的负载；JSON/XML 可用 ``$arjun$`` 占位
- `headers`，默认 `''`，`str`：自定义请求头，多行 ``Key: Value``
- `timeout`，默认 `15.0`，`float`，范围 1~+∞：单请求超时（秒）
- `threads`，默认 `5`，`int`，范围 1~50：并发线程数
- `chunks`，默认 `250`，`int`，范围 1~+∞：每组参数数量
- `delay`，默认 `0.0`，`float`，范围 0~+∞：每次请求间隔（秒）
- `rate_limit`，默认 `0`，`int`，范围 0~+∞：每秒最大请求数（0 = 不限速）
- 返回：dict：{target, method, found_params, total_requests, elapsed, ...}

**`to_text`**（lib.param_fuzz）—— 把参数 Fuzz 结果渲染为纯文本报告。

- `result`，**必填**，`dict`：param_fuzz.run 的返回 dict
- 返回：str：文本报告

**`leak_scan`**（lib.leak_scan）—— 源码泄露检测：探测 ``.git`` / ``.svn`` / ``.DS_Store`` 是否可访问并尝试还原；另一类 ``files`` 按静态清单并发探测敏感文件（vim ``.swp`` / ``~`` / ``.bak`` 备份、``.env``、``.hg`` / ``.bzr``、整站打包、SQL 转储、Actuator / Druid 等），只报告不还原。

- `target`，**必填**，`str`：目标域名或 URL
- `kinds`，默认 `null`，`list`：检测类型子集（git / svn / ds_store / files），留空全查
- `threads`，默认 `8`，`int`，范围 1~100：并发线程数
- `timeout`，默认 `8.0`，`float`，范围 1~+∞：请求超时（秒）
- `out_dir`，默认 `null`，`str`：输出目录；留空用配置 output/leak
- 返回：dict：{target, out_dir, count, results: [...]}

**`normalize_target`**（lib.leak_scan）—— 规范化目标：缺协议自动补 ``http://``。

- `raw`，**必填**，`str`：域名或 URL
- 返回：str：规范化后的 URL

**`ping`**（lib.ping_probe）—— 多地 Ping：通过接口盒子 API 从多节点探测延迟与解析结果。

- `host`，**必填**，`str`：目标域名或 IP
- `base_url`，默认 `''`，`str`：API 地址；留空用配置值
- `api_id`，默认 `''`，`str`：API 用户 ID；留空用配置值
- `api_key`，默认 `''`，`str`：API 通讯密钥；留空用配置值
- `dy`，默认 `''`，`str`：dy 参数（0 = 默认线路）
- `headers`，默认 `''`，`str`：自定义请求头，多行 ``Key: Value``
- `timeout`，默认 `30.0`，`float`，范围 1~+∞：请求超时（秒）
- 返回：dict：{host, nodes: [{node, ip, ms, ...}], error}

**`ping_batch`**（lib.ping_probe）—— 批量多地 Ping（顺序执行）。

- `hosts`，**必填**，`list`：目标列表
- `base_url`，默认 `''`，`str`：API 地址；留空用配置值
- `api_id`，默认 `''`，`str`：API 用户 ID；留空用配置值
- `api_key`，默认 `''`，`str`：API 通讯密钥；留空用配置值
- `dy`，默认 `''`，`str`：dy 参数
- `headers`，默认 `''`，`str`：自定义请求头，多行 ``Key: Value``
- `timeout`，默认 `30.0`，`float`，范围 1~+∞：单目标超时（秒）
- 返回：list[dict]：每个目标的 Ping 报告

</details>

### cn_attack —— 攻击：SSTI / MySQL / 微信凭证 / 压缩包 / 哈希爆破

SSTI 模板注入探测；MySQL 指纹与登录爆破；微信公众号凭证校验；ZIP 伪加密修复 / 解压 / CRC32 碰撞 / 密码爆破；MD5 等哈希爆破（枚举 / 字典 / 候选）。

> 爆破类 op 会消耗大量 CPU / 网络，默认都带时间上限（max_seconds）；仅可用于已授权目标。线程型任务在达到上限时会自动停止并返回当前状态。

| op | 参数（`*` = 必填） | 返回 | 风险 |
| --- | --- | --- | --- |
| `run` | `url*`, `param*`, `method`, `data`, `cookie`, `headers`, `proxy`, `prefix`, `timeout`, `enum_all` | dict：{url, param, vulnerable, prefix, subclasses, rce_hits, ...} | `intrusive` |
| `probe` | `host*`, `port`, `timeout` | dict：{user, password, state, code, message, plugin, ms, host} | `network` |
| `banner_grab` | `host*`, `port`, `timeout` | dict：{version, plugin, salt, capability, ...} | `network` |
| `try_login` | `host*`, `port`, `user*`, `password`, `timeout`, `probe_only` | dict：{user, state, code, message, plugin, ms} | `intrusive` |
| `brute` | `host*`, `port`, `users*`, `passwords*`, `threads`, `timeout`, `max_attempts`, `out_dir` | dict：{host, attempts, hits: [...], ...} | `intrusive` |
| `classify_target` | `host*` | str：'ip' / 'domain' | `safe` |
| `default_users` | — | list[str]：用户名 | `safe` |
| `default_passwords` | — | list[str]：密码 | `safe` |
| `load_lines` | `path*`, `limit` | list[str]：词条 | `read` |
| `check_credential` | `appid*`, `secret*`, `timeout`, `base_url` | dict：{appid, valid, access_token, expires_in, errcode, errmsg, raw} | `network` |
| `wechat_check_many` | `pairs*`, `timeout`, `base_url` | list[dict]：每组凭证的校验结果 | `network` |
| `parse_inputs` | `text*` | list[list[str]]：凭证对 | `safe` |
| `split_pair` | `line*` | dict：{appid, secret} | `safe` |
| `zip_list_entries` | `zip_path*` | list[dict]：{name, size, crc, encrypted, is_dir} | `read` |
| `zip_is_encrypted` | `zip_path*` | bool：是否需要密码 | `read` |
| `zip_is_fake_encrypted` | `zip_path*` | bool：是否伪加密 | `read` |
| `zip_fix_fake_encrypted` | `zip_path*`, `out_path` | dict：{src, out, out_rel} | `write` |
| `zip_extract` | `zip_path*`, `out_dir`, `password` | dict：{zip, out_dir, out_rel, count, files} | `write` |
| `zip_small_crc_candidates` | `zip_path*`, `max_size` | list[dict]：候选条目 | `read` |
| `crc32_crack` | `crc*`, `size*`, `alphabet` | str\|null：命中的明文 | `long` |
| `zip_crack` | `zip_path*`, `dict_path`, `use_builtin`, `max_numeric_len`, `custom_first`, `max_seconds` | dict：{status, result, error, finished, events, zip, tried} | `long` |
| `builtin_dict_path` | — | str：字典路径 | `safe` |
| `md5_crack` | `hash_value*`, `min_len`, `max_len`, `worker_num`, `thread_num`, `charset`, `dict_path`, `candidates`, `prefix`, `suffix`, `hash_name`, `max_seconds` | dict：{status, result, error, finished, events, hash_name, hash} | `long` |
| `hash_length` | `hash_name` | int：摘要长度 | `safe` |

<details><summary>参数详情</summary>

**`run`**（lib.ssti_finder）—— SSTI 模板注入探测：注入探测载荷，枚举可 RCE 的模板子类。

- `url`，**必填**，`str`：目标 URL
- `param`，**必填**，`str`：注入参数名
- `method`，默认 `'GET'`，`str`，可选 `GET` / `POST`：请求方法
- `data`，默认 `''`，`str`：POST body
- `cookie`，默认 `''`，`str`：Cookie 头
- `headers`，默认 `''`，`str`：自定义请求头，多行 ``Key: Value``
- `proxy`，默认 `''`，`str`：单次请求使用的代理（留空走全局代理池）
- `prefix`，默认 `'().__class__.__bases__[0]'`，`str`：注入前缀（payload 起始对象）
- `timeout`，默认 `15.0`，`float`，范围 1~+∞：单请求超时（秒）
- `enum_all`，默认 `False`，`bool`：枚举全部子类（更慢更全）
- 返回：dict：{url, param, vulnerable, prefix, subclasses, rce_hits, ...}

**`probe`**（lib.mysql_brute）—— MySQL 被动指纹：确认目标是否为 MySQL 并读取版本 / 认证方式（不爆破）。

- `host`，**必填**，`str`：目标主机
- `port`，默认 `3306`，`int`，范围 1~65535：端口
- `timeout`，默认 `6.0`，`float`，范围 1~+∞：超时（秒）
- 返回：dict：{user, password, state, code, message, plugin, ms, host}

**`banner_grab`**（lib.mysql_brute）—— 抓取 MySQL 服务端 banner 与握手信息。

- `host`，**必填**，`str`：目标主机
- `port`，默认 `3306`，`int`，范围 1~65535：端口
- `timeout`，默认 `6.0`，`float`，范围 1~+∞：超时（秒）
- 返回：dict：{version, plugin, salt, capability, ...}

**`try_login`**（lib.mysql_brute）—— 用一组用户名密码尝试登录。

- `host`，**必填**，`str`：目标主机
- `port`，默认 `3306`，`int`，范围 1~65535：端口
- `user`，**必填**，`str`：用户名
- `password`，默认 `''`，`str`：密码
- `timeout`，默认 `6.0`，`float`，范围 1~+∞：超时（秒）
- `probe_only`，默认 `False`，`bool`：只探测不真正登录
- 返回：dict：{user, state, code, message, plugin, ms}

**`brute`**（lib.mysql_brute）—— MySQL 用户名×密码组合爆破（线程池 + 上限）。

- `host`，**必填**，`str`：目标主机
- `port`，默认 `3306`，`int`，范围 1~65535：端口
- `users`，**必填**，`list`：用户名列表
- `passwords`，**必填**，`list`：密码列表
- `threads`，默认 `8`，`int`，范围 1~64：并发线程数
- `timeout`，默认 `6.0`，`float`，范围 1~+∞：单次超时（秒）
- `max_attempts`，默认 `0`，`int`，范围 0~+∞：最大尝试次数（0 = 不限）
- `out_dir`，默认 `null`，`str`：结果输出目录；留空不落盘
- 返回：dict：{host, attempts, hits: [...], ...}

**`classify_target`**（lib.mysql_brute）—— 判断目标是 IP 还是域名（用于选字典策略）。

- `host`，**必填**，`str`：目标主机
- 返回：str：'ip' / 'domain'

**`default_users`**（lib.mysql_brute）—— 内置默认用户名列表。

- 无参数
- 返回：list[str]：用户名

**`default_passwords`**（lib.mysql_brute）—— 内置默认密码列表。

- 无参数
- 返回：list[str]：密码

**`load_lines`**（lib.mysql_brute）—— 读取一行一个的字典文件（去 BOM / 去注释 / 去重）。

- `path`，**必填**，`str`：字典文件路径
- `limit`，默认 `200000`，`int`，范围 1~+∞：最多读取行数
- 返回：list[str]：词条

**`check_credential`**（lib.wechat_check）—— 校验一组微信公众号 AppID / AppSecret 是否有效（返回 access_token）。

- `appid`，**必填**，`str`：AppID
- `secret`，**必填**，`str`：AppSecret
- `timeout`，默认 `15.0`，`float`，范围 1~+∞：超时（秒）
- `base_url`，默认 `'https://api.weixin.qq.com/cgi-bin/token'`，`str`：校验接口地址
- 返回：dict：{appid, valid, access_token, expires_in, errcode, errmsg, raw}

**`wechat_check_many`**（lib.wechat_check）—— 批量校验多组微信公众号凭证（逐条顺序请求）。

- `pairs`，**必填**，`any`：[[appid, secret], …] 列表，或 ``appid:secret`` 多行文本
- `timeout`，默认 `15.0`，`float`，范围 1~+∞：单组超时（秒）
- `base_url`，默认 `'https://api.weixin.qq.com/cgi-bin/token'`，`str`：校验接口地址
- 返回：list[dict]：每组凭证的校验结果

**`parse_inputs`**（lib.wechat_check）—— 把批量输入文本解析成 (appid, secret) 列表。

- `text`，**必填**，`str`：多行 ``appid:secret`` 文本
- 返回：list[list[str]]：凭证对

**`split_pair`**（lib.wechat_check）—— 把一行解析成 (appid, secret)。

- `line`，**必填**，`str`：一行凭证文本
- 返回：dict：{appid, secret}

**`zip_list_entries`**（lib.zip_cracker）—— 列出压缩包条目（名称 / 大小 / CRC / 是否加密）。

- `zip_path`，**必填**，`str`：压缩包路径（相对项目根或绝对）
- 返回：list[dict]：{name, size, crc, encrypted, is_dir}

**`zip_is_encrypted`**（lib.zip_cracker）—— 压缩包是否有条目被标记加密（含伪加密）。

- `zip_path`，**必填**，`str`：压缩包路径
- 返回：bool：是否需要密码

**`zip_is_fake_encrypted`**（lib.zip_cracker）—— 判定是否为伪加密（标志位标记但数据未加密）。

- `zip_path`，**必填**，`str`：压缩包路径
- 返回：bool：是否伪加密

**`zip_fix_fake_encrypted`**（lib.zip_cracker）—— 修复伪加密：清除加密标志位后另存为新压缩包。

- `zip_path`，**必填**，`str`：压缩包路径
- `out_path`，默认 `''`，`str`：输出路径；留空写 ``<名字>_fixed.zip``
- 返回：dict：{src, out, out_rel}

**`zip_extract`**（lib.zip_cracker）—— 解压压缩包（可带密码）。

- `zip_path`，**必填**，`str`：压缩包路径
- `out_dir`，默认 `''`，`str`：输出目录；留空写 ``output/<包名>/``
- `password`，默认 `null`，`str`：解压密码（无密码留空）
- 返回：dict：{zip, out_dir, out_rel, count, files}

**`zip_small_crc_candidates`**（lib.zip_cracker）—— 列出适合 CRC32 碰撞的条目（未加密、非目录、大小 ≤ max_size）。

- `zip_path`，**必填**，`str`：压缩包路径
- `max_size`，默认 `6`，`int`，范围 1~32：明文最大长度
- 返回：list[dict]：候选条目

**`crc32_crack`**（lib.zip_cracker）—— CRC32 碰撞：已知 CRC 与明文长度，按字符集还原明文。

- `crc`，**必填**，`int`：目标 CRC32（十进制）
- `size`，**必填**，`int`，范围 1~12：明文长度
- `alphabet`，默认 `'0123456789'`，`str`：字符集，或预设名 digits / lower / alpha / printable
- 返回：str|null：命中的明文
- 备注：组合数随 size 指数增长；size > 8 时可能很慢。

**`zip_crack`**（lib.zip_cracker）—— 压缩包密码爆破：内置字典 + 纯数字枚举，找到密码立即返回。

- `zip_path`，**必填**，`str`：压缩包路径
- `dict_path`，默认 `null`，`str`：自定义字典路径；留空用内置字典
- `use_builtin`，默认 `True`，`bool`：是否叠加内置字典
- `max_numeric_len`，默认 `6`，`int`，范围 0~12：纯数字密码最大位数
- `custom_first`，默认 `True`，`bool`：是否优先用自定义字典
- `max_seconds`，默认 `600.0`，`float`，范围 1~3600：最长运行秒数（到点停止）
- 返回：dict：{status, result, error, finished, events, zip, tried}

**`builtin_dict_path`**（lib.zip_cracker）—— 内置压缩包密码字典的绝对路径。

- 无参数
- 返回：str：字典路径

**`md5_crack`**（lib.md5_crash）—— 哈希爆破：枚举模式（长度 + 字符集）、字典模式、候选列表模式三种。

- `hash_value`，**必填**，`str`：目标哈希值（十六进制）
- `min_len`，默认 `null`，`int`，范围 0~64：枚举最小长度（枚举模式必填）
- `max_len`，默认 `null`，`int`，范围 0~64：枚举最大长度（枚举模式必填）
- `worker_num`，默认 `8`，`int`，范围 1~64：工作进程数
- `thread_num`，默认 `8`，`int`，范围 1~64：每进程线程数
- `charset`，默认 `null`，`str`：字符集或预设名 digits / letters / mixed；留空用 mixed
- `dict_path`，默认 `null`，`str`：字典路径或字典目录
- `candidates`，默认 `null`，`list`：候选词列表（优先于字典）
- `prefix`，默认 `''`，`str`：已知明文前缀
- `suffix`，默认 `''`，`str`：已知明文后缀
- `hash_name`，默认 `'md5'`，`str`，可选 `md5` / `sha1` / `sha256` / `sha512` / `sha3_256`：哈希算法
- `max_seconds`，默认 `600.0`，`float`，范围 1~7200：最长运行秒数（到点停止）
- 返回：dict：{status, result, error, finished, events, hash_name, hash}
- 备注：worker_num × thread_num 会放大 CPU 占用，注意宿主负载。

**`hash_length`**（lib.md5_crash）—— 返回指定哈希算法的十六进制摘要长度。

- `hash_name`，默认 `'md5'`，`str`：哈希算法名
- 返回：int：摘要长度

</details>

### cn_llm —— 大模型：对话 / 向量 / OCR / 翻译

OpenAI 兼容接口：模型列表、对话补全、文本向量、图片 OCR；中英互译。地址与模型默认读 config.json 的 llm 节。

> base_url / model / api_key 留空即用配置值；请求里传值只对本次调用生效，不会写回配置文件。

| op | 参数（`*` = 必填） | 返回 | 风险 |
| --- | --- | --- | --- |
| `list_models` | `base_url`, `timeout`, `api_key`, `headers` | list[str]：模型 id 列表 | `network` |
| `chat` | `base_url`, `model`, `messages*`, `timeout`, `api_key`, `headers`, `temperature` | str：模型回复文本 | `network` |
| `embed` | `base_url`, `model`, `text*`, `timeout`, `api_key`, `headers` | list[float]：向量 | `network` |
| `ocr_image` | `base_url`, `model`, `image_path*`, `prompt`, `timeout`, `api_key`, `headers` | str：识别出的文本 | `network` |
| `translate` | `data*`, `base_url`, `model`, `timeout`, `api_key`, `system_prompt_zh`, `system_prompt_en`, `headers` | str：译文 | `network` |
| `detect_language` | `text*` | str：语言标识 | `safe` |
| `target_language` | `text*` | str：目标语言标识 | `safe` |

<details><summary>参数详情</summary>

**`list_models`**（lib.llm_codec）—— 调用 ``GET /models`` 获取服务端可用模型 id 列表（OpenAI 兼容）。

- `base_url`，默认 `''`，`str`：服务地址，如 ``http://localhost:11434/v1``；留空用配置
- `timeout`，默认 `0.0`，`float`，范围 0~+∞：超时秒数；0 表示用配置值
- `api_key`，默认 `''`，`str`：API Key；留空用配置
- `headers`，默认 `''`，`str`：自定义请求头，多行 ``Key: Value``
- 返回：list[str]：模型 id 列表

**`chat`**（lib.llm_codec）—— 调 ``POST /chat/completions`` 做一次对话补全。

- `base_url`，默认 `''`，`str`：服务地址；留空用配置
- `model`，默认 `''`，`str`：模型名；留空用配置 llm.model
- `messages`，**必填**，`any`：消息数组，如 [{"role":"user","content":"hi"}]
- `timeout`，默认 `0.0`，`float`，范围 0~+∞：超时秒数；0 表示用配置值
- `api_key`，默认 `''`，`str`：API Key；留空用配置
- `headers`，默认 `''`，`str`：自定义请求头，多行 ``Key: Value``
- `temperature`，默认 `0.0`，`float`，范围 0~2：采样温度
- 返回：str：模型回复文本

**`embed`**（lib.llm_codec）—— 调 ``POST /embeddings`` 计算文本向量。

- `base_url`，默认 `''`，`str`：服务地址；留空用配置
- `model`，默认 `''`，`str`：嵌入模型名；留空用配置 llm.embedding_model
- `text`，**必填**，`str`：待嵌入文本
- `timeout`，默认 `0.0`，`float`，范围 0~+∞：超时秒数；0 表示用配置值
- `api_key`，默认 `''`，`str`：API Key；留空用配置
- `headers`，默认 `''`，`str`：自定义请求头，多行 ``Key: Value``
- 返回：list[float]：向量

**`ocr_image`**（lib.llm_codec）—— 多模态 OCR：把图片交给视觉模型识别文字。

- `base_url`，默认 `''`，`str`：服务地址；留空用配置
- `model`，默认 `''`，`str`：OCR / 多模态模型名；留空用配置
- `image_path`，**必填**，`str`：图片路径（相对项目根或绝对）
- `prompt`，默认 `''`，`str`：识别提示词；留空用内置提示
- `timeout`，默认 `0.0`，`float`，范围 0~+∞：超时秒数；0 表示用配置值
- `api_key`，默认 `''`，`str`：API Key；留空用配置
- `headers`，默认 `''`，`str`：自定义请求头，多行 ``Key: Value``
- 返回：str：识别出的文本

**`translate`**（lib.translate_codec）—— 中英互译（自动判断方向，走 OpenAI 兼容接口）。

- `data`，**必填**，`str`：待翻译文本
- `base_url`，默认 `''`，`str`：服务地址；留空用配置
- `model`，默认 `''`，`str`：对话模型名；留空用配置 llm.model
- `timeout`，默认 `0.0`，`float`，范围 0~+∞：超时秒数；0 表示用配置值
- `api_key`，默认 `''`，`str`：API Key；留空用配置
- `system_prompt_zh`，默认 `''`，`str`：英译中时的系统提示词；留空用配置
- `system_prompt_en`，默认 `''`，`str`：中译英时的系统提示词；留空用配置
- `headers`，默认 `''`，`str`：自定义请求头，多行 ``Key: Value``
- 返回：str：译文

**`detect_language`**（lib.translate_codec）—— 判断文本语言（zh / en / other）。

- `text`，**必填**，`str`：文本
- 返回：str：语言标识

**`target_language`**（lib.translate_codec）—— 判断译文目标语言：中文输入译英，其余译中。

- `text`，**必填**，`str`：文本
- 返回：str：目标语言标识

</details>

### cn_misc —— 杂项：番茄钟 / 代理池 / 局域网共享客户端

番茄钟状态机（开始 / 暂停 / 继续 / 跳过 / 重置 / 查询）；全局代理池状态与拉取验证；局域网文件共享的客户端能力。

> 番茄钟是**进程级单例**，多次调用共享同一个状态机。共享服务端（ShareServer）不在本服务里托管，只提供客户端调用。键盘模拟（key_simulator）属于桌面交互能力，未暴露。

| op | 参数（`*` = 必填） | 返回 | 风险 |
| --- | --- | --- | --- |
| `pomodoro_start` | `work_minutes`, `short_rest_minutes`, `long_rest_minutes`, `long_every` | dict：当前阶段 / 剩余 / 进度 / 完成数 | `safe` |
| `pomodoro_pause` | — | dict：当前状态 | `safe` |
| `pomodoro_resume` | — | dict：当前状态 | `safe` |
| `pomodoro_reset` | — | dict：当前状态 | `safe` |
| `pomodoro_skip` | — | dict：当前状态 + skipped_phase | `safe` |
| `pomodoro_status` | — | dict：阶段 / 剩余秒数 / 进度 / 完成数 / 下一阶段 | `safe` |
| `proxy_status` | — | dict：代理池状态 | `safe` |
| `proxy_get` | — | dict\|null：{protocol, host, port, ...} | `safe` |
| `proxy_fetch_and_verify` | `protocols` | dict：拉取 / 验证统计 | `network` |
| `check_available` | — | bool：是否有可用代理 | `network` |
| `is_enabled` | — | bool：是否启用 | `safe` |
| `should_use_proxy` | `tool_id` | bool：是否走代理 | `safe` |
| `config` | — | dict：配置 | `safe` |
| `normalize_base` | `host*` | str：规范化地址 | `safe` |
| `generate_password` | — | str：口令 | `safe` |
| `lan_ips` | — | list[str]：IP 列表 | `safe` |
| `client_channels` | `host*`, `timeout` | dict：{name, channels: [...]} | `network` |
| `client_join` | `host*`, `channel*`, `password*`, `timeout` | dict：{token, channel, ...} | `network` |
| `client_files` | `base*`, `token*`, `timeout` | list[dict]：文件清单 | `network` |
| `client_upload` | `base*`, `token*`, `path*`, `timeout` | dict：上传结果 | `network` |
| `client_download` | `base*`, `token*`, `filename*`, `dest_dir`, `timeout` | dict：{out, out_rel} | `write` |
| `client_leave` | `base*`, `token*`, `timeout` | null：无返回内容 | `network` |

<details><summary>参数详情</summary>

**`pomodoro_start`**（lib.pomodoro）—— 开始一轮番茄钟（可临时覆盖专注 / 休息时长）。

- `work_minutes`，默认 `null`，`int`，范围 1~180：专注分钟数；留空用配置值
- `short_rest_minutes`，默认 `null`，`int`，范围 1~+∞：短休息分钟数
- `long_rest_minutes`，默认 `null`，`int`，范围 1~+∞：长休息分钟数
- `long_every`，默认 `null`，`int`，范围 1~+∞：每 N 个专注后长休息
- 返回：dict：当前阶段 / 剩余 / 进度 / 完成数

**`pomodoro_pause`**（lib.pomodoro）—— 暂停番茄钟。

- 无参数
- 返回：dict：当前状态

**`pomodoro_resume`**（lib.pomodoro）—— 继续番茄钟。

- 无参数
- 返回：dict：当前状态

**`pomodoro_reset`**（lib.pomodoro）—— 重置番茄钟（回到第一个专注阶段）。

- 无参数
- 返回：dict：当前状态

**`pomodoro_skip`**（lib.pomodoro）—— 跳过当前阶段，进入下一阶段。

- 无参数
- 返回：dict：当前状态 + skipped_phase

**`pomodoro_status`**（lib.pomodoro）—— 查询番茄钟当前状态。

- 无参数
- 返回：dict：阶段 / 剩余秒数 / 进度 / 完成数 / 下一阶段

**`proxy_status`**（lib.proxy_pool）—— 返回全局代理池状态（启用 / 池内数量 / 统计）。

- 无参数
- 返回：dict：代理池状态

**`proxy_get`**（lib.proxy_pool）—— 从池中取下一个可用代理（不含手动兜底）。

- 无参数
- 返回：dict|null：{protocol, host, port, ...}

**`proxy_fetch_and_verify`**（lib.proxy_pool）—— 从免费源拉取代理并验证，结果装载进全局池（耗时 + 联网）。

- `protocols`，默认 `null`，`list`：限定协议（http / socks5）；留空用配置
- 返回：dict：拉取 / 验证统计

**`check_available`**（lib.proxy_pool）—— 使用前检测：确认池内有可用代理（必要时触发拉取）。

- 无参数
- 返回：bool：是否有可用代理

**`is_enabled`**（lib.proxy_pool）—— 全局代理池是否启用。

- 无参数
- 返回：bool：是否启用

**`should_use_proxy`**（lib.proxy_pool）—— 判断某个工具是否应走全局代理。

- `tool_id`，默认 `null`，`str`：工具 id；留空表示默认策略
- 返回：bool：是否走代理

**`config`**（lib.proxy_pool）—— 返回当前代理池配置副本。

- 无参数
- 返回：dict：配置

**`normalize_base`**（lib.lan_share）—— 规范化共享服务地址（``ip:port`` -> ``http://ip:port``）。

- `host`，**必填**，`str`：主机，如 ``192.168.1.5:8517``
- 返回：str：规范化地址

**`generate_password`**（lib.lan_share）—— 生成 4 位数字频道口令。

- 无参数
- 返回：str：口令

**`lan_ips`**（lib.lan_share）—— 枚举本机局域网 IPv4 地址。

- 无参数
- 返回：list[str]：IP 列表

**`client_channels`**（lib.lan_share）—— 获取共享服务的频道列表。

- `host`，**必填**，`str`：共享服务地址（ip:port）
- `timeout`，默认 `5.0`，`float`，范围 1~+∞：超时（秒）
- 返回：dict：{name, channels: [...]}

**`client_join`**（lib.lan_share）—— 加入频道（校验 4 位口令，成功返回 token）。

- `host`，**必填**，`str`：共享服务地址
- `channel`，**必填**，`str`：频道名
- `password`，**必填**，`str`：4 位频道口令
- `timeout`，默认 `10.0`，`float`，范围 1~+∞：超时（秒）
- 返回：dict：{token, channel, ...}

**`client_files`**（lib.lan_share）—— 获取频道内文件清单（按上传时间倒序）。

- `base`，**必填**，`str`：服务地址
- `token`，**必填**，`str`：join 得到的 token
- `timeout`，默认 `15.0`，`float`，范围 1~+∞：超时（秒）
- 返回：list[dict]：文件清单

**`client_upload`**（lib.lan_share）—— 上传本地文件到频道。

- `base`，**必填**，`str`：服务地址
- `token`，**必填**，`str`：join 得到的 token
- `path`，**必填**，`str`：本地文件路径（相对项目根或绝对）
- `timeout`，默认 `3600.0`，`float`，范围 1~+∞：超时（秒）
- 返回：dict：上传结果

**`client_download`**（lib.lan_share）—— 从频道下载文件到本地目录（自动改名防覆盖）。

- `base`，**必填**，`str`：服务地址
- `token`，**必填**，`str`：join 得到的 token
- `filename`，**必填**，`str`：频道内文件名
- `dest_dir`，默认 `''`，`str`：本地目标目录；留空写 output/lanshare
- `timeout`，默认 `3600.0`，`float`，范围 1~+∞：超时（秒）
- 返回：dict：{out, out_rel}

**`client_leave`**（lib.lan_share）—— 离开频道（释放会话）。

- `base`，**必填**，`str`：服务地址
- `token`，**必填**，`str`：join 得到的 token
- `timeout`，默认 `5.0`，`float`，范围 1~+∞：超时（秒）
- 返回：null：无返回内容

</details>

### cn_plugin —— 第三方插件：发现 / 体检 / 环境检测 / 受控直调

统一管理 mcp/plugins 下的第三方工具：列出已发现插件、查看详情、跑版本体检、检测运行环境（打包版独立解释器等），以及以「参数数组 + 隔离 stdin + 超时上限」的方式受控直调。

> 插件调用永不经过 shell；stdin 默认 DEVNULL（stdio 模式下父进程 stdin 是 MCP 协议通道）。专用适配工具组：cn_sqlmap / cn_trufflehog / cn_oneforall / cn_flaskcookie / cn_filesensor。

| op | 参数（`*` = 必填） | 返回 | 风险 |
| --- | --- | --- | --- |
| `list` | `with_ops` | dict：{count, available, missing, plugins: [...], manifest_errors} | `safe` |
| `info` | `plugin*` | dict：插件元数据 + version_cmd + 专用工具组 | `safe` |
| `check` | `plugin` | dict：{ok, results: [{plugin, ok, returncode, version_line}]} | `safe` |
| `doctor` | — | dict：{mode, python_runtime, plugins_root, available, missing, plugins, verdict, install: [...]} | `safe` |
| `run` | `plugin*`, `args*`, `max_seconds`, `stdin`, `cwd` | dict：{success, command, returncode, duration_ms, stdout_tail, stderr_tail, timed_out, json_lines} | `intrusive` |

<details><summary>参数详情</summary>

**`list`**（cn_plugin）—— 列出 mcp/plugins 下发现的所有第三方插件（名称 / 类型 / 入口 / 可用性 / 已适配 op）。

- `with_ops`，默认 `True`，`bool`：是否包含为每个插件适配的 op 列表与详细元数据
- 返回：dict：{count, available, missing, plugins: [...], manifest_errors}

**`info`**（cn_plugin）—— 查看单个插件的详细信息与推荐调用方式。

- `plugin`，**必填**，`str`：插件 key，如 trufflehog / sqlmap
- 返回：dict：插件元数据 + version_cmd + 专用工具组

**`check`**（cn_plugin）—— 插件体检：逐个跑版本探测命令，确认可执行、打印版本行。plugin 留空检查全部。

- `plugin`，默认 `''`，`str`：只检查指定插件；留空检查全部
- 返回：dict：{ok, results: [{plugin, ok, returncode, version_line}]}
- 备注：慢工具（sqlmap 首次启动约 1~3s）会给每个插件 60s 上限。

**`doctor`**（cn_plugin）—— 环境检测：当前运行模式（dev / 打包）下插件体系可用性 —— 插件清单、独立 Python 运行时是否部署、插件目录位置与缺失补装指引。

- 无参数
- 返回：dict：{mode, python_runtime, plugins_root, available, missing, plugins, verdict, install: [...]}
- 备注：不执行任何插件命令（纯静态检测）；运行体检请用 op="check"。打包精简版默认不带插件：verdict 会给出补装方法。

**`run`**（cn_plugin）—— 受控直调插件：参数以数组透传（绝不经过 shell），stdin 默认隔离。

- `plugin`，**必填**，`str`：插件 key
- `args`，**必填**，`list`：参数数组，如 ["filesystem", "D:/tmp", "--json"]；也接受按空白/换行分隔的字符串
- `max_seconds`，默认 `300`，`int`，范围 1~3600：最长运行秒数
- `stdin`，默认 `''`，`str`：写入插件 stdin 的文本；留空则接 DEVNULL（防止吞掉 MCP 协议帧）
- `cwd`，默认 `''`，`str`：工作目录；相对路径基于插件目录，默认插件目录
- 返回：dict：{success, command, returncode, duration_ms, stdout_tail, stderr_tail, timed_out, json_lines}
- 备注：直调不做参数语义校验，适合已适配插件之外的新工具；仅可用于已授权目标。

</details>

### cn_sqlmap —— sqlmap：SQL 注入检测与取数

sqlmap 二次封装：注入探测（scan）、逐级取数（dbs / tables / columns / dump）、tamper 脚本枚举、版本查询。每次调用独立输出目录，结果自动解析。

> 默认只做检测不取数；先用 scan 确认可注入，再逐级 dbs → tables → columns → dump。导出文件落在 output/sqlmap/<目标>-<时间>/。仅用于已授权目标。

| op | 参数（`*` = 必填） | 返回 | 风险 |
| --- | --- | --- | --- |
| `version` | — | dict：{success, version, banner_tail} | `safe` |
| `scan` | `url*`, `level`, `risk`, `dbms`, `technique`, `tamper`, `threads`, `http_timeout`, `retries`, `delay`, `data`, `cookie`, `headers`, `proxy`, `random_agent`, `flush_session`, `parse_errors`, `extra_args`, `max_seconds` | dict：{success, vulnerable, dbms, payload, stdout_tail, output_dir, returncode} | `intrusive` |
| `dbs` | `url*`, `level`, `risk`, `dbms`, `tamper`, `cookie`, `data`, `proxy`, `extra_args`, `max_seconds` | dict：{success, databases: [...], stdout_tail, output_dir} | `intrusive` |
| `tables` | `url*`, `db*`, `level`, `risk`, `tamper`, `cookie`, `proxy`, `extra_args`, `max_seconds` | dict：{success, database, tables: [...], stdout_tail, output_dir} | `intrusive` |
| `columns` | `url*`, `db*`, `table*`, `level`, `risk`, `tamper`, `cookie`, `proxy`, `extra_args`, `max_seconds` | dict：{success, database, tables/columns, stdout_tail, output_dir} | `intrusive` |
| `dump` | `url*`, `db*`, `table`, `columns`, `dump_format`, `tamper`, `cookie`, `proxy`, `extra_args`, `max_seconds` | dict：{success, stdout_tail, csv_files, output_dir} | `intrusive` |
| `tamper_list` | `keyword` | dict：{count, scripts, tamper_dir, usage} | `read` |

<details><summary>参数详情</summary>

**`version`**（plugins/sqlmap-master）—— 查看 sqlmap 版本。

- 无参数
- 返回：dict：{success, version, banner_tail}

**`scan`**（plugins/sqlmap-master）—— SQL 注入探测（等价 sqlmap -u URL --batch）：默认只做检测，不取数据。

- `url`，**必填**，`str`：目标 URL（含参数才可能注入）
- `level`，默认 `null`，`int`，范围 1~5：探测等级 1~5（越大越全也越慢）
- `risk`，默认 `null`，`int`，范围 1~3：风险等级 1~3（3 会尝试 OR 型 payload）
- `dbms`，默认 `''`，`str`：指定后端数据库（mysql / mssql / postgresql / oracle …）
- `technique`，默认 `''`，`str`，可选 `B` / `E` / `U` / `S` / `T` / `Q`：注入技术：B/E/U/S/T/Q 可组合，如 BEU
- `tamper`，默认 `''`，`str`：tamper 脚本（逗号分隔），先用 tamper_list 查名字
- `threads`，默认 `null`，`int`，范围 1~10：并发线程 1~10
- `http_timeout`，默认 `null`，`int`，范围 1~+∞：单请求超时（秒）
- `retries`，默认 `null`，`int`，范围 0~+∞：请求重试次数
- `delay`，默认 `0.0`，`float`，范围 0~+∞：每次请求间隔（秒）
- `data`，默认 `''`，`str`：POST 数据（如 ``id=1&name=x``）
- `cookie`，默认 `''`，`str`：Cookie 头
- `headers`，默认 `''`，`str`：额外请求头，多个用换行分隔
- `proxy`，默认 `''`，`str`：代理地址，如 socks5://127.0.0.1:1080
- `random_agent`，默认 `False`，`bool`：随机 User-Agent
- `flush_session`，默认 `False`，`bool`：清空历史会话后重扫
- `parse_errors`，默认 `False`，`bool`：解析并显示 DBMS 报错
- `extra_args`，默认 `null`，`list`：追加原生参数（高级用法）
- `max_seconds`，默认 `300`，`int`，范围 5~3600：最长运行秒数
- 返回：dict：{success, vulnerable, dbms, payload, stdout_tail, output_dir, returncode}
- 备注：仅可用于已授权目标；默认只检测，取数请用 dbs/tables/columns/dump。

**`dbs`**（plugins/sqlmap-master）—— 枚举数据库名（sqlmap --dbs）。

- `url`，**必填**，`str`：目标 URL
- `level`，默认 `null`，`int`，范围 1~5：探测等级 1~5
- `risk`，默认 `null`，`int`，范围 1~3：风险等级 1~3
- `dbms`，默认 `''`，`str`：指定后端数据库
- `tamper`，默认 `''`，`str`：tamper 脚本
- `cookie`，默认 `''`，`str`：Cookie 头
- `data`，默认 `''`，`str`：POST 数据
- `proxy`，默认 `''`，`str`：代理地址
- `extra_args`，默认 `null`，`list`：追加原生参数
- `max_seconds`，默认 `300`，`int`，范围 5~3600：最长运行秒数
- 返回：dict：{success, databases: [...], stdout_tail, output_dir}

**`tables`**（plugins/sqlmap-master）—— 枚举指定库的表（sqlmap -D db --tables）。

- `url`，**必填**，`str`：目标 URL
- `db`，**必填**，`str`：数据库名
- `level`，默认 `null`，`int`，范围 1~5：探测等级 1~5
- `risk`，默认 `null`，`int`，范围 1~3：风险等级 1~3
- `tamper`，默认 `''`，`str`：tamper 脚本
- `cookie`，默认 `''`，`str`：Cookie 头
- `proxy`，默认 `''`，`str`：代理地址
- `extra_args`，默认 `null`，`list`：追加原生参数
- `max_seconds`，默认 `300`，`int`，范围 5~3600：最长运行秒数
- 返回：dict：{success, database, tables: [...], stdout_tail, output_dir}

**`columns`**（plugins/sqlmap-master）—— 枚举指定表的列（sqlmap -D db -T table --columns）。

- `url`，**必填**，`str`：目标 URL
- `db`，**必填**，`str`：数据库名
- `table`，**必填**，`str`：表名
- `level`，默认 `null`，`int`，范围 1~5：探测等级 1~5
- `risk`，默认 `null`，`int`，范围 1~3：风险等级 1~3
- `tamper`，默认 `''`，`str`：tamper 脚本
- `cookie`，默认 `''`，`str`：Cookie 头
- `proxy`，默认 `''`，`str`：代理地址
- `extra_args`，默认 `null`，`list`：追加原生参数
- `max_seconds`，默认 `300`，`int`，范围 5~3600：最长运行秒数
- 返回：dict：{success, database, tables/columns, stdout_tail, output_dir}

**`dump`**（plugins/sqlmap-master）—— 导出数据（sqlmap --dump）；表级需给 table，列级再给 columns。

- `url`，**必填**，`str`：目标 URL
- `db`，**必填**，`str`：数据库名
- `table`，默认 `''`，`str`：表名（留空导整库）
- `columns`，默认 `''`，`str`：列名，逗号分隔（留空导整表）
- `dump_format`，默认 `'csv'`，`str`：导出格式（sqlmap 默认 CSV）
- `tamper`，默认 `''`，`str`：tamper 脚本
- `cookie`，默认 `''`，`str`：Cookie 头
- `proxy`，默认 `''`，`str`：代理地址
- `extra_args`，默认 `null`，`list`：追加原生参数
- `max_seconds`，默认 `600`，`int`，范围 5~3600：最长运行秒数
- 返回：dict：{success, stdout_tail, csv_files, output_dir}
- 备注：导出的 CSV 落在 output_dir 内，csv_files 列出相对路径。

**`tamper_list`**（plugins/sqlmap-master）—— 枚举 sqlmap 自带 tamper 脚本（本地文件，不联网、不启动 sqlmap）。

- `keyword`，默认 `''`，`str`：按名字过滤（小写子串匹配）
- 返回：dict：{count, scripts, tamper_dir, usage}

</details>

### cn_trufflehog —— TruffleHog：密钥 / 凭证泄露扫描

TruffleHog 二次封装：扫描 Git 仓库、本地目录、Docker 镜像中的密钥与凭证，NDJSON 结果已解析为结构化 findings（detector / verified / 位置）。

> 默认离线识别（--no-verification）更快；verify=true 会联网向各平台验证密钥真伪。只对已授权仓库 / 目录做扫描。

| op | 参数（`*` = 必填） | 返回 | 风险 |
| --- | --- | --- | --- |
| `version` | — | dict：{success, version} | `safe` |
| `scan_git` | `url*`, `verify`, `concurrency`, `results`, `max_findings`, `max_seconds`, `extra_args` | dict：{success, findings_count, verified_count, detectors, findings: [{detector, verified, raw, location}]} | `network` |
| `scan_filesystem` | `path*`, `verify`, `concurrency`, `results`, `max_findings`, `max_seconds`, `extra_args` | dict：{success, findings_count, detectors, findings} | `read` |
| `scan_docker` | `image*`, `verify`, `concurrency`, `results`, `max_findings`, `max_seconds`, `extra_args` | dict：{success, findings_count, detectors, findings} | `network` |

<details><summary>参数详情</summary>

**`version`**（plugins/trufflehog）—— 查看 TruffleHog 版本。

- 无参数
- 返回：dict：{success, version}

**`scan_git`**（plugins/trufflehog）—— 扫描 Git 仓库 / 远程地址中的密钥（trufflehog git）。

- `url`，**必填**，`str`：仓库地址，如 https://github.com/owner/repo 或本地路径
- `verify`，默认 `False`，`bool`：是否在线验证密钥（联网、更慢；默认关闭，只做离线识别）
- `concurrency`，默认 `null`，`int`，范围 1~64：并发 chunk 数（留空用工具默认）
- `results`，默认 `'verified,unverified,unknown'`，`str`：结果过滤：verified / unverified / unknown 逗号组合
- `max_findings`，默认 `50`，`int`，范围 1~500：最多返回多少条命中（影响上下文体积）
- `max_seconds`，默认 `300`，`int`，范围 5~3600：最长运行秒数
- `extra_args`，默认 `null`，`list`：追加原生参数（高级用法）
- 返回：dict：{success, findings_count, verified_count, detectors, findings: [{detector, verified, raw, location}]}
- 备注：默认离线识别（不验证）；需要验证可信度时传 verify=true。

**`scan_filesystem`**（plugins/trufflehog）—— 扫描本地目录中的密钥 / 凭证（trufflehog filesystem）。

- `path`，**必填**，`str`：目录或文件路径（相对项目根或绝对）
- `verify`，默认 `False`，`bool`：是否在线验证密钥（联网、更慢；默认关闭，只做离线识别）
- `concurrency`，默认 `null`，`int`，范围 1~64：并发 chunk 数（留空用工具默认）
- `results`，默认 `'verified,unverified,unknown'`，`str`：结果过滤：verified / unverified / unknown 逗号组合
- `max_findings`，默认 `50`，`int`，范围 1~500：最多返回多少条命中（影响上下文体积）
- `max_seconds`，默认 `300`，`int`，范围 5~3600：最长运行秒数
- `extra_args`，默认 `null`，`list`：追加原生参数（高级用法）
- 返回：dict：{success, findings_count, detectors, findings}
- 备注：纯本地扫描，适合先跑了 cn_scan/leak_scan 拿到源码后检查凭证。

**`scan_docker`**（plugins/trufflehog）—— 扫描本地 Docker 镜像层中的密钥（trufflehog docker）。

- `image`，**必填**，`str`：镜像名，如 nginx:latest
- `verify`，默认 `False`，`bool`：是否在线验证密钥（联网、更慢；默认关闭，只做离线识别）
- `concurrency`，默认 `null`，`int`，范围 1~64：并发 chunk 数（留空用工具默认）
- `results`，默认 `'verified,unverified,unknown'`，`str`：结果过滤：verified / unverified / unknown 逗号组合
- `max_findings`，默认 `50`，`int`，范围 1~500：最多返回多少条命中（影响上下文体积）
- `max_seconds`，默认 `300`，`int`，范围 5~3600：最长运行秒数
- `extra_args`，默认 `null`，`list`：追加原生参数（高级用法）
- 返回：dict：{success, findings_count, detectors, findings}

</details>

### cn_oneforall —— OneForAll：子域名收集

OneForAll 二次封装：跑子域名收集并自动解析导出结果（csv/json），支持存活/爆破/DNS/HTTP/端口/接管等开关，也能列历史结果。

> 默认带 15 分钟上限；爆破（brute=true）很慢，建议先关。结果落在 plugins/OneForAll/results/，run 会把记录解析成 subdomains。

| op | 参数（`*` = 必填） | 返回 | 风险 |
| --- | --- | --- | --- |
| `version` | — | dict：{success, version, banner_tail} | `safe` |
| `check` | — | dict：{success, stdout_tail} | `network` |
| `run` | `target*`, `alive`, `brute`, `dns`, `req`, `port`, `fmt`, `takeover`, `max_rows`, `max_seconds`, `extra_args` | dict：{success, subdomain_count, subdomains: [...], result_file_rel, stdout_tail} | `intrusive` |
| `list_results` | — | dict：{count, results_dir, files: [...]} | `read` |

<details><summary>参数详情</summary>

**`version`**（plugins/OneForAll）—— 查看 OneForAll 版本。

- 无参数
- 返回：dict：{success, version, banner_tail}

**`check`**（plugins/OneForAll）—— 联网检查 OneForAll 是否有新版本（离线会失败）。

- 无参数
- 返回：dict：{success, stdout_tail}

**`run`**（plugins/OneForAll）—— 执行子域名收集（oneforall.py --target <域名> ... run），结束后自动解析 results/ 下的导出文件。

- `target`，**必填**，`str`：目标域名，如 example.com
- `alive`，默认 `null`，`bool`：只保留存活子域名；留空用工具默认（不传该参数）
- `brute`，默认 `null`，`bool`：是否启用爆破；留空用工具默认。建议先关掉再按需开
- `dns`，默认 `null`，`bool`：是否做 DNS 解析；留空用工具默认
- `req`，默认 `null`，`bool`：是否做 HTTP 探活；留空用工具默认
- `port`，默认 `''`，`str`：端口探测规模：small / medium / large；留空不探测
- `fmt`，默认 `'csv'`，`str`，可选 `csv` / `json`：导出格式
- `takeover`，默认 `False`，`bool`：是否做子域名接管检测
- `max_rows`，默认 `100`，`int`，范围 1~1000：最多返回多少条子域名记录
- `max_seconds`，默认 `900`，`int`，范围 10~7200：最长运行秒数
- `extra_args`，默认 `null`，`list`：追加原生参数（高级用法）
- 返回：dict：{success, subdomain_count, subdomains: [...], result_file_rel, stdout_tail}
- 备注：完整收集可能跑很久（默认 15 分钟上限）；先关 brute 再开，结果文件在插件目录 results/ 下。

**`list_results`**（plugins/OneForAll）—— 列出 OneForAll 历史导出文件（本地，不联网）。

- 无参数
- 返回：dict：{count, results_dir, files: [...]}

</details>

### cn_flaskcookie —— Flask Session Cookie：解码 / 签发

Flask session cookie 的编解码封装：可只解 base64，也可用 SECRET_KEY 验签解出结构、或签出新的 cookie。插件在 Flask 3.x 下失效时自动原生回退。

> decode 不给 secret 只看载荷；给 secret 才会验签。encode 需要 SECRET_KEY，输出可直接当 Cookie 头用。

| op | 参数（`*` = 必填） | 返回 | 风险 |
| --- | --- | --- | --- |
| `version` | — | dict：{success, version, stdout_tail} | `safe` |
| `decode` | `cookie*`, `secret`, `max_seconds` | dict：{success, source, value, raw, cookie, secret_used} | `safe` |
| `encode` | `secret*`, `structure*`, `max_seconds` | dict：{success, source, cookie} | `safe` |

<details><summary>参数详情</summary>

**`version`**（plugins/flask-session-cookie-manager）—— 查看插件的帮助 / 版本信息。

- 无参数
- 返回：dict：{success, version, stdout_tail}

**`decode`**（plugins/flask-session-cookie-manager）—— 解码 Flask session cookie；给了 secret 会验签并解出真实结构。

- `cookie`，**必填**，`str`：session cookie 值（含签名段）
- `secret`，默认 `''`，`str`：Flask SECRET_KEY；留空则只解 base64 部分（不验签）
- `max_seconds`，默认 `60`，`int`，范围 2~300：最长运行秒数
- 返回：dict：{success, source, value, raw, cookie, secret_used}
- 备注：Flask 3.x 下插件 CLI 会报错，此时自动回退到 itsdangerous 原生实现（source=native）。

**`encode`**（plugins/flask-session-cookie-manager）—— 用 SECRET_KEY 签一个 Flask session cookie（伪造 / 测试用）。

- `secret`，**必填**，`str`：Flask SECRET_KEY
- `structure`，**必填**，`any`：session 内容：对象，或 JSON / Python 字面量字符串
- `max_seconds`，默认 `60`，`int`，范围 2~300：最长运行秒数
- 返回：dict：{success, source, cookie}
- 备注：签名算法与 Flask 3.x 一致（URLSafeTimedSerializer + TaggedJSONSerializer + hmac/sha1）；只用于已授权测试。

</details>

### cn_filesensor —— FileSensor：敏感文件探测

FileSensor 二次封装：爬目标站点并按爬取结果生成敏感文件探测向量（备份 / swp / 源码泄露等），结果解析成命中 URL 列表。

> 站点有自定义 404 页面时务必传 filter_404 正则，否则会大量误报。仅用于已授权目标。

| op | 参数（`*` = 必填） | 返回 | 风险 |
| --- | --- | --- | --- |
| `version` | — | dict：{success, version} | `safe` |
| `scan` | `url*`, `filter_404`, `save_output`, `max_seconds` | dict：{success, crawled_pages, sensitive_found, hits: [...], saved_file} | `intrusive` |

<details><summary>参数详情</summary>

**`version`**（plugins/FileSensor）—— 查看 FileSensor 版本（解析帮助横幅）。

- 无参数
- 返回：dict：{success, version}

**`scan`**（plugins/FileSensor）—— 对目标站点做敏感文件探测（爬取 + 向量扫描），返回命中 URL 列表。

- `url`，**必填**，`str`：目标 URL，如 https://example.com/
- `filter_404`，默认 `''`，`str`：用于识别「返回 200 的假 404 页面」的正则，如 ``404 File not Found``
- `save_output`，默认 `False`，`bool`：是否把结果另存到插件目录 output/
- `max_seconds`，默认 `600`，`int`，范围 10~3600：最长运行秒数
- 返回：dict：{success, crawled_pages, sensitive_found, hits: [...], saved_file}
- 备注：基于 Scrapy 爬虫，站点大时会跑很久；先用默认参数小范围试探。

</details>

## 4. 第三方插件（`mcp/plugins/`）

插件是独立的三方工具（完整源码 / 可执行文件），本项目只做**封装层**，不修改插件本身。统一遵守四条硬约定：

1. **不走 shell**：参数以数组逐个透传，天然免疫命令注入；
2. **隔离 stdin**：stdio 模式下父进程 stdin 是 MCP 协议通道，插件默认接 `DEVNULL`（sqlmap 会读 stdin 等回车，这一点尤其关键）；
3. **超时上限**：每个 op 都有 `max_seconds`，到点终止子进程；
4. **输出有界**：超长输出保留头尾并标记 `output_truncated`；结果稳定字段为 `success / returncode / duration_ms / stdout_tail / stderr_tail`。

| 插件 | key | 类型 | 专用工具组 | 说明 |
| --- | --- | --- | --- | --- |
| FileSensor | `filesensor` | python | `cn_filesensor` | 基于 Scrapy 的敏感文件探测（备份 / swp / 源码泄露等）。 |
| Flask Session Cookie Manager | `flaskcookie` | python | `cn_flaskcookie` | Flask session cookie 编解码；上游脚本与 Flask 3.x 不兼容，适配器在 CLI 报错时自动回退到 itsdangerous 原生实现。 |
| OneForAll | `oneforall` | python | `cn_oneforall` | 子域名收集；结果导出到插件目录 results/ 下（csv / json）。 |
| sqlmap | `sqlmap` | python | `cn_sqlmap` | SQL 注入检测；内部会读 stdin 等待回车，必须隔离 stdin（已处理）。 |
| TruffleHog | `trufflehog` | binary | `cn_trufflehog` | 密钥/凭证泄露扫描器；结果以 NDJSON 输出到 stdout，日志在 stderr。 |

通用入口：`cn_plugin`（`list` / `info` / `check` / `run`）。未做专用适配的新插件，直接 `cn_plugin(op="run", params={"plugin": "<key>", "args": [...]})` 调用。

### 4.1 新增插件

1. 把工具放进 `mcp/plugins/<目录>/`；
2. 想零代码接入 → 在目录里放 `plugin.json`：

```json
{
  "key": "mytool",
  "name": "MyTool",
  "kind": "python",
  "entry": "mytool.py",
  "version_cmd": ["--version"],
  "homepage": "https://example.com/mytool",
  "notes": "一句话说明"
}
```

3. 想要语义化 op → 在 `28zenro_mcp/pluginkit/` 加 `<插件>.py` 导出 `GROUP`，并把模块名加进该包的 `_MODULES`。

### 4.2 插件风险

插件多为主动探测 / 爆破类工具（sqlmap、OneForAll、FileSensor），风险等级在 `meta.risk` 中标为 `intrusive` / `network` / `long`，**仅可用于已授权目标**；TruffleHog 扫描结果里可能含真实密钥，注意外泄。

## 5. 未暴露的方法

以下 lib 能力**刻意**没有做成 MCP op，原因是它们依赖桌面 / 进程生命周期：

| 模块 | 未暴露内容 | 原因 |
| --- | --- | --- |
| `lib.key_simulator` | 全部 | 向当前焦点窗口注入键盘事件，属于桌面交互，远程调用无意义且有风险 |
| `lib.lan_share` | `ShareServer` / `ShareState` / `ShareRequestHandler` | 需要在本进程托管 HTTP 服务与文件目录，属于 GUI 生命周期；客户端能力（channels/join/files/upload/download/leave）已暴露 |
| 各模块 | `main(argv)` 入口 | 命令行入口，工具调用不需要 |
| `lib.web_fuzz` 等 | 图形化辅助（`to_text` 已暴露，`row` 类转换未暴露） | 面向界面表格的格式转换 |

## 6. 环境依赖与配置

- Python 3.10+（本项目在 3.12 上验证）；
- 必需：`mcp`（MCP SDK）、`requests`；
- 可选：`Pillow`（cn_image）、`PyYAML`（指纹规则）、`node`（JSFuck 解码）；
- 插件依赖：各插件自带 `requirements.txt`（sqlmap 纯标准库；OneForAll 需 `fire`/`tldextract` 等；FileSensor 需 `scrapy`；flaskcookie 需 `flask` + `itsdangerous`；TruffleHog 是独立 exe）；
- 配置：读取 `%APPDATA%/28zenro/config.json`（与 GUI/CLI 共享），**只读不写**；缺失时回退内置默认值；
- 代理池：启动时把 `proxy_pool` 节装载进 `lib.proxy_pool` 全局单例，网络类工具自动复用；
- 日志：全部写 stderr；stdio 传输下 stdout 只承载 MCP 协议帧。

## 7. 自检

```bash
python mcp/server.py --selftest     # 契约审计 + 冒烟用例（含插件体检）
python mcp/server.py --audit        # 只做契约 vs lib 签名审计
python mcp/server.py --list         # 打印工具与 op 清单
python mcp/server.py --gen-docs     # 重新生成本文件
python mcp/server.py --export mcp/docs/ops.json   # 导出机器可读契约
```

审计规则：op 声明的每个参数都必须存在于真实 lib 函数签名；lib 的必填参数必须有声明；`log` / `progress` / `stop` 例外。
