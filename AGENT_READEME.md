# 28zenro — Agent 调用手册

> 本文档面向 **AI Agent / 自动化脚本**，描述 28zenro 各工具的**调用方法、参数、返回类型与适用场景**。
> 所有工具均为纯 Python 函数（位于 `lib/`），字符串进、结果出，不依赖任何 GUI。
> 也可通过命令行入口 `cli.py` 直接拉起（见文末「CLI 调度入口」）。

---

## 0. 通用约定（读代码前必看）

- **命名**：加解密函数成对出现 `xxx_encrypt(data)` / `xxx_decrypt(data)`；哈希为 `xxx_hex(data)`。
- **异常**：所有工具失败时抛各自的 `*Error(ValueError)` 子类（如 `CodecError`、`RsaError`、`JwtError`、`DnsToolError`），调用方统一 `try/except` 捕获即可。
- **输入**：文本类工具接收 `str`，内部会 `strip()`；空输入会抛错。
- **返回**：编解码/哈希/字符串工具返回 `str`；结构化工具（Web 信息收集、指纹、端口等）返回 `dict` / `list[dict]` 或 `@dataclass` 对象（可用 `dataclasses.asdict()` 序列化）。
- **日志**：耗时/网络工具普遍带 `log: Callable[[str], None]` 与 `stop: threading.Event` 参数，用于逐行回传进度与中断。
- **代理**：所有发 HTTP 请求的 Web 工具统一走 `lib.proxy_pool.make_session()`，勿自行 `requests.get`。

---

## 1. 密码学编解码（crypto）

### 1.1 Base 系列 — `lib/base_codec.py`

> GUI 侧已把 11 个独立 base 工具收拢成「baseX 工具」（`app/pages/basex_page.py`
> 标签页切换），注册表 id 为 `basex`；「密码 Fuzz」经 `lib/basex_fuzz.fuzz_basex`
> 显式参与。下方纯函数接口不变，仍可被 CLI / MCP / 其它模块直接调用。

| 函数 | 返回 | 说明 |
|---|---|---|
| `base64_encrypt/decrypt(data: str) -> str` | str | 标准 Base64 |
| `base64_urlsafe_encrypt/decrypt(data) -> str` | str | URL 安全（`-` `_`） |
| `base32_encrypt/decrypt(data) -> str` | str | RFC 4648 |
| `base16_encrypt/decrypt(data) -> str` | str | 十六进制（输出大写） |
| `base58_encrypt/decrypt(data) -> str` | str | Bitcoin 风格 |
| `base62_encrypt/decrypt(data) -> str` | str | 0-9a-zA-Z |
| `base85_encrypt/decrypt(data, variant="b85") -> str` | str | 支持 b85/a85 |
| `base91_encrypt/decrypt(data) -> str` | str | |
| `base92_encrypt/decrypt(data) -> str` | str | |
| `uuencode_encrypt/decrypt(data) -> str` | str | |
| `xxencode_encrypt/decrypt(data) -> str` | str | |

**场景**：未知编码的密文，尝试各种 Base 解码。

### 1.2 ROT 移位 — `lib/rot_codec.py`
| 函数 | 返回 |
|---|---|
| `rot13_encrypt/decrypt(data) -> str` | str |
| `rot47_encrypt/decrypt(data) -> str` | str |
| `rot_n(data, shift: int) -> str` | str（通用移位） |

**场景**：古典凯撒类移位。

### 1.3 字符加解密 — `lib/char_codec.py`
| 函数 | 返回 |
|---|---|
| `caesar_encrypt/decrypt(data, shift: int) -> str` | str |
| `pigpen_encrypt/decrypt(data) -> str` | str（猪圈符号 U+2340~） |

**场景**：凯撒密码（shift 0-25）、猪圈密码。

### 1.4 哈希 — `lib/hash_codec.py`

> GUI 侧已把 5 个独立哈希工具收拢成「哈希工具」（`app/pages/hash_page.py`
> 标签页切换），注册表 id 为 `hash_tool`。下方纯函数接口不变，仍可被
> CLI / MCP / 其它模块直接调用（哈希单向不可逆，不参与密码 Fuzz）。

| 函数 | 返回 |
|---|---|
| `md5_hex(data) -> str` | 32 位小写 |
| `sha1_hex(data) -> str` | 40 位 |
| `sha256_hex(data) -> str` | 64 位 |
| `sha512_hex(data) -> str` | 128 位 |
| `sha3_256_hex(data) -> str` | 64 位 |
| `hash_by_name(name, data) -> str` | 按名哈希 |

**场景**：单向摘要，不可逆。

### 1.5 国密 SM2/SM3/SM4 — `lib/gm_codec.py`（纯 Python，无第三方依赖）
| 函数 | 返回 | 说明 |
|---|---|---|
| `sm3_hash(data) -> bytes` | bytes | 摘要 |
| `sm3_hex(data) -> str` | str | 64 位十六进制 |
| `sm4_ecb_encrypt/decrypt(data, key, padding=True) -> bytes` | bytes | key 16 字节 |
| `sm4_cbc_encrypt/decrypt(data, key, iv, padding=True) -> bytes` | bytes | 需 16 字节 IV |
| `sm2_generate_keypair() -> tuple` | (私钥, 公钥) | |
| `sm2_public_from_private(private_key: str) -> str` | str | 私钥推公钥 |
| `sm2_encrypt(data, public_key, mode="C1C3C2") -> bytes` | bytes | mode 支持 C1C3C2/C1C2C3 |
| `sm2_decrypt(data, private_key, mode="C1C3C2") -> bytes` | bytes | |
| `sm2_sign(data, private_key, public_key="", ...) -> str` | str | 128 位 r\|\|s |
| `sm2_verify(data, signature, public_key, ...) -> bool` | bool | |
| `parse_hex(text) -> bytes` | bytes | 十六进制转字节 |

**场景**：国密算法，`data` 支持 UTF-8 文本或十六进制（配合 `parse_hex`）。

### 1.6 RSA / 大整数攻击 — `lib/rsa_attack.py`
| 函数 | 返回 | 说明 |
|---|---|---|
| `factor(n) -> list[int]` | list[int] | 综合分解（试除/Fermat/Pollard rho/p-1） |
| `factor_fermat(n) -> tuple[p, q] | None` | | 接近平方根时 |
| `factor_prho(n) -> list[int]` | | Pollard rho |
| `factor_pm1(n, bound=100000) -> int | None` | | p-1 |
| `rsa_recover_d(p, q, e) -> int` | int | 私钥 d |
| `rsa_private_key(p, q, e) -> str` | str | PEM 格式私钥 |
| `rsa_recover_pq_from_ed(n, e, d) -> tuple[p, q]` | | 由 ed 恢复 |
| `attack_common_modulus(c1, c2, e1, e2, n) -> int` | int | 共模攻击 |
| `attack_low_exponent(c, e, n) -> int` | int | 低指数 |
| `attack_wiener(n, e) -> int | None` | int | Wiener |
| `attack_hastad(ciphertexts, exponents, n) -> int` | int | 广播攻击 |
| `int_to_text(n) / text_to_int(text)` | str/int | 整数↔文本 |
| 基础：`gcd/lcm/modinv/powmod/crt/integer_nth_root/is_prime/next_prime` | | 工具函数 |

**场景**：CTF RSA 题——分解大整数、恢复私钥、常见攻击。

### 1.7 哈希长度扩展攻击 — `lib/hash_ext.py`
```python
hash_ext.length_extend(algo, original_hash, append, secret_len) -> dict
hash_ext.length_extend_full(algo, original_hash, original_data, append, secret_len) -> dict
```
- `algo`：`"md5"` / `"sha1"` / `"sha256"`
- `original_hash`：原始摘要 `H(secret || data)`（十六进制）
- `original_data`（仅 `_full`）：公开消息部分 `data`（`_full` 版能精确算 padding）
- `append`：要追加的数据（UTF-8）
- `secret_len`：secret 的字节长度（需已知或猜测）
- **返回 dict**：`{"new_hash", "new_message"（十六进制）, "new_message_raw"（bytes）}`

**场景**：`secret||data` 的 MAC 伪造（md5/sha1/sha256）。

---

## 2. 密码 Fuzz（一键试全部解密算法）

`lib/cipher_fuzz.py`：
```python
from lib import cipher_fuzz
result = cipher_fuzz.run(text, key="", offset=None, targets=..., log=None)
# -> dict: {"total_tools", "tried_tools", "hits": [{tool_id, tool, label, output, score, readable}], "skipped"}
```
- `readability(text) -> float`：可读性打分 0~1。
- `fuzz_decoder(fn)`：包装单向解码器参与 Fuzz。
- **场景**：拿到未知密文，一次性跑完所有可解密算法，按可读性排序。

---

## 3. 字符串工具

### 3.1 编码转换 — `lib/string_codec.py`
| 函数 | 返回 |
|---|---|
| `url_encode(data) / url_decode(data)` | str |
| `url_encode_full(data)` | str（含英文数字） |
| `str_to_ascii(data)` | str（十进制码点） |
| `ascii_to_str(data)` | str（支持 0x 十六进制） |
| `to_lower(data) / to_upper(data)` | str |
| `text_count(data, labels) -> str` | 统计报告 |
| `quoted_printable_encode/decode(data)` | str |
| `html_entity_encode/decode(data)` | str |
| `unicode_escape_encode/decode(data)` | str |
| `gbk_to_utf16(data) / utf16_to_gbk(data)` | str |

### 3.2 文本去重/统计 — `lib/text_dedup.py`
| 函数 | 返回 |
|---|---|
| `dedupe(data, unit="line", order="keep", ignore_case=False) -> str` | str |
| `dedupe_stats(data, unit="line", ignore_case=False, labels) -> str` | str |
| `split_units(text, unit) -> list[str]` | list |

### 3.3 文本对比 — `lib/text_diff.py`
| 函数 | 返回 |
|---|---|
| `compare(left, right, mode="char", ignore_case=False) -> DiffResult` | `DiffResult(equal, similarity, blocks, removed, added, ...)` |

### 3.4 JSON 工具 — `lib/json_tool.py`
| 函数 | 返回 |
|---|---|
| `loads_json(data) -> (obj, errors)` | 解析 + 重复键检测 |
| `format_json(data, indent=2) -> str` | 美化 |
| `minify_json(data) -> str` | 压缩 |
| `analyze_json(data, limit=500) -> str` | 结构报告 |
| `build_json(root, entries, indent=2) -> str` | 键值行构建 |
| `rows_from_json(data) -> (root, rows)` | 反解为行 |

### 3.5 esolang — `lib/esolang.py`
| 函数 | 返回 |
|---|---|
| `brainfuck_exec(program, input_text="") -> str` | str |
| `ook_exec(program, input_text="") -> str` | str |
| `jother_exec(program, input_text="") -> str` | str |
| `jsfuck_encode(js_code) -> str` | str |
| `jsfuck_decode(jsfuck_code) -> str` | str（需 Node.js） |

---

## 4. 进制互转 — `lib/number_base_codec.py`
| 函数 | 返回 |
|---|---|
| `convert(data, from_base, to_base, upper=True) -> str` | 2~16 进制任意互转 |
| `make_converter(from_base, to_base) -> fn` | 预生成转换器 |
| `bin_to_oct/dec/hex`, `oct_to_bin/dec/hex`, `dec_to_bin/oct/hex`, `hex_to_bin/oct/dec` | str |

**场景**：2/8/10/16 进制互转，支持 `0b/0o/0x` 前缀、内部分隔符、正负号。

---

## 5. JWT — `lib/jwt_codec.py`
| 函数 | 返回 |
|---|---|
| `parse(token) -> JwtInfo` | 解析（header/payload/signature） |
| `verify(token, key) -> bool` | 验签（HS/RS/ES/none） |
| `create(header, payload, key=None, algorithm="HS256") -> str` | 生成 |
| `resign(token, key=None, algorithm=None) -> str` | 重签 |
| `hs_bruteforce(token, candidates, log, stop) -> str | None` | HS 弱密钥爆破 |
| `alg_confusion_rs_to_hs(payload, public_key_pem, ...)` | 算法混淆 RS→HS |
| `inject_header(token, extra_header, key, ...)` | 注入 header |
| `b64url_encode/decode(data)` | base64url |
| `coerce_claim_value(text)` | 声明值智能类型识别 |

**场景**：JWT 解析/校验/伪造/爆破/算法混淆。

---

## 6. 文件与图片

### 6.1 文件 Hex — `lib/file_hex_codec.py`
| 函数 | 返回 |
|---|---|
| `file_to_hex(path, separator=None, prefix="") -> str` | str |
| `hex_to_file(text, out_path, separator=None)` | 写文件 |
| `bytes_to_hex(data, ...) -> str` | str |
| `hex_to_bytes(text, separator=None) -> bytes` | bytes |

### 6.2 图片 Base64 — `lib/image_codec.py`
| 函数 | 返回 |
|---|---|
| `image_to_base64(image_path, data_uri=False) -> str` | str |
| `base64_to_image(text, out_path) -> Path` | 落盘路径 |
| `decode_base64_image(text) -> (bytes, ext)` | |

### 6.3 可见水印 — `lib/watermark.py`
| 函数 | 返回 |
|---|---|
| `add_visible_watermark(carrier_path, watermark_text, output_path, position="bottom-right", font_size=30, color=(255,255,255,128), font_path=None) -> str` | 输出路径 |

### 6.4 LSB 隐写 — `lib/lsb.py`
| 函数 | 返回 |
|---|---|
| `embed(carrier_path, secret_data, output_path, channels="RGB", bit=0, offset=0, order="column", framing="marker") -> str` | 输出路径 |
| `extract(stego_path, output_path=None, channels="RGB", bit=0, offset=0, ...)` | 提取文本 |
| `detect_params(stego_path, ...)` | 自动探测参数 |
| `capacity(carrier_path, channels="RGB")` | 容量 |

---

## 7. 压缩包 — `lib/zip_cracker.py`
| 函数 | 返回 |
|---|---|
| `is_encrypted(zip_path) -> bool` | |
| `is_fake_encrypted(zip_path) -> bool` | 伪加密识别 |
| `fix_fake_encrypted(zip_path, out_path=None) -> str` | 修复路径 |
| `extract(zip_path, out_dir=None, password=None) -> list` | 解压 |
| `crc32_crack(crc, size, alphabet=...)` | CRC32 碰撞 |
| `small_crc_candidates(zip_path, max_size=6)` | 小文件 CRC 还原 |
| `class ZipCracker` | 字典爆破（`start/stop/poll_logs`） |

---

## 8. 翻译与 LLM — `lib/translate_codec.py` / `lib/llm_codec.py`
| 函数 | 返回 |
|---|---|
| `translate(data, base_url, model, timeout=120, api_key, ...) -> str` | 中英互译 |
| `detect_language(text) -> str` | 语种检测 |
| `llm_codec.chat(base_url, model, messages, ...) -> str` | 对话 |
| `llm_codec.embed(base_url, model, text, ...) -> list[float]` | 向量 |
| `llm_codec.ocr_image(base_url, model, image_path, ...) -> str` | OCR |
| `llm_codec.list_models(base_url, ...) -> list[str]` | 模型列表 |

---

## 9. Web 信息收集（网络工具，走代理池）

> 这些工具的网络请求统一走 `lib.proxy_pool.make_session()`；返回结构化 `dict`/`list[dict]`。

### 9.1 Web Fuzz — `lib/web_fuzz.py`
```python
web_fuzz.run(target, timeout=8, with_robots=False, with_sitemap=False,
             with_hostsearch=False, with_subdomain_brute=False, ...) -> dict
```
返回 `WebFuzzResult` 的 dict：`status/final_url/headers/security/cookies/title/meta/technologies/links/scripts/forms/comments/emails/phones/ips/subdomains/robots/sitemap/hostsearch/dns_brute`。
**场景**：抓全一个 URL 的主机信息合并报告。

### 9.2 JSFinder — `lib/jsfinder.py`
```python
jsfinder.run(url, cookie="", deep=False, timeout=5, max_links=50) -> (urls, subdomains)
```
**场景**：从页面 JS 提取 URL 与子域名。

### 9.3 指纹探测 — `lib/fingerprint.py`
```python
fingerprint.run(target, timeout=8, rules=None, log, stop) -> dict
# -> {"target","final_url","status","matches":[{name,product,vendor,version,match_type,...}],...}
fingerprint.load_rules(directories=None) -> list[dict]
```
**场景**：observer_ward 风格 Web 指纹识别。

### 9.4 DNS 解析 / 子域名爆破 — `lib/dns_tool.py`
```python
dns_tool.resolve_dns(host, use_proxy=False, timeout=8) -> {"host", "records":[{type,values,note}]}
dns_tool.brute_subdomains(domain, dict_path=None, interval=0.3, use_proxy=False) -> (list, note)
```
**场景**：A/AAAA/CNAME 解析、字典子域名爆破。

### 9.5 域名历史收录 — `lib/hostsearch.py`
```python
hostsearch.query_hostsearch(domain, timeout=8) -> {"domain","records":[{subdomain,ip}],"note"}
```

### 9.6 主机探针 — `lib/httpscan.py`
```python
httpscan.run(target, threads=10, timeout=5, https=False) -> list[dict]
# 每项 {"ip","status","server","title","final_url",...}
```
**场景**：CIDR 网段 Web 主机发现。

### 9.7 目录爆破 — `lib/dir_scan.py`
```python
dir_scan.scan(target, out_dir=None, dict_dir=None, threads=16, timeout=6,
              interval=30, headers="", log, on_hit, stop) -> dict
# -> DirScanResult.to_dict(): {"base","total","tested","hits":[{word,url,status,length,title}],...}
```

### 9.8 源码泄露 — `lib/leak_scan.py`
```python
leak_scan.run(target, out_dir, kinds=["git","svn","ds_store"], threads=8, timeout=8) -> list[dict]
# 每条 {"kind","url","summary","found","directory",...}
```

### 9.9 参数爆破 — `lib/param_fuzz.py`
```python
param_fuzz.run(target, method="GET", wordlist="small", ...) -> dict
# -> {"target","method","found_params":[...],"heuristic_params":[...],"total_requests",...}
```

### 9.10 端口爆破 — `lib/port_scan.py`
```python
port_scan.scan(host, ports, pool=None, threads=24, timeout=6, retries=3, ...) -> dict
# -> {"host","total","open","hits":[{port,service,state,label,ms,proxy}],...}
port_scan.parse_ports(text) -> list[int]
```

### 9.11 SSTI 子类枚举 — `lib/ssti_finder.py`
```python
ssti_finder.run(url, param, method="GET", data="", cookie="", headers="",
                proxy="", prefix=DEFAULT_PREFIX, timeout=15, enum_all=False) -> SSTIReport
# SSTIReport: probe_ok, hits:[RceHit(index,name,keys,payloads)], subclasses
```

### 9.12 微信凭证校验 — `lib/wechat_check.py`
```python
wechat_check.check_credential(appid, secret, timeout=15) -> CheckResult
wechat_check.check_many(pairs, timeout=15) -> list[CheckResult]
# CheckResult: appid, valid, access_token, expires_in, errcode, errmsg
```

### 9.13 多地 Ping — `lib/ping_probe.py`
```python
ping_probe.run_ping(host, base_url, api_id, api_key, dy, ...) -> PingReport
# PingReport: host, nodes:[{...}], error
```

### 9.14 MySQL 弱口令 — `lib/mysql_brute.py`
```python
mysql_brute.probe(host, port=3306, timeout=6) -> AuthResult   # 纯被动指纹
mysql_brute.brute(host, users, passwords, port=3306, ...) -> dict  # 内网爆破
mysql_brute.classify_target(host) -> str  # 内网/公网/域名
```

### 9.15 代理池 — `lib/proxy_pool.py`
```python
proxy_pool.load_config(cfg)      # 从 config.json 的 proxy_pool 节加载
proxy_pool.make_session(tool_id) -> requests.Session  # 创建走代理的会话
proxy_pool.is_enabled() -> bool
proxy_pool.get_proxies() -> dict | None
proxy_pool.fetch_and_verify(log) -> dict
```

### 9.16 HTTP 请求器 — `lib/http_requester.py`
类 Burp Repeater / Intruder 的请求发送器（**不抓包**，自己构造并发送请求）。

```python
spec = http_requester.RequestSpec(
    method="POST", url="https://h/api",
    query=[Entry("token", "{{payload}}")],   # 重复键 = 多条 Entry
    headers=[Entry("X-Sign", "{{payload}}")],
    body_kind="form",                         # none/form/json/text
    body_entries=[Entry("data", "{{payload}}")])
http_requester.run(spec, mode="const", const_value="aGVsbG8+")   # 发一次
http_requester.run(spec, mode="loop", attack="sniper",            # 循环模式
                    payloads=["p1", "p2"])
http_requester.compose(spec, ["p1", "p2"])   # 只组装报文，不发送
http_requester.plan(spec, mode="loop", attack="clusterbomb", ...)  # 只算请求数
```

- `mode`：`const`（常量，发一次）/ `loop`（循环）
- `attack`：`sniper` / `batteringram` / `pitchfork` / `clusterbomb`（语义同 Burp）
- 载荷位置：请求里写 `{{payload}}` 即被标记；一个都没写时，循环模式把每个
  启用的参数 / 请求头 / 表单字段的值各当作一个位置（隐式）
- **载荷按字面发送**：已经 Base64 / URL 编码的密文不会被 `requests` 二次
  转义（`+` 不会变 `%2B`）；非占位符文本只做最小 URL 安全化
- 返回 dict：`{mode, attack, total, done, responses:[{payloads, status, length, url, ...}]}`

### 9.17 密码学循环接口 — `lib/crypto_interface.py`
把项目里能正向计算的加密 / 编码工具收成「载荷生成器」，供请求器循环模式
把明文列表批量变成密文载荷。

```python
crypto_interface.list_ops()          # 全部生成器（含参数 schema）
crypto_interface.transform(["flag", "hi"], "crypto.base64").outputs
crypto_interface.transform(["abc"], "classic.caesar", {"shift": 3}).outputs
crypto_interface.transform(["x"], "gm.sm4_cbc", {"key": "...", "iv": "..."})
crypto_interface.transform_text("flag\nhi", "hash.md5")
```
运算失败不中断整批：失败项原样保留并记进 `CryptoResult.errors`。

### 9.18 攻击面测绘 — `lib/attack_surface.py`
把现有 Web 原子工具编排成一条 pipeline（复用各 lib 纯函数，不重复实现）：

```python
attack_surface.run(target, with_subdomain=True, with_port=False,
                   with_fingerprint=True, with_waf=True, with_dir=False,
                   with_leak=False, with_param=True, with_oss=True,
                   subdomain_dict=None, subdomain_interval=0.3, ports="",
                   threads=16, log, stop) -> dict
# -> {"target","url","steps":[{id,name,ok,note,result}...],
#     "summary":{...}, "elapsed":秒, "stopped":bool}
attack_surface.to_text(report) -> str
```
**场景**：一键全链路攻击面测绘，顺序为 子域名→端口→指纹→WAF→目录→源码泄露→参数→OSS 桶。

### 9.19 WAF 识别 — `lib/waf_detect.py`
```python
waf_detect.run(target, timeout=8, log, stop) -> dict
# -> {"target","normal_status","attack_results":[...],
#     "matches":[{name,bypass}], "blocked":bool}
```
**场景**：识别 Cloudflare / 宝塔 / 安全狗 / ModSecurity 等 WAF，附绕过建议。

### 9.20 OSS 桶探测 — `lib/oss_bucket.py`
```python
oss_bucket.run(buckets, domain="", timeout=8, log, stop) -> dict
# -> {"buckets":[{bucket,provider,exists,public_read,listable,status,note}...],
#     "hits":[...], "summary":{...}}
oss_bucket.derive_bucket_names(domain, extra="") -> list[str]
```
**场景**：检测阿里云 OSS / 腾讯 COS / AWS S3 桶的公开读 / 可列举 / 存在性。

### 9.21 弱口令检测 — `lib/weak_cred.py`
```python
weak_cred.brute(host, service, users, passwords, port=None, threads=8,
                timeout=6, log, on_hit, stop) -> dict
# service: "redis" / "ftp" / "ssh"（ssh 仅 banner 指纹，不爆破）
weak_cred.probe(host, service, port=None, timeout=6) -> AuthResult
weak_cred.try_redis / try_ftp / try_ssh(...) -> AuthResult
```
**场景**：Redis / FTP 弱口令爆破 + SSH banner 指纹（内网爆破、公网仅指纹，合规）。

### 9.22 网站图标抓取 — `lib/favicon_fetch.py`
```python
favicon_fetch.fetch_favicon(url, timeout=8, session=None, log=None) -> bytes
favicon_fetch.fetch_and_save_icon(url, directory, timeout=8, log=None) -> str
favicon_fetch.copy_icon_file(source, directory) -> str
favicon_fetch.normalize_url(url) -> str
favicon_fetch.sniff_extension(data, content_type="") -> str
```
依次解析页面 `<link rel="icon">`、站点根目录 `/favicon.ico`、公共 favicon
服务；只接受真实图片字节。`fetch_and_save_icon` 按内容哈希落盘去重。
**场景**：快捷访问页自动获取 / 刷新链接图标；也可单独给其它模块复用。

---

## 10. 效率 / 其他

### 10.1 番茄时钟 — `lib/pomodoro.py`
```python
p = pomodoro.Pomodoro(PomodoroConfig(work_minutes=25, ...))
p.start() / p.pause() / p.resume() / p.reset() / p.skip() / p.tick()
p.remaining / p.progress / p.phase / p.round_done
```

### 10.2 键盘模拟 — `lib/key_simulator.py`
```python
sim = key_simulator.KeySimulator(dry_run=False)
sim.start(text, rate, duration) -> Plan
sim.stop() / sim.wait()
key_simulator.build_plan(text, rate, duration) -> Plan  # 纯计划，不执行
```
**场景**：模拟物理键盘输入（Windows 扫描码）。

### 10.3 局域网传输 — `lib/lan_share.py`
```python
server = lan_share.ShareServer(service_name, port=0)
server.start(on_event) -> int  # 返回实际端口
server.stop()
server.state  # ShareState（频道/密码/会话管理）

# 客户端
lan_share.client_channels(host) -> dict
lan_share.client_join(host, channel, password) -> token
lan_share.client_upload(base, token, path)
lan_share.client_download(base, token, filename, dest_dir)
```

### 10.4 MD5/SHA 爆破 — `lib/md5_crash.py`
```python
cracker = md5_crash.Md5Cracker()
cracker.start(md5_value, min_len, max_len, worker_num, thread_num, charset, ...)
cracker.poll_logs() -> list   # 命中明文 / 进度
cracker.stop()
```
**场景**：已知哈希反推明文（枚举/字典/多进程）。

---

## 11. CLI 调度入口（`cli.py`）

> Agent 可直接用命令行拉起任何 Web 工具，无需导入 Python。

```bash
python cli.py list                          # 列出全部工具（标注 CLI 可用/仅 GUI）
python cli.py webfuzz <url> [--robots --sitemap --hostsearch --subdomain]
python cli.py jsfinder <url> [--deep --cookie C]
python cli.py fingerprint <url> [--rules-dir DIR]
python cli.py dns <host> [--proxy]
python cli.py subdomain <domain> [--dict PATH --interval N]
python cli.py hostsearch <domain>
python cli.py httpscan <cidr> [--threads N --https]
python cli.py dirscan <url> [--dict-dir DIR --threads N]
python cli.py leakscan <domain> [--kinds git svn ds_store]
python cli.py paramfuzz <url> [--method GET --wordlist small]
python cli.py portscan <host> [--ports 1-1024 --no-proxy]
python cli.py ssti <url> <param> [--cookie C]
python cli.py wechat <appid> <secret> [...]
python cli.py ping <host> [--api-id ID --api-key KEY]

# 通用选项
python cli.py ... --json                    # 输出 {ok, tool, result|error}
python cli.py ... --config <path>           # 指定 config.json
```

- **返回约定**：`--json` 输出 `{"ok": bool, "tool": str, "result": ...}` 或 `{"ok": false, "error": str}`；退出码 0=成功，非 0=失败（错误在 stderr）。
- **结果类型**：与对应 lib 函数返回值一致（dict/list/dataclass 已 `asdict` 序列化）。
- **代理**：CLI 与 GUI 共用 `config.json` 的代理池配置。

### 11.1 MCP Server（`mcp_server.py`）

> 工具调用型 Agent（Claude Desktop / Cursor 等）可把本文件注册为 MCP server，
> 直接以 tool call 形式调用，无需拼命令行。

```bash
python mcp_server.py                # stdio 传输，由宿主以子进程拉起
```

宿主配置（Claude Desktop `claude_desktop_config.json` / Cursor `.cursor/mcp.json`）：

```json
{
  "mcpServers": {
    "28zenro": {
      "command": "python",
      "args": ["D:/Code/pythonCode/CTFcrypto/mcp_server.py"]
    }
  }
}
```

- 依赖：`pip install mcp`（Python ≥ 3.10），无 GUI 依赖，复用 `lib.*` 与 `config.json` 代理池。
- 暴露的 tool：`webfuzz` `jsfinder` `fingerprint` `dns_resolve` `subdomain_brute` `hostsearch`
  `httpscan` `dirscan` `leakscan` `paramfuzz` `portscan` `ssti` `wechat_check`
  `ping_multi` `mysql_probe`（与 CLI 子命令一一对应）。
- 所有 tool 返回 JSON dict/list；进度日志走 stderr，不污染协议通道。
- 慢工具（`dirscan` / `portscan` / `paramfuzz`）建议用默认参数小范围试探。

---

## 12. 工具 id 索引（`app/registry.py` 的 `ToolSpec.id`）

| 分类 | 工具 id |
|---|---|
| Fuzz | `cipher_fuzz` |
| 编解码 | `rot13` `rot47` `basex` |
| 哈希 | `hash_tool` `md5_crash` `sha1_crash` `sha256_crash` `hash_ext` |
| 国密 | `gm` |
| RSA | `rsa_attack` |
| 进制 | `number_base` |
| 字符串 | `url_codec` `ascii_codec` `entity_codec` `esolang` `to_lower` `to_upper` `text_count` `text_diff` `text_dedup` `text_dedup_stats` `json_tool` |
| 字符 | `caesar` `pigpen` |
| JWT | `jwt_tool` |
| Web | `jsfinder` `web_fuzz` `fingerprint` `dns_tool` `hostsearch` `subdomain_brute` `param_fuzz` `httpscan` `leak_scan` `port_scan` `mysql_brute` `ping_probe` `wechat_check` `ssti_finder` `http_requester` `browser`（仅 GUI，QtWebEngine 内嵌浏览器，无 lib 纯函数） |
| Misc | `translate` `key_simulate` `watermark` `zip_crack` `file_hex` `pomodoro` `lan_share` |
| 快捷访问 | `quick_access`（仅 GUI，链接图标收藏夹，配置存 `config.json` 的 `quick_access` 节） |

> 通过 `app.registry.get_tool(tool_id)` 可取得 `ToolSpec`（含 `enc`/`dec` 纯函数、`params` 参数 schema、`fuzz` 参与方式）。
