# 指纹规则库（observer_ward / FingerprintHub 风格）

本目录存放「指纹探测」子工具使用的 Web 指纹规则（YAML 格式），规则语法与
社区工具 [observer_ward（侦查守卫）](https://github.com/emo-crab/observer_ward)
及其指纹库 [FingerprintHub](https://github.com/0x727/FingerprintHub) 兼容。

## 目录约定

- 每个 `.yaml` / `.yml` 文件是一条（或多条）指纹规则；
- 应用启动 / 探测时自动加载本目录全部规则；
- 用户也可在「指纹探测」页面通过「加载规则目录」按钮指定额外规则目录，
  覆盖 / 扩充内置规则。

## 规则结构

```yaml
id: thinkphp                    # 规则 ID（不支持中文）
info:
  name: ThinkPHP                # 组件显示名（支持中文）
  author: 28zenro
  tags: detect,tech,thinkphp    # 逗号分隔标签
  severity: info                # unknown/info/low/medium/high/critical
  metadata:
    product: thinkphp           # CPE 产品名（关联漏洞）
    vendor: thinkphp            # CPE 厂商名
    verified: true
http:
  - method: GET
    path: ['/']                 # 探针请求路径
    matchers:
      - type: word              # word / regex / favicon
        words: ['thinkphp_show_page_trace']
        part: body              # body / header
        case-insensitive: true
      - type: favicon
        hash: ['116323821']     # mmh3 十进制 或 32 位 md5 hex
```

## 支持的匹配器

| type | 说明 |
| --- | --- |
| `word` | 关键词匹配，`part` 选 `body` / `header`，`case-insensitive` 忽略大小写，`condition: and` 时需全部命中 |
| `regex` | 正则匹配（`part` 同上），建议配合 `extractors` 提取版本号 |
| `favicon` | favicon 哈希匹配，`hash` 支持 mmh3（十进制）与 md5（32 位 hex） |

## 版本提取（extractors）

规则顶层或 `info.metadata` 里可用 `$1` / `$2` 等占位符引用正则捕获组：

```yaml
matchers:
  - type: regex
    regex: ['(?i)server:\s*nginx(?:/([\d.]+))?']
    part: header
extractors:
  - name: version
    type: regex
    regex: ['(?i)server:\s*nginx(?:/([\d.]+))?']
```

命中后 `$1` 会被替换为实际版本号，结果显示为 `version: 1.24.0`。

## 说明

- 目前只实现 `http` 探针（word / regex / favicon），不支持 `tcp` 服务指纹；
- 完整规则规范见 [FingerprintHub 规则说明](https://0x727.github.io/FingerprintHub/)。
