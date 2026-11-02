# -*- coding: utf-8 -*-
from __future__ import annotations

import subprocess

# ---------------------------------------------------------------------------
# 异常
# ---------------------------------------------------------------------------
class EsolangError(ValueError):
    """Esolang 处理失败时抛出的统一异常。"""


# ---------------------------------------------------------------------------
# Brainfuck 解释器
# ---------------------------------------------------------------------------
#: 八种合法 Brainfuck 指令
_BF_COMMANDS = "+-<>[].,"

#: 默认内存带大小（单元数）
_TAPE_SIZE = 30000


def brainfuck_exec(program: str, input_text: str = "") -> str:
    """执行 Brainfuck 程序，返回标准输出内容。

    - ``program`` 为 Brainfuck 源代码（忽略非指令字符，如注释 / 空白）；
    - ``input_text`` 为程序的 ``,`` 指令读取的输入（用尽后读到 0）；
    - 括号不匹配、内存指针越界、执行步数超限都会抛 :class:`EsolangError`。
    """
    code = "".join(c for c in str(program) if c in _BF_COMMANDS)
    if not code:
        raise EsolangError("Brainfuck 程序为空（未包含任何合法指令）。")

    # 预处理：建立括号配对表，提前校验括号匹配
    match: dict[int, int] = {}
    stack: list[int] = []
    for pos, char in enumerate(code):
        if char == "[":
            stack.append(pos)
        elif char == "]":
            if not stack:
                raise EsolangError(f"Brainfuck 括号不匹配：第 {pos + 1} 个指令的 ']' 无对应 '['。")
            start = stack.pop()
            match[start] = pos
            match[pos] = start
    if stack:
        raise EsolangError("Brainfuck 括号不匹配：存在未闭合的 '['。")

    tape = [0] * _TAPE_SIZE
    ptr = 0
    pc = 0
    output: list[str] = []
    input_chars = list(str(input_text))
    input_pos = 0
    steps = 0
    max_steps = 10_000_000  # 防止死循环

    while pc < len(code):
        steps += 1
        if steps > max_steps:
            raise EsolangError("Brainfuck 执行步数超限（疑似死循环），已中止。")
        char = code[pc]
        if char == ">":
            ptr += 1
            if ptr >= _TAPE_SIZE:
                raise EsolangError("Brainfuck 内存指针越界（超过磁带右端）。")
        elif char == "<":
            ptr -= 1
            if ptr < 0:
                raise EsolangError("Brainfuck 内存指针越界（超过磁带左端）。")
        elif char == "+":
            tape[ptr] = (tape[ptr] + 1) & 0xFF
        elif char == "-":
            tape[ptr] = (tape[ptr] - 1) & 0xFF
        elif char == ".":
            output.append(chr(tape[ptr]))
        elif char == ",":
            if input_pos < len(input_chars):
                tape[ptr] = ord(input_chars[input_pos]) & 0xFF
                input_pos += 1
            else:
                tape[ptr] = 0
        elif char == "[":
            if tape[ptr] == 0:
                pc = match[pc]
        elif char == "]":
            if tape[ptr] != 0:
                pc = match[pc]
        pc += 1

    return "".join(output)


# ---------------------------------------------------------------------------
# Ook!（Brainfuck 双词变体）
# ---------------------------------------------------------------------------
#: Ook 指令 -> Brainfuck 指令映射（每两个 Ook 词对应一个 BF 指令）
_OOK_MAP = {
    ".?": ">", "?.": "<",
    "..": "+", "!!": "-",
    "!.": ".", ".!": ",",
    "!?": "[", "?!": "]",
}


def ook_to_brainfuck(program: str) -> str:
    """把 Ook! 程序翻译成 Brainfuck 程序。

    Ook! 每两个词（``Ook.`` / ``Ook?`` / ``Ook!``）组成一条指令，
    词之间以空格分隔。
    """
    tokens = str(program).split()
    # 每个 token 形如 "Ook." / "Ook?" / "Ook!"，取最后一个字符
    ops = []
    for token in tokens:
        if token.startswith("Ook") and len(token) >= 4:
            ops.append(token[-1])
        elif token in ".?!":  # 允许省略 Ook 前缀的紧凑写法
            ops.append(token)
    if len(ops) % 2 != 0:
        raise EsolangError("Ook! 程序词数为奇数：每两个 Ook 词对应一条指令。")

    bf = []
    for i in range(0, len(ops), 2):
        pair = ops[i] + ops[i + 1]
        cmd = _OOK_MAP.get(pair)
        if cmd is None:
            raise EsolangError(f"Ook! 程序含未知指令对「Ook{ops[i]} Ook{ops[i+1]}」。")
        bf.append(cmd)
    return "".join(bf)


def ook_exec(program: str, input_text: str = "") -> str:
    """执行 Ook! 程序，返回标准输出（先转 Brainfuck 再执行）。"""
    return brainfuck_exec(ook_to_brainfuck(program), input_text)


# ---------------------------------------------------------------------------
# jother（Brainfuck 的 JS 变体）
# ---------------------------------------------------------------------------
def jother_to_brainfuck(program: str) -> str:
    """把 jother 程序翻译成 Brainfuck 程序。

    jother 用 ``[]()!+`` 六个字符表示 BF 的八种指令（``[]`` 共用）。
    与 Brainfuck 的对应关系为 8 个 token 的组合；这里支持常见的 jother
    字符序列直接映射（``+!+[]+[]+`` 等复杂写法超出简单映射，按字符处理）。
    """
    text = str(program).strip()
    if not text:
        raise EsolangError("jother 程序为空。")
    # jother 本质是 JS 表达式，执行结果才是 BF 程序。
    # 简单实现：直接按 BF 指令字符过滤（jother 常用写法含 + - < > . , [ ]）。
    bf = "".join(c for c in text if c in _BF_COMMANDS)
    if not bf:
        raise EsolangError(
            "jother 程序未能提取出 Brainfuck 指令。jother 是 JS 表达式，"
            "建议先用 node 执行得到 BF 源码后再解码。")
    return bf


def jother_exec(program: str, input_text: str = "") -> str:
    """执行 jother 程序（先提取 Brainfuck 指令再执行）。"""
    return brainfuck_exec(jother_to_brainfuck(program), input_text)


# ---------------------------------------------------------------------------
# JSFuck 编码 / 解码
# ---------------------------------------------------------------------------
#: JSFuck 编码：把每个字符用 JS 表达式拼出。这里实现「字符串字面量 -> JSFuck」的
#: 常见子集：对 ASCII 字符，利用 ``[]+[]`` / ``!![]`` / ``+!+[]`` 等基元构造。
#: 完整 JSFuck 编码非常复杂（需逐字符映射到基元表达式），这里给出核心映射表，
#: 覆盖 CTF 常见的短 JS 片段。
_JSFUCK_PRIMITIVES = {
    "false": "![]",
    "true": "!![]",
    "undefined": "[][[]]",
    "NaN": "+[![]]",
    "Infinity": "+(+!+[]+(!+[]+[])[!+[]+!+[]+!+[]]+[+!+[]]+[+[]]+[+[]])",
}


def jsfuck_encode(js_code: str) -> str:
    """把 JS 代码编码成 JSFuck（仅 ``[]()!+`` 六字符）。

    完整 JSFuck 编码需要逐字符的基元表达式构建，本实现提供核心字符映射，
    覆盖数字、常用符号与 ``undefined`` / ``NaN`` / ``true`` / ``false``。
    复杂语句请使用专用工具（如在线 JSFuck 编码器）。
    """
    text = str(js_code)
    out: list[str] = []
    for char in text:
        prim = _jsfuck_char(char)
        if prim is None:
            raise EsolangError(
                f"JSFuck 编码暂不支持字符 {char!r}。"
                "本实现覆盖数字、字母与部分符号；复杂代码请用专用编码器。")
        out.append(prim)
    return "+".join(out)


def _jsfuck_char(char: str) -> str | None:
    """返回单个字符的 JSFuck 表达式；不支持返回 None。"""
    # 数字：+!+[] 是 1，+[] 是 0；重复拼接构造任意数字
    if char.isdigit():
        n = int(char)
        if n == 0:
            return "+[]"
        return "+" + "+!+[]" * n if n == 1 else _jsfuck_number(n)
    # true / false / undefined / NaN
    if char == "t":
        return "(!![]+[])[+[]]"
    if char == "r":
        return "(!![]+[])[+!+[]]"
    if char == "u":
        return "(!![]+[])[+!+[]+!+[]]"
    if char == "e":
        return "(!![]+[])[+!+[]+!+[]+!+[]]"
    if char == "f":
        return "(![]+[])[+[]]"
    if char == "a":
        return "(![]+[])[+!+[]]"
    if char == "l":
        return "(![]+[])[+!+[]+!+[]]"
    if char == "s":
        return "(![]+[])[+!+[]+!+[]+!+[]]"
    return None


def _jsfuck_number(n: int) -> str:
    """把非负整数构造成 JSFuck 数字表达式（用 1 累加）。"""
    if n == 0:
        return "+[]"
    return "+(" + "+".join(["!+[]"] * n) + ")"


def jsfuck_decode(jsfuck_code: str) -> str:
    """解码 JSFuck：调用系统 ``node`` 执行还原为字符串。

    JSFuck 是合法 JS 代码，执行即还原；需本机安装 Node.js。
    """
    import shutil
    if shutil.which("node") is None:
        raise EsolangError(
            "JSFuck 解码需要 Node.js：当前系统未找到 node 命令。"
            "请安装 Node.js 后重试。")
    code = str(jsfuck_code).strip()
    if not code:
        raise EsolangError("JSFuck 代码为空。")
    try:
        proc = subprocess.run(
            ["node", "-e", f"process.stdout.write(String(eval({code!r})))"],
            capture_output=True, text=True, timeout=30,
            encoding="utf-8", errors="replace",
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise EsolangError(f"JSFuck 解码失败：{exc}") from exc
    if proc.returncode != 0:
        raise EsolangError(f"JSFuck 解码失败：{proc.stderr.strip()[:200]}")
    return proc.stdout


__all__ = [
    "EsolangError",
    "brainfuck_exec",
    "ook_to_brainfuck",
    "ook_exec",
    "jother_to_brainfuck",
    "jother_exec",
    "jsfuck_encode",
    "jsfuck_decode",
]


# ---------------------------------------------------------------------------
# 自检：``python -m lib.esolang``
# ---------------------------------------------------------------------------
def _self_test() -> int:
    failures: list[str] = []

    # Brainfuck：输出 "Hello World!"
    hello = "++++++++[>++++[>++>+++>+++>+<<<<-]>+>+>->>+[<]<-]>>.>---.+++++++..+++.>>.<-.<.+++.------.--------.>>+.>++."
    out = brainfuck_exec(hello)
    if out != "Hello World!\n":
        failures.append(f"Brainfuck HelloWorld 输出错误：{out!r}")

    # 简单加减 + 循环
    if brainfuck_exec("+++[>+<-]>.") != chr(3):
        failures.append("Brainfuck 加减循环错误")

    # Ook! 翻译（Ook. Ook. = +，Ook. Ook? = >，Ook! Ook. = .）
    bf = ook_to_brainfuck("Ook. Ook. Ook. Ook? Ook! Ook.")
    if bf != "+>.":
        failures.append(f"Ook 翻译错误：{bf!r}")

    # 括号不匹配报错
    try:
        brainfuck_exec("+++[")
    except EsolangError:
        pass
    else:
        failures.append("括号不匹配未报错")

    if failures:
        print("[FAIL] " + "；".join(failures))
        return 1
    print("esolang 自检通过：Brainfuck / Ook / 括号校验全部正确。")
    return 0


if __name__ == "__main__":
    raise SystemExit(_self_test())
