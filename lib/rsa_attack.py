# -*- coding: utf-8 -*-
"""RSA / 大整数攻击纯逻辑模块（纯标准库，无第三方依赖）。

面向 CTF 密码学的常见大整数与 RSA 攻击，全部用 Python 大整数 + 标准库实现，
避免 ``sympy`` / ``gmpy2`` / ``Cryptodome`` 等二进制依赖在打包与跨平台分发时
带来的麻烦。

对外能力
--------
1. **大整数基础运算**
   - :func:`modinv`          模逆元 a^{-1} mod m
   - :func:`crt`             中国剩余定理（CRT）
   - :func:`euler_phi`       欧拉函数 φ(n)（需已知质因数分解）
   - :func:`gcd` / :func:`lcm`  最大公约数 / 最小公倍数
   - :func:`powmod`          快速幂取模 a^e mod m

2. **大整数分解**
   - :func:`factor_trial`    试除法（小因子）
   - :func:`factor_fermat`   Fermat 分解（p、q 接近时）
   - :func:`factor_prho`     Pollard's rho（含 Brent 变体加速）
   - :func:`factor_pm1`      Pollard's p-1
   - :func:`factor`          自动按顺序尝试上述方法，返回质因子列表

3. **RSA 基础恢复**
   - :func:`rsa_recover_d`   已知 p、q、e 恢复私钥 d
   - :func:`rsa_private_key` 已知 p、q、e 生成 PEM 格式私钥
   - :func:`rsa_recover_pq_from_ed`  已知 n、e、d 反推 p、q

4. **常见 RSA 攻击**
   - :func:`attack_common_modulus`   共模攻击（同一 m 用不同 e 加密）
   - :func:`attack_low_exponent`     低加密指数 / 小明文（e 次开方）
   - :func:`attack_wiener`           Wiener 攻击（d 较小，连分数逼近）
   - :func:`attack_hastad`           Hastad 广播攻击（同一 m，多个 e_i 的 CRT）

所有数值输入均接受十进制 / 十六进制字符串（十六进制可带 ``0x`` 前缀），
由 :func:`parse_int` 统一解析。算法正确性见文件末尾 ``__main__`` 自检块。

本模块只做「大整数 / 参数进，结果出」的纯逻辑，不导入任何 UI 模块。
"""

from __future__ import annotations

import math
import random
from typing import Any, Callable


class RsaError(ValueError):
    """RSA / 大整数攻击统一异常：输入非法或攻击失败等。"""


# ---------------------------------------------------------------------------
# 输入解析
# ---------------------------------------------------------------------------
def parse_int(value) -> int:
    """把十进制 / 十六进制字符串解析成 int。

    接受 ``int``、十进制字符串（``123``）、十六进制字符串（``0x1f`` 或
    ``1f`` 带 ``hex=True`` 无法区分时按含字母判定）。带 ``0x`` 前缀或含
    a-f 字母视为十六进制；纯数字视为十进制。
    """
    if isinstance(value, int):
        return value
    text = str(value).strip().replace("_", "").replace(" ", "")
    if not text:
        raise RsaError("数值为空")
    if text.lower().startswith("0x"):
        try:
            return int(text, 16)
        except ValueError as exc:
            raise RsaError(f"不是合法十六进制：{value}") from exc
    # 含 a-f 字母且不含 e/E（避免把科学计数法误判）时视为十六进制
    if any(ch in text.lower() for ch in "abcdef") and "e" not in text.lower():
        try:
            return int(text, 16)
        except ValueError:
            pass
    try:
        return int(text, 10)
    except ValueError as exc:
        raise RsaError(f"不是合法整数：{value}") from exc


def _to_int(value) -> int:
    return value if isinstance(value, int) else parse_int(value)


# ---------------------------------------------------------------------------
# 大整数基础运算
# ---------------------------------------------------------------------------
def gcd(a, b) -> int:
    """最大公约数（欧几里得）。"""
    return math.gcd(_to_int(a), _to_int(b))


def lcm(a, b) -> int:
    """最小公倍数。"""
    x, y = _to_int(a), _to_int(b)
    if x == 0 or y == 0:
        return 0
    return abs(x * y) // math.gcd(x, y)


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """扩展欧几里得：返回 ``(g, x, y)`` 使 ``a*x + b*y = g = gcd(a, b)``。"""
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = extended_gcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)


def modinv(a, m) -> int:
    """模逆元 ``a^{-1} mod m``；不存在时抛 :class:`RsaError`。"""
    a = _to_int(a) % _to_int(m)
    m = _to_int(m)
    if m <= 0:
        raise RsaError("模数必须为正整数")
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise RsaError(f"{a} 在模 {m} 下无逆元（gcd={g}）")
    return x % m


def powmod(base, exp, mod) -> int:
    """快速幂取模 ``base^exp mod mod``（内置 pow 的三参形式）。"""
    return pow(_to_int(base), _to_int(exp), _to_int(mod))


def euler_phi(n) -> int:
    """欧拉函数 φ(n)（用试除法分解 n 后计算）。"""
    n = _to_int(n)
    if n <= 0:
        raise RsaError("φ(n) 要求 n > 0")
    if n == 1:
        return 1
    result = n
    x = n
    p = 2
    while p * p <= x:
        if x % p == 0:
            while x % p == 0:
                x //= p
            result -= result // p
        p += 1 if p == 2 else 2
    if x > 1:
        result -= result // x
    return result


def crt(remainders, moduli) -> int:
    """中国剩余定理：解 ``x ≡ r_i (mod m_i)``，返回最小非负解。

    ``remainders`` / ``moduli`` 为等长序列。模数不必两两互素（用逐次合并），
    无解时抛 :class:`RsaError`。
    """
    rs = [_to_int(r) for r in remainders]
    ms = [_to_int(m) for m in moduli]
    if len(rs) != len(ms) or not rs:
        raise RsaError("CRT 需要等长且非空的余数与模数列表")

    x, mod = 0, 1
    for r, m in zip(rs, ms):
        if m <= 0:
            raise RsaError("CRT 模数必须为正")
        # 合并 x (mod mod) 与 r (mod m)：求 x + mod*t ≡ r (mod m)
        g, a, _ = extended_gcd(mod, m)
        diff = r - x
        if diff % g != 0:
            raise RsaError(f"CRT 无解：{r} (mod {m}) 与 {x} (mod {mod}) 矛盾")
        l = mod // g * m
        t = (diff // g * a) % (m // g)
        x = (x + mod * t) % l
        mod = l
    return x % mod


def integer_nth_root(n: int, k: int) -> int:
    """整数 k 次方根（向下取整），``n`` 为完全 k 次方时返回精确根。"""
    if k <= 0:
        raise RsaError("开方次数必须为正")
    if n < 0:
        raise RsaError("暂不支持负数开方")
    if n == 0:
        return 0
    if k == 1:
        return n
    # 二分逼近，避免浮点精度问题
    lo, hi = 1, 1 << ((n.bit_length() + k - 1) // k)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if pow(mid, k) <= n:
            lo = mid
        else:
            hi = mid - 1
    return lo


def is_perfect_power(n: int, k: int) -> bool:
    """判断 ``n`` 是否为某个整数的 k 次幂。"""
    r = integer_nth_root(n, k)
    return pow(r, k) == n


def is_prime(n: int) -> bool:
    """确定性素性判定（Miller-Rabin + 小素数试除，对任意 int 可靠）。"""
    n = _to_int(n)
    if n < 2:
        return False
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for p in small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False
    # Miller-Rabin（用足够多的确定性基底）
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    bases = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for a in bases:
        if a >= n:
            continue
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def next_prime(n: int) -> int:
    """大于等于 ``n`` 的最小素数。"""
    n = _to_int(n)
    if n <= 2:
        return 2
    if n % 2 == 0:
        n += 1
    while not is_prime(n):
        n += 2
    return n


# ---------------------------------------------------------------------------
# 大整数分解
# ---------------------------------------------------------------------------
def factor_trial(n: int, limit: int = 1_000_000) -> list[int]:
    """试除法：返回 ``n`` 的质因子列表（含重数），只试除到 ``limit``。

    ``n`` 本身含大于 ``limit`` 的质因子时，该因子会作为剩余整体返回（若剩余
    是素数）。用于快速剥离小因子。
    """
    n = _to_int(n)
    if n < 2:
        raise RsaError("分解对象必须 ≥ 2")
    factors: list[int] = []
    d = 2
    while d <= limit and d * d <= n:
        while n % d == 0:
            factors.append(d)
            n //= d
        d += 1 if d == 2 else 2
    if n > 1:
        factors.append(n)
    return factors


def factor_fermat(n: int) -> tuple[int, int] | None:
    """Fermat 分解：``n = p*q`` 且 p、q 接近时有效。

    返回 ``(p, q)``（p ≤ q）；不适用时返回 None。
    """
    n = _to_int(n)
    if n % 2 == 0:
        return None
    a = integer_nth_root(n, 2)
    if a * a < n:
        a += 1
    # 限制迭代次数，避免在 p、q 不接近时无限循环
    max_iter = 1_000_000
    for _ in range(max_iter):
        b2 = a * a - n
        b = integer_nth_root(b2, 2)
        if b * b == b2:
            return (a - b, a + b)
        a += 1
    return None


def _pollard_rho_brent(n: int) -> int | None:
    """Pollard's rho（Brent 变体）：返回 n 的一个非平凡因子，失败返回 None。"""
    if n % 2 == 0:
        return 2
    if n % 3 == 0:
        return 3
    while True:
        y = random.randrange(1, n)
        c = random.randrange(1, n)
        m = 128
        g = r = q = 1
        while g == 1:
            x = y
            for _ in range(r):
                y = (y * y + c) % n
            k = 0
            while k < r and g == 1:
                ys = y
                for _ in range(min(m, r - k)):
                    y = (y * y + c) % n
                    q = q * abs(x - y) % n
                g = math.gcd(q, n)
                k += m
            r *= 2
        if g == n:
            g = 1
            while g == 1:
                ys = (ys * ys + c) % n
                g = math.gcd(abs(x - ys), n)
        if g != n:
            return g


def factor_prho(n: int) -> list[int]:
    """Pollard's rho（Brent 变体）递归分解，返回质因子列表（升序）。"""
    n = _to_int(n)
    if n < 2:
        raise RsaError("分解对象必须 ≥ 2")
    factors: list[int] = []

    def _recurse(x: int) -> None:
        if x == 1:
            return
        if is_prime(x):
            factors.append(x)
            return
        factor = _pollard_rho_brent(x)
        if factor is None or factor == x:
            # rho 失败，退回试除法兜底
            factors.extend(factor_trial(x, 100_000))
            return
        _recurse(factor)
        _recurse(x // factor)

    _recurse(n)
    return sorted(factors)


def factor_pm1(n: int, bound: int = 100_000) -> int | None:
    """Pollard's p-1：当 ``n`` 的某个因子 ``p`` 使 ``p-1`` 为小素数幂积时有效。

    返回一个非平凡因子，失败返回 None。
    """
    n = _to_int(n)
    if n % 2 == 0:
        return 2
    a = 2
    for j in range(2, bound + 1):
        a = pow(a, j, n)
        if j % 1000 == 0:
            g = math.gcd(a - 1, n)
            if 1 < g < n:
                return g
    g = math.gcd(a - 1, n)
    return g if 1 < g < n else None


def factor(n: int, use_fermat: bool = True, use_prho: bool = True,
           use_pm1: bool = True) -> list[int]:
    """综合分解：依次尝试试除法 → Fermat → Pollard's rho → p-1。

    返回质因子列表（升序，含重数）。对 256 位以内的常见 RSA 模数通常有效。
    """
    n = _to_int(n)
    if n < 2:
        raise RsaError("分解对象必须 ≥ 2")

    factors: list[int] = []

    def _try_methods(x: int) -> int | None:
        """用 Fermat / rho / p-1 尝试返回 x 的一个非平凡因子，失败返回 None。"""
        if x % 2 == 0:
            return 2
        if use_fermat:
            fp = factor_fermat(x)
            if fp is not None:
                return fp[0]
        if use_prho:
            f = _pollard_rho_brent(x)
            if f is not None and 1 < f < x:
                return f
        if use_pm1:
            f = factor_pm1(x)
            if f is not None and 1 < f < x:
                return f
        return None

    def _decompose(x: int) -> None:
        if x == 1:
            return
        if is_prime(x):
            factors.append(x)
            return
        f = _try_methods(x)
        if f is None:
            # 上述方法都失败：试除法（较慢但保底）
            for d in factor_trial(x, 10_000_000):
                if is_prime(d):
                    factors.append(d)
                else:
                    _decompose(d)
            return
        _decompose(f)
        _decompose(x // f)

    # 先试除法剥离小因子（快速，避免对小因子跑 rho）
    remaining = n
    for d in factor_trial(remaining, 1_000_000):
        if d == 1:
            continue
        if is_prime(d):
            factors.append(d)
            remaining //= d
        else:
            _decompose(d)
            remaining //= d
    if remaining > 1:
        _decompose(remaining)

    return sorted(factors)


# ---------------------------------------------------------------------------
# RSA 基础恢复
# ---------------------------------------------------------------------------
def rsa_recover_d(p, q, e) -> int:
    """已知 ``p``、``q``、``e`` 恢复私钥 ``d = e^{-1} mod lcm(p-1, q-1)``。"""
    p, q, e = _to_int(p), _to_int(q), _to_int(e)
    if not (is_prime(p) and is_prime(q)):
        raise RsaError("p、q 应为素数（请先确认分解结果）")
    lam = lcm(p - 1, q - 1)
    return modinv(e, lam)


def rsa_private_key(p, q, e) -> str:
    """已知 ``p``、``q``、``e`` 生成 PKCS#1 PEM 格式 RSA 私钥（纯标准库）。"""
    p, q, e = _to_int(p), _to_int(q), _to_int(e)
    if not (is_prime(p) and is_prime(q)):
        raise RsaError("p、q 应为素数")
    n = p * q
    d = rsa_recover_d(p, q, e)
    # 用 PKCS#1 的 CRT 参数构造，兼容多数工具
    dmp1 = d % (p - 1)
    dmq1 = d % (q - 1)
    iqmp = modinv(q, p)

    import struct

    def _der_len(length: int) -> bytes:
        if length < 0x80:
            return bytes([length])
        bs = length.to_bytes((length.bit_length() + 7) // 8, "big")
        return bytes([0x80 | len(bs)]) + bs

    def _der_int(value: int) -> bytes:
        if value == 0:
            body = b"\x00"
        else:
            body = value.to_bytes((value.bit_length() + 7) // 8, "big")
            if body[0] & 0x80:
                body = b"\x00" + body
        return b"\x02" + _der_len(len(body)) + body

    def _der_seq(*items: bytes) -> bytes:
        body = b"".join(items)
        return b"\x30" + _der_len(len(body)) + body

    seq = _der_seq(
        _der_int(0), _der_int(n), _der_int(e), _der_int(d),
        _der_int(p), _der_int(q), _der_int(dmp1), _der_int(dmq1),
        _der_int(iqmp),
    )
    # PKCS#1 RSAPrivateKey 只有一层 SEQUENCE（不要在外层再套一层）
    der = seq
    import base64
    b64 = base64.b64encode(der).decode("ascii")
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return "-----BEGIN RSA PRIVATE KEY-----\n" + "\n".join(lines) + \
           "\n-----END RSA PRIVATE KEY-----\n"


def rsa_recover_pq_from_ed(n, e, d) -> tuple[int, int]:
    """已知 ``n``、``e``、``d`` 反推 ``p``、``q``（基于 e*d-1 的分解技巧）。

    返回 ``(p, q)``；失败抛 :class:`RsaError`。
    """
    n, e, d = _to_int(n), _to_int(e), _to_int(d)
    k = e * d - 1
    if k <= 0 or k % 2 != 0:
        raise RsaError("e*d-1 不是正偶数，参数可能不正确")

    # 反复：随机取 a，a^k ≡ 1 (mod n)；k 反复折半找非平凡平方根
    t = k
    while t % 2 == 0:
        t //= 2
        for _ in range(20):
            a = random.randrange(2, n - 1)
            g = math.gcd(a, n)
            if 1 < g < n:
                return (g, n // g)
            x = pow(a, t, n)
            if x == n - 1 or x == 1:
                continue
            # 从 x 往回平方，找 y^2 ≡ 1 的非平凡解
            y = x
            while y != 1:
                z = (y * y) % n
                if z == 1 and y != 1 and y != n - 1:
                    p = math.gcd(y - 1, n)
                    if 1 < p < n:
                        return (p, n // p)
                y = z
    raise RsaError("无法从 n、e、d 恢复 p、q（参数可能不正确）")


# ---------------------------------------------------------------------------
# 常见 RSA 攻击
# ---------------------------------------------------------------------------
def _rsa_decrypt_pq(c, d, n) -> int:
    """用私钥 d 解密：m = c^d mod n。"""
    return pow(_to_int(c), _to_int(d), _to_int(n))


def attack_common_modulus(c1, c2, e1, e2, n) -> int:
    """共模攻击：同一明文 m 用同一 n、不同 e1/e2 加密得 c1/c2。

    要求 ``gcd(e1, e2) = 1``。返回恢复的明文 m。
    """
    c1, c2 = _to_int(c1), _to_int(c2)
    e1, e2, n = _to_int(e1), _to_int(e2), _to_int(n)
    g, a, b = extended_gcd(e1, e2)
    if g != 1:
        raise RsaError(f"共模攻击要求 gcd(e1,e2)=1，当前为 {g}")
    # m = c1^a * c2^b mod n（a、b 可能为负，需取逆元）
    if a < 0:
        c1 = modinv(c1, n)
        a = -a
    if b < 0:
        c2 = modinv(c2, n)
        b = -b
    return (pow(c1, a, n) * pow(c2, b, n)) % n


def attack_low_exponent(c, e, n) -> int:
    """低加密指数 / 小明文攻击：``c = m^e``（m^e < n，即无模约简）。

    直接对 c 开 e 次方根恢复 m；若 c 不是完全 e 次方，尝试 ``c + k*n`` 逐步
    开方（应对 m^e 略大于 n 的情况）。
    """
    c, e, n = _to_int(c), _to_int(e), _to_int(n)
    if e < 2:
        raise RsaError("加密指数 e 必须 ≥ 2")
    # 先试直接开方
    r = integer_nth_root(c, e)
    if pow(r, e) == c:
        return r
    # 再试 c + k*n
    for k in range(1, 10_000):
        cand = c + k * n
        r = integer_nth_root(cand, e)
        if pow(r, e) == cand:
            return r
    raise RsaError("低指数攻击失败：密文不是可开方的 e 次幂")


def _continued_fraction(num: int, den: int):
    """把 num/den 展成连分数，逐项产出渐进分数 (k, d)。"""
    while den:
        q = num // den
        yield (q, 1)
        num, den = den, num - q * den


def _convergents(num: int, den: int):
    """产出 num/den 的所有渐进分数 (k, d)。"""
    h0, h1 = 0, 1
    k0, k1 = 1, 0
    for a, _ in _continued_fraction(num, den):
        h2 = a * h1 + h0
        k2 = a * k1 + k0
        yield (h2, k2)
        h0, h1 = h1, h2
        k0, k1 = k1, k2


def attack_wiener(n, e) -> int | None:
    """Wiener 攻击：当私钥 ``d`` 较小时（约 d < n^0.25/3），用连分数恢复 d。

    返回恢复的 ``d``；失败返回 None。
    """
    n, e = _to_int(n), _to_int(e)
    for k, d in _convergents(e, n):
        if k == 0 or d == 0:
            continue
        # 验证：φ(n) = (e*d - 1)/k，且 φ 应为整数
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        # 验证二次方程 x^2 - (n - phi + 1)x + n = 0 有整数解
        s = n - phi + 1
        discriminant = s * s - 4 * n
        if discriminant < 0:
            continue
        t = integer_nth_root(discriminant, 2)
        if t * t != discriminant:
            continue
        if (s + t) % 2 != 0:
            continue
        p = (s + t) // 2
        q = (s - t) // 2
        if p * q == n:
            return d
    return None


def attack_hastad(ciphertexts, exponents, n) -> int:
    """Hastad 广播攻击：同一明文 m 用相同的 e、不同的 n 加密。

    当 ``m^e < ∏ n_i`` 时，用 CRT 合并 ``m^e mod ∏n_i`` 再开 e 次方。
    ``ciphertexts`` 为密文列表，``exponents`` 为对应 e 列表（通常全相等），
    ``n`` 为模数列表（可传列表，或单一 int 表示全部相同）。
    """
    cs = [_to_int(c) for c in ciphertexts]
    es = [_to_int(e) for e in exponents]
    if isinstance(n, (list, tuple)):
        ns = [_to_int(x) for x in n]
    else:
        ns = [_to_int(n)] * len(cs)
    if not (len(cs) == len(es) == len(ns)):
        raise RsaError("密文、指数、模数数量必须一致")
    if len(cs) == 0:
        raise RsaError("广播攻击至少需要一组密文")

    # 所有 e 相同时直接 CRT 合并；否则需要组合（这里简化：要求 e 全相同）
    e0 = es[0]
    if any(e != e0 for e in es):
        raise RsaError("Hastad 攻击当前仅支持各密文使用相同 e 的情形")
    if len(cs) < e0:
        raise RsaError(f"Hastad 攻击至少需要 e 组密文（e={e0}，现有 {len(cs)} 组）")

    m_e = crt(cs, ns)
    r = integer_nth_root(m_e, e0)
    if pow(r, e0) != m_e:
        raise RsaError("Hastad 攻击失败：合并结果不是完全 e 次方")
    return r


# ---------------------------------------------------------------------------
# 整数 ↔ 字节 / 文本辅助
# ---------------------------------------------------------------------------
def int_to_bytes(n: int) -> bytes:
    """把非负整数转成最小长度大端字节串（0 → b''）。"""
    n = _to_int(n)
    if n < 0:
        raise RsaError("负数无法转字节串")
    if n == 0:
        return b""
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def int_to_text(n: int) -> str:
    """把整数按大端字节解码为 UTF-8 文本（失败回退为十六进制）。"""
    raw = int_to_bytes(n)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.hex()


def text_to_int(text: str) -> int:
    """把文本按 UTF-8 字节转成整数。"""
    return int.from_bytes(text.encode("utf-8"), "big")


# ---------------------------------------------------------------------------
# 自检：``python -m lib.rsa_attack``
# ---------------------------------------------------------------------------
def _self_test() -> int:
    failures: list[str] = []

    def check(name: str, got, expect) -> None:
        if got != expect:
            failures.append(f"{name}: got {got}, expect {expect}")

    # 1. 基础运算
    check("gcd", gcd(48, 18), 6)
    check("lcm", lcm(4, 6), 12)
    check("modinv", modinv(3, 11), 4)
    check("powmod", powmod(2, 10, 1000), 24)
    check("euler_phi", euler_phi(36), 12)
    check("crt", crt([2, 3, 2], [3, 5, 7]), 23)
    check("nth_root", integer_nth_root(27, 3), 3)
    check("nth_root_floor", integer_nth_root(28, 3), 3)
    check("is_prime", is_prime(97), True)
    check("is_prime_comp", is_prime(91), False)

    # 2. 分解
    check("factor_trial", factor_trial(12), [2, 2, 3])
    # Fermat：p、q 接近
    p, q = 1009, 1013
    fp = factor_fermat(p * q)
    check("factor_fermat", sorted(fp) if fp else None, [p, q])
    # 综合分解：两个 16 位素数乘积
    n1 = 3571 * 7919
    check("factor", factor(n1), [3571, 7919])
    # 含重数
    check("factor_square", factor(2 * 2 * 3 * 3 * 5), [2, 2, 3, 3, 5])

    # 3. RSA 基础恢复
    p2, q2, e2 = 61, 53, 17
    d2 = rsa_recover_d(p2, q2, e2)
    check("rsa_recover_d", (e2 * d2) % lcm(p2 - 1, q2 - 1), 1)
    pem = rsa_private_key(p2, q2, e2)
    check("rsa_private_key_header", pem.startswith("-----BEGIN RSA PRIVATE KEY-----"), True)
    rp = rsa_recover_pq_from_ed(p2 * q2, e2, d2)
    check("rsa_recover_pq_from_ed", sorted(rp), sorted([p2, q2]))

    # 4. 常见攻击
    # 共模攻击
    n3, e_a, e_b = 77, 3, 7  # 77=7*11，gcd(3,7)=1
    m3 = 5  # 与 77 互素
    c_a = pow(m3, e_a, n3)
    c_b = pow(m3, e_b, n3)
    check("common_modulus", attack_common_modulus(c_a, c_b, e_a, e_b, n3), m3)

    # 低指数攻击
    m4 = 12345
    c4 = pow(m4, 3)  # 无模约简
    check("low_exponent", attack_low_exponent(c4, 3, 10**30), m4)

    # Wiener 攻击（用小 d 生成，d 需满足 d < n^0.25/3）
    wp, wq = 10007, 10009
    wn = wp * wq
    wphi = (wp - 1) * (wq - 1)
    wd = 29  # 小 d（< n^0.25/3 ≈ 33）
    we = modinv(wd, wphi)
    wd_recovered = attack_wiener(wn, we)
    check("wiener", wd_recovered, wd)

    # Hastad 广播攻击
    hm = 7
    he = 3
    hn_list = [next_prime(10**6 + i) for i in range(3)]
    hc_list = [pow(hm, he, nn) for nn in hn_list]
    check("hastad", attack_hastad(hc_list, [he, he, he], hn_list), hm)

    if failures:
        print("[FAIL] " + "；".join(failures))
        return 1
    print("rsa_attack 自检通过：基础运算 / 分解 / RSA 恢复 / 常见攻击全部正确。")
    return 0


if __name__ == "__main__":
    raise SystemExit(_self_test())
