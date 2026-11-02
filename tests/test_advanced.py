# -*- coding: utf-8 -*-
"""JWT / 哈希长度扩展 / RSA 攻击 / JSON 工具的回归测试。

覆盖结构解析、互逆性、已知向量与常见攻击路径的关键断言。
"""

import pytest

from lib import hash_ext
from lib import json_tool as jt
from lib import jwt_codec as jwt
from lib import rsa_attack as ra


# ---------------------------------------------------------------------------
# JWT
# ---------------------------------------------------------------------------
class TestJwt:
    def test_parse_structure(self):
        token = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            "dozjgvvlkg5X9d7L2L6mE0M9h9Zk0m0"
        )
        info = jwt.parse(token)
        assert info.header["alg"] == "HS256"
        assert info.payload["sub"] == "1234567890"

    def test_create_verify_hs256(self):
        token = jwt.create({"sub": "admin"}, {"role": "user"}, key="secret")
        assert jwt.verify(token, "secret") is True
        assert jwt.verify(token, "wrong") is False

    def test_none_algorithm_verify(self):
        token = jwt.create({"sub": "x"}, {"a": "b"}, key=None, algorithm="none")
        assert jwt.verify(token, key=None) is True

    def test_b64url(self):
        assert jwt.b64url_encode(b"a>b?") == "YT5iPw"


# ---------------------------------------------------------------------------
# 哈希长度扩展
# ---------------------------------------------------------------------------
class TestHashExt:
    def test_md5_extend_full(self):
        import hashlib

        secret = b"secret"
        data = b"data"
        append = b"&admin=1"
        original = hashlib.md5(secret + data).hexdigest()
        res = hash_ext.length_extend_full(
            "md5", original, data.decode(), append.decode(), len(secret)
        )
        # 独立真值：用标准库 hashlib 计算 H(secret || data || padding || append)
        total_len = len(secret) + len(data)
        pad = hash_ext._padding("md5", total_len)
        forged = hashlib.md5(secret + data + pad + append).hexdigest()
        assert res["new_hash"] == forged
        # new_message 应恰好等于 data || padding || append（不含 secret）
        assert res["new_message"] == (data + pad + append).hex()

    @pytest.mark.parametrize("algo", ["md5", "sha1", "sha256"])
    def test_extend_returns_keys(self, algo):
        res = hash_ext.length_extend(algo, "0" * (32 if algo == "md5" else 40 if algo == "sha1" else 64), "x", 8)
        assert "new_hash" in res
        assert "new_message" in res


# ---------------------------------------------------------------------------
# RSA 攻击
# ---------------------------------------------------------------------------
class TestRsaAttack:
    def test_factor_small(self):
        # 15 = 3 * 5
        factors = ra.factor(15)
        assert sorted(factors) == [3, 5]

    def test_rsa_recover_d(self):
        # p=61, q=53, e=17：用 lcm(p-1,q-1) 验证 d 是合法私钥
        p, q, e = 61, 53, 17
        d = ra.rsa_recover_d(p, q, e)
        lam = ra.lcm(p - 1, q - 1)
        assert (e * d) % lam == 1
        # 再验证加解密互逆
        m = 42
        n = p * q
        assert ra.powmod(ra.powmod(m, e, n), d, n) == m

    def test_modinv(self):
        # 3 * inv = 1 (mod 11) -> inv = 4
        assert ra.modinv(3, 11) == 4

    def test_int_text_roundtrip(self):
        assert ra.int_to_text(ra.text_to_int("flag")) == "flag"

    def test_low_exponent(self):
        # m^3 = c，小 m 直接开三次方
        m = 42
        c = m ** 3
        n = 10 ** 30  # 足够大，不影响开方
        assert ra.attack_low_exponent(c, 3, n) == m


# ---------------------------------------------------------------------------
# JSON 工具
# ---------------------------------------------------------------------------
class TestJsonTool:
    def test_loads_valid(self):
        obj, errors = jt.loads_json('{"a": 1}')
        assert obj == {"a": 1}
        assert errors == []

    def test_loads_invalid(self):
        with pytest.raises(jt.JsonToolError):
            jt.loads_json('{"a": }')

    def test_format_minify(self):
        data = '{"b":2,"a":[1,true]}'
        formatted = jt.format_json(data, indent=2)
        assert jt.minify_json(formatted).replace(" ", "") == data.replace(" ", "")

    def test_analyze(self):
        report = jt.analyze_json('{"a": 1, "b": {"c": 2}}')
        assert "对象" in report  # 根类型为对象
        assert "最大深度" in report
