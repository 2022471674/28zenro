# -*- coding: utf-8 -*-
"""国密算法（SM3 / SM4 / SM2）正确性测试。

测试向量取自 GM/T 0004-2012（SM3）、GM/T 0002-2012（SM4）官方文档，
以及 GB/T 32918 系列（SM2）公开测试向量，用于回归保护纯 Python 实现。
"""

import pytest

from lib import gm_codec as g


# ---------------------------------------------------------------------------
# SM3 摘要
# ---------------------------------------------------------------------------
class TestSm3:
    def test_empty(self):
        # GM/T 0004-2012 附录 A 示例 1
        assert g.sm3_hex("") == (
            "1ab21d8355cfa17f8e61194831e81a8f"
            "22bec8c728fefb747ed035eb5082aa2b"
        )

    def test_abc(self):
        # GM/T 0004-2012 附录 A 示例 2
        assert g.sm3_hex("abc") == (
            "66c7f0f462eeedd9d1f2d46bdc10e4e2"
            "4167c4875cf2f7a2297da02b8f4ba8e0"
        )

    def test_known_digest_length(self):
        assert len(g.sm3_hash("x")) == 32
        assert len(g.sm3_hex("x")) == 64


# ---------------------------------------------------------------------------
# SM4 对称加解密
# ---------------------------------------------------------------------------
class TestSm4:
    KEY = bytes(range(16))          # 00..0f
    IV = bytes([0xAA] * 16)
    PLAINTEXT = "flag{sm4_test_12345}"

    def test_ecb_roundtrip(self):
        ct = g.sm4_ecb_encrypt(self.PLAINTEXT.encode(), self.KEY)
        pt = g.sm4_ecb_decrypt(ct, self.KEY)
        assert pt.decode() == self.PLAINTEXT

    def test_ecb_known_vector(self):
        # GM/T 0002-2012 附录 A 示例：key=0123456789abcdeffedcba9876543210，
        # 明文=0123456789abcdeffedcba9876543210 -> 密文 681edf34d206965e...
        key = bytes.fromhex("0123456789abcdeffedcba9876543210")
        pt = bytes.fromhex("0123456789abcdeffedcba9876543210")
        expected = "681edf34d206965e86b3e94f536e4246"
        assert g.sm4_ecb_encrypt(pt, key, padding=False).hex() == expected

    def test_cbc_roundtrip(self):
        ct = g.sm4_cbc_encrypt(self.PLAINTEXT.encode(), self.KEY, self.IV)
        pt = g.sm4_cbc_decrypt(ct, self.KEY, self.IV)
        assert pt.decode() == self.PLAINTEXT

    def test_cbc_padding_removed(self):
        # 明文长度非 16 倍数时，解密后应正确去掉 PKCS7 填充
        for text in ("a", "ab", "1234567890123456", "x" * 20):
            ct = g.sm4_cbc_encrypt(text.encode(), self.KEY, self.IV)
            assert g.sm4_cbc_decrypt(ct, self.KEY, self.IV).decode() == text


# ---------------------------------------------------------------------------
# SM2 公钥密码
# ---------------------------------------------------------------------------
class TestSm2:
    def test_keypair_derive(self):
        priv, pub = g.sm2_generate_keypair()
        # 由私钥推公钥应一致
        assert g.sm2_public_from_private(priv) == pub

    def test_encrypt_decrypt_c1c3c2(self):
        priv, pub = g.sm2_generate_keypair()
        ct = g.sm2_encrypt("sm2 secret".encode(), pub, mode="C1C3C2")
        pt = g.sm2_decrypt(ct, priv, mode="C1C3C2")
        assert pt == b"sm2 secret"

    def test_encrypt_decrypt_c1c2c3(self):
        priv, pub = g.sm2_generate_keypair()
        ct = g.sm2_encrypt("legacy".encode(), pub, mode="C1C2C3")
        pt = g.sm2_decrypt(ct, priv, mode="C1C2C3")
        assert pt == b"legacy"

    def test_sign_verify(self):
        priv, pub = g.sm2_generate_keypair()
        sig = g.sm2_sign("message", priv, pub)
        assert len(sig) == 128  # r||s
        assert g.sm2_verify("message", sig, pub) is True
        assert g.sm2_verify("tampered", sig, pub) is False


# ---------------------------------------------------------------------------
# parse_hex 容错
# ---------------------------------------------------------------------------
class TestParseHex:
    def test_prefix_and_separator(self):
        assert g.parse_hex("0xAA BB") == b"\xaa\xbb"
        assert g.parse_hex("aa:bb") == b"\xaa\xbb"
        assert g.parse_hex("aa-bb") == b"\xaa\xbb"

    def test_odd_length(self):
        assert g.parse_hex("f") == b"\x0f"

    def test_invalid(self):
        with pytest.raises(g.GmError):
            g.parse_hex("zz")
