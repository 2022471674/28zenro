# -*- coding: utf-8 -*-
"""编解码工具（Base / ROT / 字符 / 哈希 / 进制 / 字符串）回归测试。

覆盖各工具「编码→解码」互逆性，以及已知向量的固定断言，防止回归。
"""

import pytest

from lib import base_codec as bc
from lib import char_codec as cc
from lib import hash_codec as hc
from lib import number_base_codec as nb
from lib import rot_codec as rc
from lib import string_codec as sc


# ---------------------------------------------------------------------------
# Base 系列
# ---------------------------------------------------------------------------
class TestBase:
    @pytest.mark.parametrize(
        "enc,dec",
        [
            (bc.base64_encrypt, bc.base64_decrypt),
            (bc.base64_urlsafe_encrypt, bc.base64_urlsafe_decrypt),
            (bc.base32_encrypt, bc.base32_decrypt),
            (bc.base16_encrypt, bc.base16_decrypt),
            (bc.base58_encrypt, bc.base58_decrypt),
            (bc.base62_encrypt, bc.base62_decrypt),
            (bc.base91_encrypt, bc.base91_decrypt),
            (bc.base92_encrypt, bc.base92_decrypt),
            (bc.uuencode_encrypt, bc.uuencode_decrypt),
            (bc.xxencode_encrypt, bc.xxencode_decrypt),
        ],
    )
    def test_roundtrip(self, enc, dec):
        text = "flag{hello_world_123}"
        assert dec(enc(text)) == text

    def test_base64_known(self):
        assert bc.base64_encrypt("hi") == "aGk="
        assert bc.base64_decrypt("aGk=") == "hi"

    def test_base16_known(self):
        assert bc.base16_encrypt("A") == "41"
        assert bc.base16_decrypt("41") == "A"

    @pytest.mark.parametrize("variant", ["b85", "a85"])
    def test_base85_roundtrip(self, variant):
        text = "ctf base85 测试"
        assert bc.base85_decrypt(bc.base85_encrypt(text, variant), variant) == text


# ---------------------------------------------------------------------------
# ROT 移位
# ---------------------------------------------------------------------------
class TestRot:
    def test_rot13_known(self):
        assert rc.rot13_encrypt("hello") == "uryyb"
        assert rc.rot13_decrypt("uryyb") == "hello"
        # 自反：两次 ROT13 还原
        assert rc.rot13_encrypt(rc.rot13_encrypt("abc")) == "abc"

    def test_rot47_known(self):
        assert rc.rot47_encrypt("A") == "p"
        assert rc.rot47_decrypt("p") == "A"

    def test_rot_n_known(self):
        assert rc.rot_n("abc", 3) == "def"
        assert rc.rot_n("xyz", 3) == "abc"
        # 非字母原样保留
        assert rc.rot_n("a1!", 1) == "b1!"


# ---------------------------------------------------------------------------
# 字符加解密
# ---------------------------------------------------------------------------
class TestChar:
    def test_caesar_known(self):
        assert cc.caesar_encrypt("abc", 3) == "def"
        assert cc.caesar_decrypt("def", 3) == "abc"
        assert cc.caesar_encrypt("XYZ", 2) == "ZAB"

    def test_pigpen_roundtrip(self):
        text = "abcdefghijklmnopqrstuvwxyz"
        # 猪圈密码解密输出为大写字母（与实现约定一致）
        assert cc.pigpen_decrypt(cc.pigpen_encrypt(text)) == text.upper()


# ---------------------------------------------------------------------------
# 哈希
# ---------------------------------------------------------------------------
class TestHash:
    def test_md5_known(self):
        assert hc.md5_hex("abc") == "900150983cd24fb0d6963f7d28e17f72"

    def test_sha1_known(self):
        assert hc.sha1_hex("abc") == "a9993e364706816aba3e25717850c26c9cd0d89d"

    def test_sha256_known(self):
        assert hc.sha256_hex("abc") == (
            "ba7816bf8f01cfea414140de5dae2223"
            "b00361a396177a9cb410ff61f20015ad"
        )

    def test_sha512_length(self):
        assert len(hc.sha512_hex("abc")) == 128

    def test_sha3_256_known(self):
        assert hc.sha3_256_hex("abc") == (
            "3a985da74fe225b2045c172d6bd390bd"
            "855f086e3e9d525b46bfe24511431532"
        )

    def test_hash_by_name(self):
        assert hc.hash_by_name("md5", "abc") == hc.md5_hex("abc")


# ---------------------------------------------------------------------------
# 进制互转
# ---------------------------------------------------------------------------
class TestNumberBase:
    def test_hex_to_dec(self):
        assert nb.convert("ff", 16, 10) == "255"

    def test_dec_to_bin(self):
        assert nb.convert("10", 10, 2) == "1010"

    def test_prefix(self):
        assert nb.convert("0xff", 16, 10) == "255"

    def test_separator(self):
        assert nb.convert("1010 1100", 2, 16) == "AC"

    def test_negative(self):
        assert nb.convert("-5", 10, 2) == "-101"


# ---------------------------------------------------------------------------
# 字符串工具
# ---------------------------------------------------------------------------
class TestString:
    def test_url_encode(self):
        assert sc.url_encode("a b") == "a%20b"

    def test_url_decode_roundtrip(self):
        assert sc.url_decode(sc.url_encode("中文 abc")) == "中文 abc"

    def test_ascii_roundtrip(self):
        assert sc.ascii_to_str(sc.str_to_ascii("Hi!")) == "Hi!"

    def test_case(self):
        assert sc.to_upper("aBc") == "ABC"
        assert sc.to_lower("aBc") == "abc"
