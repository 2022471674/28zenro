import hashlib


def to_bytes(data) -> bytes:
    if isinstance(data, bytes):
        return data
    return str(data).encode("utf-8")

def md5_hex(data: str) -> str:
    """计算 MD5 摘要（32 位十六进制小写字符串）。"""
    return hashlib.md5(to_bytes(data)).hexdigest()


def sha1_hex(data: str) -> str:
    """ 计算 SHA-1 摘要（40 位十六进制小写字符串）。"""
    return hashlib.sha1(to_bytes(data)).hexdigest()


def sha256_hex(data: str) -> str:
    """计算 SHA-256 摘要（64 位十六进制小写字符串）。"""
    return hashlib.sha256(to_bytes(data)).hexdigest()


def sha512_hex(data: str) -> str:
    """计算 SHA-512 摘要（128 位十六进制小写字符串）。"""
    return hashlib.sha512(to_bytes(data)).hexdigest()


def sha3_256_hex(data: str) -> str:
    """计算 SHA3-256 摘要（64 位十六进制小写字符串）。"""
    return hashlib.sha3_256(to_bytes(data)).hexdigest()


def hash_by_name(name: str, data: str) -> str:
    algorithm = str(name).strip().lower().replace("-", "_")
    if algorithm not in hashlib.algorithms_available:
        raise ValueError(f"不支持的哈希算法: {name}")
    return hashlib.new(algorithm, to_bytes(data)).hexdigest()

