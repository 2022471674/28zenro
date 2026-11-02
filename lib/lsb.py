# -*- coding: utf-8 -*-
"""LSB 隐写：嵌入秘密信息 / 提取水印文字，并支持自定义嵌入位置与参数自动探测。

移植自「水印GUI」项目的 ``wmtool/lsb.py``，保持纯逻辑、无任何 UI 依赖，
与本项目 ``lib/`` 层约定一致（只做「路径 / 参数进、路径 / 文本出」）。

默认参数与旧脚本完全一致（列优先、bit0、RGB 三通道、偏移 0、FF 结束符），
因此旧脚本生成的 stego 图片仍可直接提取。

在此基础上支持：
* 通道：R/G/B/A 任意子集，如 "RGB"、"RGBA"、"RB"、"G"
* 位平面：0-7（0 为最低位，即经典 LSB）
* 起始偏移：跳过前 N 个可写位
* 扫描顺序：列优先(column，兼容旧脚本) / 行优先(row)
* 载荷封装：结束符(marker，兼容旧脚本) / 长度前缀(length，更利于自动探测)

并提供 :func:`detect_params`：对未知参数的 stego 图片爆破参数组合并给出候选。

对外接口：
    read_secret(input)              入参是文件路径则读取其内容，否则原样返回
    parse_channels(channels)        通道字符串 -> RGBA 下标列表
    capacity / capacity_text        载体可写容量
    embed(...)                      LSB 嵌入，返回输出路径
    extract(...)                    LSB 提取，可选写入文本文件
    detect_params(...)              爆破参数，返回候选列表
    describe_params(...)            参数 -> 一行中文描述
"""

from __future__ import annotations

import os

from PIL import Image

END_MARKER = "11111111"

# 通道字符 -> RGBA 元组下标
_CHANNEL_INDEX = {"R": 0, "G": 1, "B": 2, "A": 3}

CHANNEL_PRESETS = ("RGB", "RGBA", "R", "G", "B", "A", "RB", "GB")
CHANNEL_NAMES = {
    "RGB": "RGB 三通道（默认）",
    "RGBA": "RGBA 四通道",
    "R": "仅红色通道",
    "G": "仅绿色通道",
    "B": "仅蓝色通道",
    "A": "仅透明通道",
    "RB": "红+蓝通道",
    "GB": "绿+蓝通道",
}
ORDERS = ("column", "row")
ORDER_NAMES = {"column": "列优先（兼容旧脚本）", "row": "行优先"}
FRAMINGS = ("marker", "length")
FRAMING_NAMES = {"marker": "结束符 FF（兼容旧脚本）", "length": "长度前缀（推荐自动探测）"}


def read_secret(secret_input):
    """若入参是存在的文件路径，则读取其文本内容，否则原样作为秘密信息。"""
    if os.path.isfile(secret_input):
        with open(secret_input, "rb") as f:
            return f.read().decode("utf-8", errors="ignore")
    return secret_input


def parse_channels(channels):
    """把通道字符串解析为下标列表，如 "RGB" -> [0,1,2]。"""
    if channels is None:
        return [0, 1, 2]
    text = str(channels).strip().upper()
    if not text:
        return [0, 1, 2]
    result = []
    for ch in text:
        if ch not in _CHANNEL_INDEX:
            raise ValueError(f"不支持的通道: {ch}（可用 R/G/B/A，如 RGB、RGBA、RB）")
        idx = _CHANNEL_INDEX[ch]
        if idx not in result:
            result.append(idx)
    if not result:
        raise ValueError("通道不能为空，例如 RGB")
    return result


def _check_bit(bit):
    bit = int(bit)
    if not 0 <= bit <= 7:
        raise ValueError(f"位平面需为 0-7，当前: {bit}")
    return bit


def _check_offset(offset):
    offset = int(offset)
    if offset < 0:
        raise ValueError(f"起始偏移不能为负数，当前: {offset}")
    return offset


def _check_order(order):
    if order not in ORDERS:
        raise ValueError(f"不支持的扫描顺序: {order}（可用 column / row）")
    return order


def _load(carrier_path, channels):
    if not os.path.isfile(carrier_path):
        raise FileNotFoundError(f"载体图片不存在: {carrier_path}")
    need_alpha = 3 in parse_channels(channels)
    with Image.open(carrier_path) as src:
        img = src.convert("RGBA" if need_alpha else "RGB")
    return img


def _pixel_order(width, height, order):
    """生成像素坐标序列。column 与旧脚本一致（先列后行）。"""
    if order == "row":
        for j in range(height):
            for i in range(width):
                yield i, j
    else:
        for i in range(width):
            for j in range(height):
                yield i, j


def capacity(carrier_path, channels="RGB"):
    """返回可写入的位数。"""
    img = _load(carrier_path, channels)
    width, height = img.size
    return width * height * len(parse_channels(channels))


def capacity_text(carrier_path, channels="RGB"):
    """返回容量的人类可读描述。"""
    bits = capacity(carrier_path, channels)
    return f"{bits} 位（约 {bits // 8} 字节）"


def _encode_bits(secret_bytes, framing):
    """把载荷编码成位串。"""
    if framing == "length":
        header = format(len(secret_bytes), "032b")
        body = "".join(format(b, "08b") for b in secret_bytes)
        return header + body
    body = "".join(format(b, "08b") for b in secret_bytes)
    return body + END_MARKER


def _write_bits(img, bits, channels, bit, offset, order):
    """把位串写入图片，返回实际写入位数。"""
    indices = parse_channels(channels)
    bit = _check_bit(bit)
    offset = _check_offset(offset)
    order = _check_order(order)
    mask = 0xFF ^ (1 << bit)
    width, height = img.size
    pixels = img.load()
    total = len(bits)
    pos = 0
    slot = -1  # 全局可写位序号
    for i, j in _pixel_order(width, height, order):
        if pos >= total:
            break
        values = list(pixels[i, j])
        changed = False
        for idx in indices:
            slot += 1
            if slot < offset or pos >= total:
                continue
            values[idx] = (values[idx] & mask) | (int(bits[pos]) << bit)
            pos += 1
            changed = True
        if changed:
            pixels[i, j] = tuple(values)
    return pos


def embed(carrier_path, secret_data, output_path, channels="RGB", bit=0,
          offset=0, order="column", framing="marker"):
    """把秘密信息写入载体图片，返回输出路径。

    framing="marker" 时与原脚本格式一致（末尾 FF 结束符）。
    """
    if not secret_data:
        raise ValueError("秘密信息不能为空")
    framing = framing if framing in FRAMINGS else "marker"

    img = _load(carrier_path, channels)
    # 以 UTF-8 字节为单位写入，中文等多字节字符才能正确还原
    secret_bytes = secret_data.encode("utf-8") if isinstance(secret_data, str) else bytes(secret_data)
    bits = _encode_bits(secret_bytes, framing)

    indices = parse_channels(channels)
    width, height = img.size
    max_capacity = width * height * len(indices)
    if offset + len(bits) > max_capacity:
        raise ValueError(
            f"秘密信息过长（需 {len(bits)} 位，偏移 {offset}，"
            f"载体仅支持 {max_capacity} 位）")

    output_dir = os.path.dirname(os.path.abspath(output_path))
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    _write_bits(img, bits, channels, bit, offset, order)
    img.save(output_path)
    return output_path


def _channel_bytes(img, channels, order):
    """按通道与扫描顺序取出原始字节序列。

    多通道选取用扩展切片赋值（C 层）完成，避免逐像素 Python 循环。
    """
    indices = parse_channels(channels)
    need_alpha = 3 in indices
    if order == "column":
        # 列优先（先列后行）等价于「转置后按行读取」
        img = img.transpose(Image.Transpose.TRANSPOSE)
    raw = img.tobytes()
    stride = 4 if need_alpha else 3
    if indices == list(range(stride)):
        return raw, stride
    count = len(raw) // stride
    if len(indices) == 1:
        return raw[indices[0]:count * stride:stride], 1
    out = bytearray(count * len(indices))
    width = len(indices)
    for k, c in enumerate(indices):
        out[k::width] = raw[c:count * stride:stride]
    return bytes(out), width


# 位平面 -> 把字节映射成 b'0'/b'1' 的转换表（预计算，translate 为 C 层操作）
_BIT_TABLES = {
    b: bytes(0x31 if (v >> b) & 1 else 0x30 for v in range(256))
    for b in range(8)
}
# b'0'/b'1' -> 0/1
_TO01 = bytes(1 if i == 0x31 else 0 for i in range(256))
# 左移表：把 0/1 映射成 0/(1<<shift)
_SHIFT_TABLES = {
    s: bytes(0 if i == 0 else (1 << s) for i in range(256))
    for s in range(1, 8)
}


def _pack_bits(bits):
    """把 b'0'/b'1' 位串按 8 位打包成 bytes（C 层实现，避免逐位 Python 循环）。"""
    count = len(bits) // 8
    if count <= 0:
        return b""
    values = bits[:count * 8].translate(_TO01)
    acc = 0
    for k in range(8):
        shift = 7 - k
        seg = values[k::8]
        if shift:
            seg = seg.translate(_SHIFT_TABLES[shift])
        acc |= int.from_bytes(seg, "big")
    return acc.to_bytes(count, "big")


def _read_bits(img, channels, bit, offset, order, limit=None):
    """读出可写位，返回 b'0'/b'1' 组成的 bytes。

    limit 非空时最多读取 limit 位（用于自动探测，避免在超大图上做无用功）。
    """
    bit = _check_bit(bit)
    offset = _check_offset(offset)
    order = _check_order(order)
    raw, _stride = _channel_bytes(img, channels, order)
    bits = raw.translate(_BIT_TABLES[bit])  # C 层完成位提取
    if limit is not None and offset + limit < len(bits):
        return bits[offset:offset + limit]
    return bits[offset:]


def _decode_marker(bits, offset=0):
    """按结束符解码（兼容旧脚本：同时识别 FF 与 00 填充）。"""
    return _decode_marker_ex(bits, offset)[0]


# 结束符封装的扫描上限：随机数据平均每 256 字节就会撞上 0x00/0xFF，
# 因此只需扫描开头一小段即可判定有无结束符，无需处理整张图。
_MARKER_SCAN_BYTES = 64 * 1024


def _decode_marker_ex(bits, offset=0, scan_bytes=_MARKER_SCAN_BYTES):
    """按结束符解码，返回 (数据, 终止字节)。

    终止字节为 None 表示扫描窗口内未遇到结束符（基本可判定不是该封装）。
    """
    window = bits[offset:offset + scan_bytes * 8]
    packed = _pack_bits(window)
    pos_zero = packed.find(b"\x00")
    pos_ff = packed.find(b"\xff")
    candidates = [p for p in (pos_zero, pos_ff) if p >= 0]
    if not candidates:
        return packed, None
    cut = min(candidates)
    return packed[:cut], packed[cut]


def _decode_length(bits, offset=0):
    """按 32 位长度前缀解码（长度字段自带大小，故不受扫描窗口限制）。"""
    if len(bits) - offset < 32:
        return b""
    head = _pack_bits(bits[offset:offset + 32])
    if len(head) < 4:
        return b""
    length = int.from_bytes(head, "big")
    if length <= 0:
        return b""
    # 容量不足直接拒绝，无需打包
    if offset + 32 + length * 8 > len(bits):
        return b""
    return _pack_bits(bits[offset + 32:offset + 32 + length * 8])


def _decode_bytes(raw):
    """把字节按 UTF-8 解码，失败时回退逐字节（兼容旧脚本 ord 拆位）。"""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return "".join(chr(b) for b in raw)


def extract(stego_path, output_path=None, channels="RGB", bit=0, offset=0,
            order="column", framing="marker"):
    """从隐写图片提取水印文字，可选同时写入文本文件，返回提取结果。"""
    img = _load(stego_path, channels)
    bits = _read_bits(img, channels, bit, offset, order)

    if framing == "length":
        raw = _decode_length(bits)
    elif framing == "auto":
        raw = _decode_length(bits)
        if not raw:
            raw = _decode_marker(bits)
    else:
        raw = _decode_marker(bits)

    extracted = _decode_bytes(raw)

    if output_path:
        output_dir = os.path.dirname(os.path.abspath(output_path))
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(extracted)

    return extracted


# --------------------------------------------------------------------------
# 自动探测
# --------------------------------------------------------------------------
_PRINTABLE = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


# 候选结果的最小可信长度（字节）。随机数据很容易在几字节内撞上 0x00/0xFF
# 结束符，解出 1-4 个可打印字符，故短于该长度的一律不采纳
# （命中 flag/key 等关键词的除外，见 _score）。
_MIN_CANDIDATE_BYTES = 8


def _score(raw, terminated=True, framing="marker"):
    """给一段提取结果打分，越大越像真实载荷。

    误报的主要来源是「随机数据恰好早遇到 0x00/0xFF 结束符，解出几个可打印字符」，
    因此对过短结果、重复填充、以及可打印率不足的结果都要显著降分。

    framing 影响判据：
    * marker  —— 必须有结束符截断，且重复字节填充要重罚（那多半是读到了填充位）
    * length  —— 长度由前缀显式声明，重复内容是正常的（如长串 'A'），不罚重复
    """
    if not raw:
        return -1.0

    try:
        text = raw.decode("utf-8")
        decoded_ok = True
    except UnicodeDecodeError:
        text = None
        decoded_ok = False

    has_keyword = decoded_ok and any(
        k in text for k in ("flag", "FLAG", "ctf", "CTF", "key", "密码"))

    # 过短结果不可信（关键词除外）
    if len(raw) < _MIN_CANDIDATE_BYTES and not has_keyword:
        return 0.5 if terminated else -1.0

    if decoded_ok:
        total = len(text)
        printable = sum(1 for ch in text if ord(ch) in _PRINTABLE or ord(ch) > 0x7F)
        ratio = printable / total
        if ratio < 0.95:
            return 1.0 * ratio
        score = 6.0 * ratio
        if len(raw) <= 4096:
            score += 1.0
    else:
        total = len(raw)
        printable = sum(1 for b in raw if b in _PRINTABLE)
        ratio = printable / total
        if ratio < 0.95:
            return 1.0 * ratio
        score = 4.0 * ratio

    if framing == "marker":
        # 结束符封装：重复字节填充（如 wwww、UUUU）几乎都是噪声
        if len(set(raw)) <= 3 and len(raw) > 4:
            score -= 5.0
        elif len(raw) > 16 and len(set(raw)) / len(raw) < 0.02:
            score -= 3.0
        if terminated:
            score += 1.5
        else:
            score -= 4.0
    else:
        # 长度前缀封装：长度已被显式声明，只要有内容即可信
        score += 1.5

    if has_keyword:
        score += 2.0
    return score


# 自动探测时最多处理的「原始通道字节数」，等价于位串长度上限。
# 每个原始字节贡献 1 位，故 8M 对应约 1MB 载荷容量，足以覆盖 CTF 场景。
_DETECT_MAX_BITS = 8 * 1024 * 1024


def detect_params(stego_path, channels_presets=CHANNEL_PRESETS, bits=range(0, 8),
                  offsets=(0, 1, 2, 4, 8, 16, 32, 64, 128, 256),
                  orders=ORDERS, framings=("length", "marker"), limit=8,
                  min_score=4.0):
    """爆破参数组合，返回按可信度排序的候选列表。

    每个候选为 dict: {"channels","bit","offset","order","framing",
    "score","text","bytes"}。

    性能：每个 (顺序, 通道) 的原始字节只取一次并缓存，位平面用预计算转换表
    在 C 层完成；解码时不做整体切片——长度前缀按声明长度精确打包，
    结束符封装遇 0x00/0xFF 即停，因此大图与大载荷都能快速完成。
    """
    if not os.path.isfile(stego_path):
        raise FileNotFoundError(f"隐写图片不存在: {stego_path}")

    # 去重通道组合（预设里可能有重复），减少重复计算
    unique_channels = []
    seen_channels = set()
    for ch in channels_presets:
        try:
            norm = "".join(dict.fromkeys(str(ch).upper()))
            parse_channels(norm)
        except ValueError:
            continue
        if norm in seen_channels:
            continue
        seen_channels.add(norm)
        unique_channels.append(norm)

    raw_cache = {}
    results = []
    for order in orders:
        for channels in unique_channels:
            need_alpha = 3 in parse_channels(channels)
            # 缓存键必须包含具体通道组合，否则 "B" 会复用 "RGB" 的字节流
            key = (order, channels, "RGBA" if need_alpha else "RGB")
            if key not in raw_cache:
                with Image.open(stego_path) as src:
                    img = src.convert(key[2])
                raw_cache[key] = _channel_bytes(img, channels, order)[0]
            raw = raw_cache[key]
            # 每个通道字节经 translate 后只产出 1 个位，故位长等于字节数
            if len(raw) > _DETECT_MAX_BITS:
                raw = raw[:_DETECT_MAX_BITS]

            for bit in bits:
                # 位平面在 C 层提取一次，之后只做有界切片与打包：
                # 结束符封装只扫描开头一小段，长度前缀封装按声明长度打包
                full = raw.translate(_BIT_TABLES[bit])
                if len(full) > _DETECT_MAX_BITS:
                    full = full[:_DETECT_MAX_BITS]

                for offset in offsets:
                    if offset >= len(full):
                        continue
                    for framing in framings:
                        if framing == "length":
                            raw_bytes = _decode_length(full, offset)
                            terminated = bool(raw_bytes)
                        else:
                            raw_bytes, term = _decode_marker_ex(full, offset)
                            terminated = term is not None
                        if not raw_bytes:
                            continue
                        sc = _score(raw_bytes, terminated, framing)
                        if sc < min_score:
                            continue
                        results.append({
                            "channels": channels,
                            "bit": int(bit),
                            "offset": int(offset),
                            "order": order,
                            "framing": framing,
                            "score": round(sc, 2),
                            "bytes": len(raw_bytes),
                            "text": _decode_bytes(raw_bytes),
                        })
    results.sort(key=lambda item: (-item["score"], item["offset"], item["bit"]))
    # 去掉完全重复的文本，保留最高分
    unique = []
    seen = set()
    for item in results:
        sig = (item["text"], item["channels"], item["bit"], item["offset"],
               item["order"], item["framing"])
        if sig in seen:
            continue
        seen.add(sig)
        unique.append(item)
        if len(unique) >= limit:
            break
    return unique


def describe_params(channels="RGB", bit=0, offset=0, order="column",
                    framing="marker"):
    """把参数格式化成一行中文描述，便于日志展示。"""
    return (f"通道={channels}，位平面={bit}，偏移={offset}，"
            f"顺序={ORDER_NAMES.get(order, order)}，"
            f"封装={FRAMING_NAMES.get(framing, framing)}")
