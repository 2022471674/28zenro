# -*- coding: utf-8 -*-
"""lib 包：密码 / 编码方法的纯逻辑层。

本包内所有模块只负责「字符串进、字符串出」的编解码与哈希计算，
禁止导入 tkinter 等任何 UI 模块，从而与界面完全解耦。

对外暴露：
    base_codec          Base 系列编解码纯函数
    rot_codec           ROT 系列移位纯函数
    hash_codec          哈希摘要纯函数
    number_base_codec   2~16 进制互转纯函数
    string_codec        字符串编码工具纯函数（URL / ASCII / JWT / 大小写 / 字数统计）
    jwt_codec           JWT 纯逻辑（解析 / 校验 / 创建，HS·RS·ES·none 全算法）
    translate_codec     中英互译纯函数（OpenAI 兼容 /chat/completions）
    llm_codec           大模型接口纯逻辑（OpenAI 兼容 models / chat / embeddings）
    pomodoro            番茄时钟纯逻辑（专注 / 休息阶段状态机）
    key_simulator       键盘输入模拟模块（把英文字母快速连续注入焦点窗口）
    md5_crash           MD5 爆破模块（排列枚举 + 多进程 / 多线程，含参数校验与主控）
    watermark           图片水印模块（可见水印添加 + LSB 隐写嵌入 / 提取）
    image_codec         图片编解码模块（图片文件 -> Base64 文本）
    jsfinder            JSFinder 模块（从页面与其 JS 提取 URL / 子域名）
    web_fuzz            Web Fuzz 模块（URL 一次抓全页面 / 主机信息，走代理池）
    httpscan            httpscan 模块（CIDR 网段 Web 主机发现）
    fingerprint         指纹探测模块（observer_ward 风格指纹规则匹配，走代理池）
    lan_share           局域网文件共享（HTTP 服务端 + 4 位密码频道 + 客户端）
    leak_scan           源码泄露检测（.git / .svn / .DS_Store 三合一）
    dir_scan            目录爆破（读取 dict/Contents 全部字典逐条探测路径）
    port_scan           端口爆破（代理池轮换，封禁即换代理；纯标准库 SOCKS5/HTTP）
    mysql_brute         MySQL 用户名/密码爆破（纯标准库 MySQL 协议）
    zip_cracker         ZIP 压缩包工具（伪加密修复 / CRC32 碰撞 / 字典爆破）
    ping_probe          多地 Ping（接口盒子 apihz.cn 免费 API，多节点 ICMP 延迟检测）
    proxy_pool          全局代理池（免费代理源拉取 / 验证 / 轮换，供 Web 工具共享）
    file_hex_codec      文件 ↔ 十六进制文本互转
    http_requester      HTTP 请求器（类 Burp Repeater/Intruder，不抓包）
    crypto_interface    密码学循环接口（把密码学工具收成请求器的载荷生成器）
"""

from . import (
    base_codec,
    char_codec,
    dir_scan,
    esolang,
    file_hex_codec,
    hash_codec,
    hash_ext,
    hostsearch,
    httpscan,
    image_codec,
    jwt_codec,
    jsfinder,
    key_simulator,
    lan_share,
    leak_scan,
    llm_codec,
    md5_crash,
    mysql_brute,
    number_base_codec,
    ping_probe,
    pomodoro,
    port_scan,
    proxy_pool,
    rot_codec,
    rsa_attack,
    ssti_finder,
    string_codec,
    translate_codec,
    watermark,
    web_fuzz,
    wechat_check,
    zip_cracker,
    fingerprint,
    gensh_wallpapper,
)

__all__ = [
    "base_codec",
    "char_codec",
    "rot_codec",
    "hash_codec",
    "file_hex_codec",
    "hostsearch",
    "number_base_codec",
    "string_codec",
    "esolang",
    "hash_ext",
    "translate_codec",
    "llm_codec",
    "key_simulator",
    "md5_crash",
    "pomodoro",
    "watermark",
    "image_codec",
    "jwt_codec",
    "jsfinder",
    "httpscan",
    "lan_share",
    "leak_scan",
    "dir_scan",
    "port_scan",
    "mysql_brute",
    "ping_probe",
    "proxy_pool",
    "ssti_finder",
    "zip_cracker",
    "wechat_check",
    "web_fuzz",
    "rsa_attack",
    "fingerprint",
    "gensh_wallpapper"
]
