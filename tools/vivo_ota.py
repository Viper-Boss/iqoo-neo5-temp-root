#!/usr/bin/env python3
"""
Vivo/iQOO 全机型 OTA 固件下载器
================================
Complete Vivo/iQOO OTA Firmware Downloader

一键下载任意 vivo/iQOO 机型的全量固件包，无需 root、无需解锁。

功能:
  1. 查询任意 vivo/iQOO 机型的固件下载 URL
  2. 直接从 vivo CDN 下载（速度可达 110MB/s）
  3. 解密/加密 OTA 协议（jvq 1.0.3 替换密码 + base64）
  4. 为新机型破解字母表（已知明文攻击）

用法:
  python3 vivo_ota.py list                          # 列出已知机型
  python3 vivo_ota.py query PD2055 V2055A 9.10.3   # 查询固件
  python3 vivo_ota.py download <url> firmware.zip   # 下载固件
  python3 vivo_ota.py crack                          # 新机型破解指南
  python3 vivo_ota.py decode <encrypted>             # 解密
  python3 vivo_ota.py encode <plaintext>             # 加密

License: GPLv3
Author: Viper-Boss
"""

import sys, os, json, urllib.request, urllib.error, string

# ============================================================
# 第一步：破解后的完整字母表（60 个已验证符号 → 6-bit 值）
# ============================================================
# 破解方法：已知明文攻击
# 
# vivo 的 jvq 1.0.3 "加密" = 字符替换密码 + 标准 base64
# 它不是真正的密码学加密，只是一个固定的字符映射表。
#
# 以下映射通过对 PD2055_A_9.10.3 的 OTA 请求进行已知明文攻击获得，
# 并通过 decode → encode roundtrip 验证 100% 正确。
#
# 如何为新机型破解（如果此表不适用）：
#   1. 让手机进 recovery → 选择"联网更新"
#   2. adb bugreport → 提取 FS/cache/recovery/last_log
#   3. 日志中有 "param=<加密串>&jvq=1.0.3"
#   4. 加密串中必定包含已知明文（型号、版本号等）
#   5. 用已知明文推导每个符号的 6-bit 值
#   6. 验证：encode(decode(x)) == x
#
# 详见本文件末尾的 crack_for_device() 和 scripts/ 目录。

ALPHABET = {
    # value: symbol  (这是从密文分析中逆向出来的映射)
    # 字母表按 value 排序
    'Q': 0,  # value 0x00
    '8': 1,  # value 0x01
    'v': 2,  # value 0x02
    'N': 3,  # value 0x03
    '-': 4,  # value 0x04
    'r': 5,  # value 0x05
    'y': 6,  # value 0x06
    'a': 7,  # value 0x07
    'E': 8,  # value 0x08
    'J': 9,  # value 0x09
    'G': 10, # value 0x0a
    'o': 11, # value 0x0b
    'T': 12, # value 0x0c
    'W': 13, # value 0x0d
    'O': 14, # value 0x0e
    't': 15, # value 0x0f
    'K': 16, # value 0x10
    '_': 17, # value 0x11
    'q': 18, # value 0x12
    'M': 19, # value 0x13
    'k': 20, # value 0x14
    'h': 21, # value 0x15
    '5': 22, # value 0x16
    'R': 23, # value 0x17
    'Z': 24, # value 0x18
    '6': 25, # value 0x19
    'L': 26, # value 0x1a
    'x': 27, # value 0x1b
    'c': 28, # value 0x1c
    'U': 29, # value 0x1d
    'A': 30, # value 0x1e
    '3': 31, # value 0x1f
    'd': 32, # value 0x20
    'n': 33, # value 0x21
    'z': 34, # value 0x22
    'e': 35, # value 0x23
    'H': 36, # value 0x24
    'u': 37, # value 0x25
    '2': 38, # value 0x26
    'X': 39, # value 0x27
    'j': 40, # value 0x28
    'S': 41, # value 0x29
    'F': 45, # value 0x2d
    'Y': 46, # value 0x2e
    'w': 47, # value 0x2f
    'f': 48, # value 0x30
    'P': 49, # value 0x31
    'D': 50, # value 0x32
    '9': 51, # value 0x33
    '4': 52, # value 0x34
    'C': 53, # value 0x35
    '0': 54, # value 0x36
    'l': 55, # value 0x37
    'm': 56, # value 0x38
    '1': 57, # value 0x39
    'I': 58, # value 0x3a
    'V': 59, # value 0x3b
    '7': 60, # value 0x3c
    'g': 61, # value 0x3d
    's': 62, # value 0x3e
}
# 注意：值 42(0x2a), 43(0x2b), 44(0x2c), 63(0x3f) 未在此固件中出现过。
# 如果你的请求/响应中遇到未知符号，需要用已知明文攻击补全。


# ============================================================
# 第二步：解密算法（核心！）
# ============================================================
# 
# vivo OTA 协议的编码方式：
#   明文 → 按 8-bit 分组 → 每 6-bit 映射到一个替换字符
#
# 解码公式（与标准 base64 相同，但字符映射不同）：
#   4 个 6-bit 值 (v0, v1, v2, v3) → 3 个字节:
#     byte0 = (v0 << 2) | (v1 >> 4)
#     byte1 = ((v1 & 0xF) << 4) | (v2 >> 2)
#     byte2 = ((v2 & 0x3) << 6) | v3      ← 注意是 <<6 不是 <<4 !!!
#
# ⚠️ 常见错误：byte2 用 <<4 会导致结果微妙地错误，很难 debug！
# 我花了 3 个小时才找到这个 bug。标准 base64 的第三个字节就是 <<6。

def decode(encrypted: str, alphabet: dict = None) -> bytes:
    """
    解密 vivo OTA 协议字符串。
    
    参数:
        encrypted: 加密的字符串（param= 或响应内容）
        alphabet:  字符映射表（默认使用已破解的 ALPHABET）
    
    返回:
        解密后的 bytes（通常是 JSON 或 URL 参数）
    """
    if alphabet is None:
        alphabet = ALPHABET
    
    # 将每个字符转换为 6-bit 值
    vals = []
    for ch in encrypted:
        v = alphabet.get(ch)
        if v is None:
            continue  # 跳过未知字符（填充等）
        vals.append(v)
    
    # 每 4 个 6-bit 值 → 3 个字节
    out = []
    for i in range(0, len(vals) - 3, 4):
        v0, v1, v2, v3 = vals[i:i+4]
        out.append((v0 << 2) | (v1 >> 4))
        out.append(((v1 & 0xF) << 4) | (v2 >> 2))
        out.append(((v2 & 0x3) << 6) | v3)  # ← <<6 !!! 不是 <<4 !!!
    
    # 处理尾部（不满 4 个的情况）
    r = len(vals) % 4
    if r == 2:
        out.append((vals[-2] << 2) | (vals[-1] >> 4))
    elif r == 3:
        out.append((vals[-3] << 2) | (vals[-2] >> 4))
        out.append(((vals[-2] & 0xF) << 4) | (vals[-1] >> 2))
    
    return bytes(out)


# ============================================================
# 第三步：加密算法（用于构造请求）
# ============================================================

def encode(plaintext: bytes, alphabet: dict = None) -> str:
    """
    加密明文为 vivo OTA 协议格式。
    
    用于构造发送到 vivo 服务器的请求。
    """
    if alphabet is None:
        alphabet = ALPHABET
    inv = {v: k for k, v in alphabet.items()}
    
    # 将字节流转换为 bit 流
    bits = []
    for b in plaintext:
        bits.extend([
            (b >> 7) & 1, (b >> 6) & 1, (b >> 5) & 1, (b >> 4) & 1,
            (b >> 3) & 1, (b >> 2) & 1, (b >> 1) & 1, b & 1
        ])
    
    # 补齐到 6 的倍数
    while len(bits) % 6:
        bits.append(0)
    
    # 每 6-bit 映射到一个替换字符
    out = []
    for i in range(0, len(bits), 6):
        v = 0
        for k in range(6):
            v = (v << 1) | bits[i + k]
        out.append(inv.get(v, 'Q'))  # 未知值默认用 value 0
    
    return ''.join(out)


def verify_roundtrip(encrypted: str, alphabet: dict = None) -> bool:
    """验证：decode 后再 encode 应该得到原始密文"""
    decoded = decode(encrypted, alphabet)
    re_encoded = encode(decoded, alphabet)
    return re_encoded == encrypted


# ============================================================
# 第四步：构造 OTA 请求并发送到 vivo 服务器
# ============================================================

def build_request(model: str, device: str, version: str,
                  imei: str = "0" * 64) -> str:
    """
    构造 OTA 查询请求的明文参数。
    
    参数:
        model:   设备代号 (如 "PD2055")
        device:  公开型号 (如 "V2055A") 
        version: 固件版本 (如 "9.10.3")
        imei:    IMEI 哈希 (EOL 设备通常可以用全零)
    
    返回:
        明文请求字符串（需加密后发送）
    """
    hw = f"{model}MA"  # 硬件版本号规律: 型号 + "MA"
    
    request = (
        f"model={model}&"
        f"hardware={hw}&"
        f"version={model}_N_{hw}_{version}&"
        f"oem={model}D_CN-ZH_FULL_SC_NULL&"
        f"sdkVersion=34&"
        f"imei={imei}&"
        f"emmcid=<REDACTED_EMMCID>&"
        f"oemVersion=N&custom=N&gn=0&"
        f"oemProjects={model}+{model}B+{model}C,{model}D+{model}E+{model}F,{model}G&"
        f"vgcCu=NULL&hasVgc=0&countryRegion=CN-ZH&vgcSwVer=null&"
        f"pver=1&jvq_type=0&errType=0&errVersion=&"
        f"upsreason=&fbereason="
    )
    return request


def query_ota(model: str, device: str, version: str) -> dict:
    """
    向 vivo OTA 服务器查询固件下载 URL。
    
    这是一个完整的端到端操作：
    1. 构造明文请求
    2. 加密
    3. POST 到 vivo 服务器
    4. 解密响应
    5. 返回包含下载 URL 的 JSON
    
    适用于所有使用 jvq 1.0.3 协议的 vivo/iQOO 设备。
    """
    # 构造并加密请求
    plaintext = build_request(model, device, version)
    encrypted = encode(plaintext.encode())
    
    # 发送 POST 请求
    url = "https://sysupgrade.vivo.com.cn/api2"
    body = f"param={encrypted}&jvq=1.0.3"
    
    req = urllib.request.Request(
        url,
        data=body.encode(),
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Wget/1.20",
        },
        method="POST"
    )
    
    try:
        resp = urllib.request.urlopen(req, timeout=30)
        encrypted_response = resp.read().decode()
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}"}
    except Exception as e:
        return {"error": str(e)}
    
    # 解密响应
    try:
        response_bytes = decode(encrypted_response)
        response_text = response_bytes.decode('utf-8', errors='replace')
        return json.loads(response_text)
    except json.JSONDecodeError:
        # 响应可能不是完整 JSON（部分符号未破解）
        return {"raw": response_text, "note": "partial decode - see crack guide"}
    except Exception as e:
        return {"error": f"Decode failed: {e}"}


def download_firmware(url: str, output: str):
    """从 vivo CDN 下载固件（直连，可达 110MB/s）"""
    print(f"[*] URL: {url[:80]}...")
    req = urllib.request.Request(url, headers={"User-Agent": "Wget/1.20"})
    resp = urllib.request.urlopen(req, timeout=60)
    
    total = int(resp.headers.get('Content-Length', 0))
    downloaded = 0
    chunk = 1024 * 1024  # 1MB
    
    with open(output, 'wb') as f:
        while True:
            data = resp.read(chunk)
            if not data:
                break
            f.write(data)
            downloaded += len(data)
            if total > 0:
                print(f"\r  {downloaded/1024/1024:.0f}/{total/1024/1024:.0f} MB ({downloaded/total*100:.1f}%)",
                      end='', flush=True)
    
    print(f"\n[+] 已保存: {output} ({downloaded/1024/1024:.0f} MB)")


# ============================================================
# 第五步：如何为新机型破解（完整教程）
# ============================================================

CRACK_GUIDE = """
╔══════════════════════════════════════════════════════════════════╗
║        如何为新机型破解 vivo OTA 协议 (jvq 1.0.3)              ║
║        How to crack vivo OTA protocol for a new device          ║
╚══════════════════════════════════════════════════════════════════╝

如果上面的 ALPHABET 对你的设备不适用（返回乱码或空结果），
按以下步骤破解你自己的字母表：

步骤 1：获取密文
─────────────────
  a. 让手机进入 recovery 模式
     方法: adb reboot recovery
           或者: 关机后按 音量上+电源键

  b. 在 recovery 菜单中选择「联网更新」或「安装系统软件→联网更新」
     这会让 recovery 向 vivo 服务器发送加密请求

  c. 等待几秒后重启回系统，然后:
     adb bugreport

  d. 在 bugreport zip 中找到:
     FS/cache/recovery/last_log

  e. 在日志中搜索 "param=" — 后面跟着的 606 字符就是加密的请求

步骤 2：已知明文
─────────────────
  加密前的明文请求中必定包含以下已知字符串:
  - "model=PDxxxx"        (你的设备代号，如 model=PD2055)
  - "PDxxxxD_A_x.x.x"     (完整版本号，如 PD2055D_A_9.10.3)
  - "PDxxxxMA"            (硬件版本，如 PD2055MA)
  - "&hardware="          (字段名，固定不变)
  - "&version="           (字段名)
  - "&imei="              (字段名)

  设备代号在 设置→关于手机 中可以查到。

步骤 3：推导字母表
─────────────────
  原理: 密文中的每个字符对应一个 6-bit 值 (0-63)。
  如果你知道明文的某个字节，就能推导出产生它的 6-bit 值。

  方法:
  1. 将已知明文（如 "model=PD2055"）在密文中滑动尝试每个位置
  2. 在每个位置，用已知明文的字节推导密文字符的 6-bit 值
  3. 收集所有一致的推导结果
  4. 用爬山算法优化剩余未知符号
  5. 验证: encode(decode(ciphertext)) == ciphertext

  完整攻击脚本: scripts/ota_known_plaintext_attack.py
  爬山算法: scripts/ota_hill_climb.py
  CP-SAT 求解器: scripts/ota_cpsat_solver.py

步骤 4：关键公式
─────────────────
  解码时第三个字节:
    b2 = ((v2 & 0x3) << 6) | v3     ← 正确! <<6
    b2 = ((v2 & 0x3) << 4) | v3     ← 错误! 会导致微妙错误

  这是我在破解过程中踩的最大坑，花了 3 小时才找到。
  如果你的解密结果"看起来差不多但有些字符不对"，
  99% 是这个 <<6 vs <<4 的问题。

步骤 5：查询固件
─────────────────
  拿到字母表后:
  python3 vivo_ota.py query <你的型号> <V型号> <版本号>
  
  例如:
  python3 vivo_ota.py query PD2055 V2055A 9.10.3
  python3 vivo_ota.py query PD2408 V2408A 16.1.16.5.W10
  python3 vivo_ota.py query PD2196 V2196A 12.0.9.6.W10

常见问题
─────────
  Q: 服务器返回 retcode=210 "无更新"
  A: 该版本可能不在升级路线上。试试更低的版本号。
     EOL 设备（已停产）可能需要特殊处理。

  Q: 解密结果有乱码
  A: 字母表不完整（缺少 4 个值: 42, 43, 44, 63）。
     用已知明文攻击补全，或用原始密文直接重放（见 tools/test_replay.py）

  Q: 查询其他机型返回空
  A: 可能需要该机型的真实 IMEI。从 bugreport 的 last_ota_info 中获取。
"""


# ============================================================
# 已验证的固件直链
# ============================================================

VERIFIED_URLS = {
    "PD2055_A_9.10.3 (iQOO Neo5, final EOL)": {
        "url": "http://sysupgrade.vivo.com.cn/dapi2.do?fileName=%40a160970%3D1Wb74zZnMyZkEQMylyN9YS0gMdN46HMkYHYggQN4FiZ9USMPFQM8DyMwZSN8FSMz1XN90",
        "size": "7,039,074,100 bytes (6.56 GB)",
        "sha256": "<REDACTED_EMMCID> (server-reported)",
        "kernel": "4.19.152-perf+",
        "android": "14 (OriginOS 4)",
    },
}


# ============================================================
# CLI 入口
# ============================================================

KNOWN_MODELS = {
    # 常见 vivo/iQOO 机型参考（型号→设备代号映射）
    "iQOO Neo5":       ("PD2055", "V2055A"),
    "iQOO Neo5S":      ("PD2154", "V2154A"),
    "iQOO Neo5 SE":    ("PD2157", "V2157A"),
    "iQOO Neo6":       ("PD2196", "V2196A"),
    "iQOO Neo6 SE":    ("PD2199", "V2199A"),
    "iQOO Neo7":       ("PD2231", "V2231A"),
    "iQOO Neo7 Pro":   ("PD2243", "V2243A"),
    "iQOO Neo8":       ("PD2311", "V2311A"),
    "iQOO Neo8 Pro":   ("PD2312", "V2312A"),
    "iQOO Neo9":       ("PD2346", "V2346A"),
    "iQOO Neo9 Pro":   ("PD2347", "V2347A"),
    "iQOO Neo9s Pro":  ("PD2392", "V2392A"),
    "iQOO Neo10 Pro":  ("PD2419", "V2419A"),
    "iQOO 5":          ("PD2012", "V2012A"),
    "iQOO 7":          ("PD2055F", "V2055A"),
    "iQOO 8":          ("PD2136", "V2136A"),
    "iQOO 9":          ("PD2171", "V2171A"),
    "iQOO 10":         ("PD2214", "V2214A"),
    "iQOO 11":         ("PD2247", "V2247A"),
    "iQOO 12":         ("PD2319", "V2319A"),
    "iQOO 13":         ("PD2415", "V2415A"),
    "vivo X60":        ("PD2059", "V2059A"),
    "vivo X70":        ("PD2155", "V2155A"),
    "vivo X80":        ("PD2181", "V2181A"),
    "vivo X90":        ("PD2237", "V2237A"),
    "vivo X100":       ("PD2321", "V2321A"),
    "vivo X200":       ("PD2408", "V2408A"),
    "vivo X200 Pro":   ("PD2409", "V2409A"),
    "vivo X200s":      ("PD2415", "V2415A"),
}


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        print("\n" + "=" * 60)
        print("命令 / COMMANDS")
        print("=" * 60)
        print(f"  list                    — 列出已知机型")
        print(f"  query <model> <device> <version> — 查询固件URL")
        print(f"  download <url> <file>   — 下载固件")
        print(f"  decode <encrypted>      — 解密字符串")
        print(f"  encode <plaintext>      — 加密字符串")
        print(f"  crack                   — 新机型破解教程")
        print(f"  urls                    — 已验证的固件直链")
        print()
        print("快速开始 / Quick start:")
        print(f"  python3 {sys.argv[0]} query PD2055 V2055A 9.10.3")
        print(f"  python3 {sys.argv[0]} list")
        print(f"  python3 {sys.argv[0]} crack")
        sys.exit(0)
    
    cmd = sys.argv[1]
    
    if cmd == "list":
        print("\n已知机型 / Known Models:")
        print("-" * 50)
        for name, (pd, v) in sorted(KNOWN_MODELS.items()):
            print(f"  {name:20s}  {pd:10s}  {v}")
        print(f"\n共 {len(KNOWN_MODELS)} 个机型")
        print("查询: python3 vivo_ota.py query <PD代号> <V型号> <版本>")
    
    elif cmd == "query":
        if len(sys.argv) < 5:
            print("用法: query <model> <device> <version>")
            print("  model:   PD代号 (如 PD2055)")
            print("  device:  V型号 (如 V2055A)")
            print("  version: 固件版本 (如 9.10.3)")
            print("\n查已知机型: python3 vivo_ota.py list")
            sys.exit(1)
        model, device, version = sys.argv[2], sys.argv[3], sys.argv[4]
        print(f"[*] 查询: {model} / {device} / {version}")
        print(f"[*] 服务器: https://sysupgrade.vivo.com.cn/api2\n")
        result = query_ota(model, device, version)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        if 'url' in result:
            print(f"\n[+] 下载URL: {result['url']}")
            print(f"[+] 文件大小: {result.get('fileLength', '?')} bytes")
            print(f"\n下载: python3 {sys.argv[0]} download '{result['url']}' firmware.zip")
        elif result.get('retcode') == 210:
            print("\n[-] 服务器返回 '无更新' — 该版本可能不在升级路线上")
            print("    试试更低的版本号，或用 crack 模式获取该机型的正确参数")
    
    elif cmd == "download":
        if len(sys.argv) < 4:
            print("用法: download <url> <output_file>")
            sys.exit(1)
        download_firmware(sys.argv[2], sys.argv[3])
    
    elif cmd == "decode":
        if len(sys.argv) < 3:
            print("用法: decode <encrypted_string>")
            sys.exit(1)
        result = decode(sys.argv[2])
        print(result.decode('utf-8', errors='replace'))
        ok = verify_roundtrip(sys.argv[2])
        print(f"\n[{'+' if ok else '-'}] Roundtrip验证: {'通过' if ok else '失败'}", file=sys.stderr)
    
    elif cmd == "encode":
        if len(sys.argv) < 3:
            print("用法: encode <plaintext>")
            sys.exit(1)
        result = encode(sys.argv[2].encode())
        print(result)
    
    elif cmd == "crack":
        print(CRACK_GUIDE)
    
    elif cmd == "urls":
        print("\n已验证的固件直链 / Verified firmware URLs:")
        print("-" * 60)
        for name, info in VERIFIED_URLS.items():
            print(f"\n  {name}")
            print(f"  URL: {info['url']}")
            print(f"  大小: {info['size']}")
            print(f"  内核: {info['kernel']}")
            print(f"  系统: {info['android']}")
            print(f"  下载: python3 {sys.argv[0]} download '{info['url']}' {name.split()[0]}.zip")
    
    else:
        print(f"未知命令: {cmd}")
        sys.exit(1)


if __name__ == '__main__':
    main()
