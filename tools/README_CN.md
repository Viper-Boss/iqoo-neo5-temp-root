# Vivo OTA 协议破解工具 / Vivo OTA Protocol Cracking Tool
# vivo 旧版 OTA 协议（jvq 1.0.3）完整解密器/加密器
# 可用于下载任意 vivo/iQOO 机型的全量固件包

这个工具可以：
1. **解密** OTA 请求参数和服务器响应（获取下载 URL）
2. **加密** 任意明文为协议格式（伪造请求查询其他机型/版本）
3. **查询** vivo OTA 服务器获取任意机型的固件下载链接
4. **下载** 固件包（全量 ROM）

## 快速开始

```bash
# 查询任意机型的固件下载 URL
python3 tools/vivo_ota_full.py query PD2055 V2055A 9.10.3

# 查询其他机型（例如 PD2408）
python3 tools/vivo_ota_full.py query PD2408 V2408A 16.1.16.5.W10

# 解密一个已捕获的加密响应
python3 tools/vivo_ota_full.py decode <encrypted_string>

# 下载固件
python3 tools/vivo_ota_full.py download <url> firmware.zip
```

## 协议原理

vivo 旧版 OTA 协议（jvq 1.0.3）的"加密"**不是真正的密码学加密**——它是一个**替换密码套在标准 base64 外面**。

```
明文 → 标准 base64 → 字符替换（每个 base64 字符映射到另一个字符）
```

这意味着只要拿到 64 个符号的映射表（字母表），就可以完全双向转换。

### 关键 bug 提醒

标准 base64 解码的第三个字节公式是：
```python
b2 = ((v2 & 0x3) << 6) | v3    # ✅ 正确
b2 = ((v2 & 0x3) << 4) | v3    # ❌ 错误（常见 bug！）
```

`<<4` 会产生微妙但完全错误的结果。这个 bug 花了我几个小时才找到。

## 如何为新设备破解字母表

如果字母表不匹配你的设备（不同固件版本可能有不同映射），用以下方法：

### 方法：已知明文攻击

1. **获取密文**：在 recovery 模式下触发"联网更新"，然后 `adb bugreport` 从 `FS/cache/recovery/last_log` 提取 `param=<encrypted>`

2. **已知明文**：请求中必定包含：
   - `model=PDxxxx`（设备型号）
   - `PDxxxxD_A_x.x.x`（完整版本号）
   - `PDxxxxMA`（硬件版本）
   - IMEI 哈希（64 位十六进制字符串）

3. **推导**：将已知明文与密文对齐，逐字符推导 6-bit 值

4. **验证**：`encode(decode(ciphertext)) == ciphertext` 必须为 True

完整攻击脚本见 `scripts/ota_known_plaintext_attack.py`

### 为什么有效

- 请求明文中包含大量已知结构（`model=`, `&`, `=`, `_`, `.`, 数字等）
- IMEI 哈希是 64 个十六进制字符，是极强的锚点
- base64 的 mod-4 对齐特性可以用来验证候选位置

## 请求格式（明文）

```
model=PD2055&hardware=PD2055MA&version=PD2055_N_PD2055MA_9.10.3
&oem=PD2055D_CN-ZH_FULL_SC_NULL&sdkVersion=34
&imei=<hash>&emmcid=<hex>
&oemVersion=N&custom=N&gn=0
&oemProjects=PD2055+PD2055B+PD2055C,PD2055D+PD2055E+PD2055F,PD2055G
&vgcCu=NULL&hasVgc=0&countryRegion=CN-ZH&vgcSwVer=null
&pver=1&jvq_type=0&errType=0&errVersion=&upsreason=&fbereason=
```

## 响应格式（解密后）

```json
{
  "fileLength": "7039074100",
  "version": "9.10.3",
  "url": "http://sysupgrade.vivo.com.cn/dapi2.do?fileName=%40...",
  "up.model": "PD2055",
  "up.version": "PD2055_N_PD2055MA_9.10.3",
  "up.imei": "...",
  "up.emmcid": "...",
  "checkString": ""
}
```

`url` 字段就是**固件的直接下载链接**（从 vivo CDN 直连下载，速度可达 110MB/s）。

## 注意事项

- 对于 EOL（生命周期结束）的机型，服务器可能返回 `无更新`（retcode 210）
- 全量包 URL 可能有有效期，建议获取后立即下载
- 下载链接走 HTTP（不是 HTTPS），但文件有 SHA256 校验
- 某些机型可能需要正确的 IMEI 才能查询（EOL 机型通常不需要）

## 许可证

GPLv3 — 见主仓库 LICENSE 文件
