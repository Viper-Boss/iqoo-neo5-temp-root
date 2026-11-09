# 02 - vivo OTA 协议分析 / OTA Protocol Analysis

> **文档状态**: ✅ 已完成  
> **最后更新**: 2026-11-09  
> **作者**: Viper-Boss

---

## 概述

vivo/iQOO 设备的 OTA 更新使用自定义协议（`jvq=1.0.3`），请求和响应都经过"加密"。本章节记录该协议的完整破解过程，包括：

- 协议结构发现
- 加密机制分析（替换密码 + base64）
- 已知明文攻击方法
- 约束求解（CP-SAT）
- 关键 bug 修复（`<<6` vs `<<4`）
- 最终字母表验证
- 工具使用

**结论**: 该"加密"实际上是**替换密码套在标准 base64 外面**，不是真正的密码学加密。只要获得字母表映射，就可以完全双向转换。

---

## 协议发现

### 触发 OTA 请求

1. 重启设备进入 recovery 模式
2. 选择"联网更新"（online update）
3. Recovery 向 vivo 服务器发送加密请求
4. 通过 `adb bugreport` 提取 recovery 日志

### 日志内容

```
FS/cache/recovery/last_log:
  wget --post-data 'param=<encrypted>&jvq=1.0.3' \
       https://sysupgrade.vivo.com.cn/api2
```

请求体包含两个参数：
- `param`: 加密的查询参数（606 字符）
- `jvq`: 协议版本（1.0.3）

### 响应格式

服务器返回加密的 JSON 响应（666 字符），包含：
- `fileLength`: 固件大小
- `version`: 固件版本
- `url`: 下载链接
- `up.imei`: 设备 IMEI 哈希
- `up.emmcid`: 设备存储 ID
- `checkString`: 完整性校验（通常为空）

---

## 加密机制分析

### 第一步：结构分析

观察密文特征：
- 字符集：64 个不同符号（大小写字母 + 数字 + `-` + `_`）
- 重复子串间距：全部 ≡ 0 (mod 4)

**推断**: 这是 base64 类编码（重复子串只在 mod-4 边界保持对齐）。

### 第二步：标准 base64 对比

标准 base64 解码公式：
```python
# 4 个 6-bit 值 (v0, v1, v2, v3) → 3 个字节
byte0 = (v0 << 2) | (v1 >> 4)
byte1 = ((v1 & 0xF) << 4) | (v2 >> 2)
byte2 = ((v2 & 0x3) << 6) | v3   # ← 注意是 <<6
```

**关键 bug**: 早期版本错误地使用 `<<4` 而非 `<<6`，导致第三个字节解码错误。这个 bug 花了 3 小时才发现。

### 第三步：替换密码

标准 base64 字母表：
```
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_
```

vivo 协议使用**自定义字母表**（64 个符号的置换），需要先破解映射关系。

---

## 已知明文攻击

### 已知明文来源

请求中必定包含以下已知字符串：
- `model=PD2055`（设备型号）
- `PD2055D_A_9.10.3`（完整版本号）
- `PD2055MA`（硬件版本）
- IMEI 哈希（64 位十六进制，从 bugreport 提取）
- 字段名（`&hardware=`, `&version=`, `&imei=` 等）

### 攻击方法

1. **锚点定位**: 将已知明文在密文中滑动，尝试每个位置
2. **符号推导**: 在每个位置，用已知明文的字节推导密文字符的 6-bit 值
3. **一致性检查**: 收集所有一致的推导结果
4. **约束求解**: 用 CP-SAT 求解剩余未知符号的双射约束
5. **爬山优化**: 对残余错误进行局部优化
6. **重编码验证**: `encode(decode(ciphertext)) == ciphertext`

### 工具链

| 阶段 | 脚本 | 位置 |
|------|------|------|
| 结构分析 | `try_decode.py` | `research/archive/01_ota_protocol/` |
| 锚点攻击 | `anchor_attack.py` | `scripts/legacy/` |
| CP-SAT 求解 | `cpsat_solve.py` | `scripts/legacy/` |
| 爬山优化 | `final2.py` | `scripts/legacy/` |
| 重编码验证 | `reencode_test.py` | `scripts/legacy/` |
| 完整工具 | `vivo_ota.py` | `tools/` |

---

## 最终字母表

破解后的字母表（60 个已验证符号，4 个未出现）：

```python
ALPHABET = {
    'Q': 0,  '8': 1,  'v': 2,  'N': 3,  '-': 4,  'r': 5,
    'y': 6,  'a': 7,  'E': 8,  'J': 9,  'G': 10, 'o': 11,
    'T': 12, 'W': 13, 'O': 14, 't': 15, 'K': 16, '_': 17,
    'q': 18, 'M': 19, 'k': 20, 'h': 21, '5': 22, 'R': 23,
    'Z': 24, '6': 25, 'L': 26, 'x': 27, 'c': 28, 'U': 29,
    'A': 30, '3': 31, 'd': 32, 'n': 33, 'z': 34, 'e': 35,
    'H': 36, 'u': 37, '2': 38, 'X': 39, 'j': 40, 'S': 41,
    'F': 45, 'Y': 46, 'w': 47, 'f': 48, 'P': 49, 'D': 50,
    '9': 51, '4': 52, 'C': 53, '0': 54, 'l': 55, 'm': 56,
    '1': 57, 'I': 58, 'V': 59, '7': 60, 'g': 61, 's': 62,
}
```

**验证**: 全部 60 个符号通过 roundtrip 测试（`encode(decode(x)) == x`）。

**字母表演化**: 见 `research/archive/data/alphabet*.json`（12 个版本，从残缺到完整）。

---

## 工具使用

### 查询固件下载 URL

```bash
# 查询任意 vivo/iQOO 机型
python3 tools/vivo_ota.py query PD2055 V2055A 9.10.3

# 输出示例
{
  "fileLength": "7039074100",
  "version": "9.10.3",
  "url": "http://sysupgrade.vivo.com.cn/dapi2.do?fileName=..."
}
```

### 下载固件

```bash
# 从 URL 下载
python3 tools/vivo_ota.py download <url> firmware.zip

# 速度：~110 MB/s（vivo CDN 直连）
```

### 解密/加密

```bash
# 解密
python3 tools/vivo_ota.py decode <encrypted_string>

# 加密
python3 tools/vivo_ota.py encode <plaintext>
```

---

## 为新机型破解字母表

如果字母表对新设备不适用（不同固件版本可能有不同映射）：

### 步骤

1. **获取密文**:
   - 设备进 recovery → 联网更新
   - `adb bugreport`
   - 提取 `FS/cache/recovery/last_log`
   - 搜索 `param=<密文>`

2. **准备已知明文**:
   - 设备型号（`model=PDxxxx`）
   - 版本号（`PDxxxxD_A_x.x.x`）
   - 硬件版本（`PDxxxxMA`）
   - IMEI 哈希（从 bugreport 的 `last_ota_info` 提取）

3. **运行攻击**:
   ```bash
   cd research/archive/01_ota_protocol
   python3 anchor_attack.py
   python3 cpsat_solve.py
   python3 final2.py
   ```

4. **验证**:
   ```bash
   python3 reencode_test.py
   # 必须输出: roundtrip PASS
   ```

### 注意事项

- 不同 vivo 设备可能使用不同字母表
- EOL（生命周期结束）设备可能返回 `retcode=210`（无更新）
- 某些机型需要真实 IMEI 才能查询

---

## 已知限制

1. **字母表可能变化**: 不同固件版本可能使用不同映射
2. **EOL 设备**: 部分旧机型服务器不再响应
3. **IMEI 校验**: 某些机型可能需要真实 IMEI
4. **协议版本**: 仅适用于 `jvq=1.0.3`，新版本可能不同

---

## 参考

- 完整破解脚本: `research/archive/01_ota_protocol/`
- 权威工具: `tools/vivo_ota.py`
- 字母表演化: `research/archive/data/alphabet*.json`
- 解密样本: `analysis/examples/decrypted_ota_response.sample.txt`
- 失败尝试: `FAILED_ATTEMPTS.md`（`<<4` bug 的详细记录）
