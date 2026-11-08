# scripts/ — 分析脚本说明

本目录包含两条独立的分析流水线：**A) kallsyms 提取**、**B) vivo OTA 协议破解**。
下面标注了**权威（已验证）**脚本和**历史/辅助**脚本，避免重复踩坑。

---

## A) kallsyms 提取流水线（权威，已用 markers 429/429 验证）

按顺序运行：

| 顺序 | 脚本 | 作用 | 状态 |
|------|------|------|------|
| 1 | `parse_boot.py` | 从 boot.img 解析 v2 头、剥离 52 字节 vivo 包装、导出 ARM64 kernel Image | ✅ 权威 |
| 2 | `find_ti.py` | 定位 token_index（256×u16，验证 256/256） | ✅ 权威 |
| 3 | `find_structure.py` / `scan_offsets.py` | 定位 offsets 表 / markers / token_table 候选位置 | ✅ 辅助定位 |
| 4 | `find_names_start.py` | **关键**：暴力搜索 names 起点，使解析计数 == num_syms 且干净收尾 | ✅ 权威 |
| 5 | `verify_kallsyms.py` | **决定性验证**：markers[k] == name[256k] 偏移，429/429 匹配才可信 | ✅ 权威 |
| 6 | `gen_target_offsets.py` | 从验证过的符号表生成 target.h 偏移 | ✅ 权威 |

### 正确结构（PD2055_A_9.10.3，已验证）
```
offsets : 0x1f805cc .. 0x1feb7a8  (109,687 × s32)
num_syms: u32 @ 0x1feb8cc = 0x1AC77
names   : 0x1feb9cc .. 0x215904e  ([u8 len][tokens], 4.19, 无 0x80 扩展)
markers : 0x21590cc               (429 × u32 @ 8 字节步距 — vivo 自定义)
tokens  : 0x2159ecc (table) / 0x215a2cc (index)
```

### ⚠️ 已废弃的错误做法（不要再用）
早期 `align_final.py` / `lookup_syms.py` / `parse419.py`（已删除）曾报告
"109,641 符号、names@0x1febb9b、offsets@0x1f805bc"，并用 0x80 扩展长度解析。
这是**错误**的：names 起点偏晚 50 条，导致名字与偏移错位配对，
`init_task`/`commit_creds` 查不到，target.h 偏移全错。
**教训**：解析 kallsyms 必须用 markers 交叉验证（`verify_kallsyms.py`），
不能只看"解析出了多少个名字"。4.19 是纯 `[u8 len][tokens]`，没有 0x80 扩展。

---

## B) vivo OTA 协议破解流水线（jvq 1.0.3）

协议本质 = **替换密码 + 标准 base64**，不是真加密。完整可用工具见
`../tools/vivo_ota.py`（已含破解好的字母表，可直接查询/下载任意机型固件）。

下列脚本是**破解过程**的记录（如何从零得到字母表）：

| 脚本 | 作用 | 状态 |
|------|------|------|
| `try_decode.py` | 尝试 base64 变体解码，发现 mod-4 对齐规律 | 历史 |
| `anchor_attack.py` | **已知明文攻击**：用 IMEI 哈希/版本号锚定符号值 | ✅ 核心方法 |
| `cpsat_solve.py` | 用 OR-Tools CP-SAT 求解替换密码双射约束 | ✅ 核心方法 |
| `final2.py` | 爬山算法优化剩余未知符号 | ✅ 核心方法 |
| `repair.py` | 修复个别错解符号 | 辅助 |
| `reencode_test.py` | **重编码 oracle**：encode(decode(x))==x 验证字母表 | ✅ 验证 |
| `finish.py` | 收尾、导出最终字母表 | 辅助 |

### ⚠️ 最关键的坑
标准 base64 第三字节公式是 `b2 = ((v2 & 0x3) << 6) | v3`。
**不是 `<< 4`！** 用 `<<4` 会产生"看起来差不多但每第 3 字节都错"的结果，
极难 debug（我花了 3 小时）。`tools/vivo_ota.py` 已修正。

### 为新机型破解字母表
若 `tools/vivo_ota.py` 的字母表对某机型不适用：
1. 该机型进 recovery → 联网更新 → `adb bugreport` → 取 `FS/cache/recovery/last_log`
2. 日志里 `param=<密文>&jvq=1.0.3`
3. 用 `anchor_attack.py` 思路：密文里必含 `model=PDxxxx`、版本号、`&hardware=` 等已知明文
4. 用 `reencode_test.py` 验证 roundtrip
