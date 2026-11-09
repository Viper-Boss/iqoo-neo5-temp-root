# scripts/legacy/ — 历史脚本（已被上层权威工具取代）

本目录是研究过程中的**历史脚本**，保留仅作发现过程记录。它们**不是**复现流水线的
一部分——复现请用上层 `scripts/` 中的权威工具：

| 权威工具（scripts/） | 用途 |
|---|---|
| `extract_boot_image.py` | 从 boot.img 提取 ARM64 kernel Image（v2 头解析）|
| `parse_kallsyms.py` | 解析 kallsyms（运行时 markers 429/429 验证）|
| `verify_kallsyms.py` | 6 重独立只读校验 |
| `disasm_futex.py` | 反汇编 futex 函数（复现反汇编报告）|
| `gen_target_offsets.py` | 从 kallsyms 生成 target.h 偏移 |

## 本目录内容

**kallsyms 发现脚本**（已被 `parse_kallsyms.py` + `kallsyms_layout.json` 取代）：
- `find_ti.py` / `find_structure.py` / `scan_offsets.py` / `find_names_start.py`
  —— 当初用来定位 token_index / markers / offsets / names_start 的探索脚本。
- `parse_boot.py` —— 早期 boot.img 解析（被 `extract_boot_image.py` 取代）。
- `reverify_kallsyms.py` / `verify_final.py` —— 早期校验（被 `verify_kallsyms.py` 取代）。

> ⚠️ 注意：这些发现脚本当时是在一个**被错误截断 52 字节**的 kernel Image 上运行的，
> 因此其中的结构偏移（names@0x1feb9cc 等）对应那个旧镜像，比正确镜像**小 52**。
> 正确偏移见 `scripts/kallsyms_layout.json`（已按正确镜像 +52 并经 markers 验证）。
> 不要直接复用本目录脚本里的硬编码偏移。

**vivo OTA 协议破解脚本**（工作工具见 `tools/vivo_ota.py`）：
- `try_decode.py` / `anchor_attack.py` / `cpsat_solve.py` / `final2.py` /
  `repair.py` / `finish.py` / `reencode_test.py`
  —— 记录"已知明文攻击 + CP-SAT + 爬山 + 重编码 oracle"的破解过程。

> 🔒 隐私：这些脚本需要**原始加密样本**（recovery 日志里的 `param=`/`conf=`），
> 样本含设备 IMEI 哈希等隐私信息，**不随仓库分发**。脚本中的输入路径已改为
> 项目相对路径 `samples/...`（占位），缺失时应自行放入样本或改用 `tools/vivo_ota.py`
> （已内置破解好的字母表，可直接查询/下载，无需重跑破解）。

## 路径说明

所有 `Q:\...` 开发者绝对路径已移除，改为项目相对路径。这些历史脚本可能需要你
自行准备输入样本才能运行；权威复现流程不依赖本目录。
