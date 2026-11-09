# 变更日志 / Changelog

本项目所有显著变更记录在此。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [SemVer](https://semver.org/lang/zh-CN/)。

---

## [0.4.0] - 2026-11-09（开源工程化整理，分支 chore/open-source-archive）

### 新增

- **规范化目录**: `docs/`（10 篇技术文档 + index）、`analysis/{reports,examples,evidence}`、
  `research/archive/`、`tests/`、`.github/{workflows,ISSUE_TEMPLATE}`
- **项目元数据**: `CHANGELOG.md`、`RESEARCH_TIMELINE.md`、`FAILED_ATTEMPTS.md`、
  `KNOWN_LIMITATIONS.md`、`SECURITY.md`、`CONTRIBUTING.md`、`README_EN.md`
- **README 重构**: `README.md` 成为项目入口（诚实状态声明 + 工具索引 + 复现流程）；
  原长篇双语叙述保留为 `docs/full_writeup.md`
- **离线测试**: `tests/privacy_scan.py`（结构性隐私扫描）、`tests/check_docs.py`（链接检查）
- **CI**: `.github/workflows/ci.yml`（离线安全测试，明确安全红线）
- **Issue 模板**: bug / 技术纠正 / 机型适配
- **`requirements.txt`**: capstone
- **历史归档**: `research/archive/` 75+ 脚本 + 字母表演化 + 旧结构元数据，
  每条标注 HISTORICAL / INCORRECT / SUPERSEDED

### 修正

- **`exploit/LICENSE_UPSTREAM`（补全）**: 上游 Apache-2.0 许可证全文（此前缺失，
  与 LICENSE 声明不符）+ `exploit/NOTICE`（NebuSec/CyberMeowfia、yijiacloud、
  Linux jhash 的可追溯归属）
- **`disasm_futex.py`**: capstone 改为惰性导入，未安装依赖时 `--help` 仍可用并给出
  明确安装提示
- **`tools/vivo_ota.py`**: emmcid 改为 CLI 参数（默认全零占位）；修正把
  `up.emmcid` 误标为固件 SHA256 的错误
- **`BOOT_IMAGE.md` → `analysis/reports/boot_image_structure.md`**，并修正全部旧路径引用

### 隐私

- 当前工作树中的 IMEI 哈希 / emmcid 已全部脱敏（代码、样本、归档脚本）
- **移除 19 份中间解密样本**：其乱码形态仍残留标识符片段，边际研究价值低于隐私风险；
  协议结构、字母表与破解方法完整保留
- 隐私扫描器改为**结构性检测**，自身不内嵌任何真实标识符
- ⚠️ **Git 历史中仍存在**：早期提交（自 91f79fb 起）含 IMEI 哈希与 emmcid 字面量。
  已报告，未擅自改写历史（需作者确认后执行 filter-repo）

---

## [0.3.0] - 2026-11-09（当前，分支 analysis/futex-disassembly）

### 新增

- **`docs/` 技术文档体系（10 份）**：设备信息、OTA 协议、固件提取、kallsyms、
  反汇编、futex 研究、KernelSnitch 移植、构建测试、Bootloader、已知问题
- **`scripts/` 权威可复现流水线**：
  - `extract_boot_image.py`：boot.img → ARM64 Image（v2 头解析，CLI 参数）
  - `parse_kallsyms.py`：解析 kallsyms（运行时 markers 429/429 自校验）
  - `verify_kallsyms.py`：6 重独立只读校验
  - `disasm_futex.py`：反汇编 futex 函数（复现报告证据）
  - `gen_target_offsets.py`：从 kallsyms 生成 target.h 偏移
  - `kallsyms_layout.json`：已验证的结构常量
- **`analysis/reports/futex_disassembly_report.md`**：vivo futex 反汇编验证报告
- **`research/archive/`**：75+ 个历史脚本（OTA 破解、kallsyms 迭代、反汇编取证）
  + 35 个中间数据文件（字母表演化、解密样本[已脱敏]）
- **`exploit/tests/test_futex_hash.c`**：16 项单元测试（独立反汇编参考）
- **`exploit/src/diag_params.c`**：只读参数诊断工具
- **`exploit/src/wallpaper_blob_stub.S`**：空壁纸 blob（无资产也能构建）
- **CI 工作流**（`.github/workflows/`）：离线安全测试
- **`requirements.txt`**：Python 依赖（capstone）

### 修正（重大技术错误）

- **futex_key 布局**：经反汇编 vivo 真实内核，确认
  **mm@0, address@8, 哈希=[mm,addr]**（与上游 v4.19 **相反**）。
  推翻此前两次错误判断（详见 FAILED_ATTEMPTS.md）
- **boot.img 提取**：vendor wrapper = **0 字节**（此前"52 字节 vivo 头"是误判）；
  ARM64 头字段**完好**（text_offset=0x80000，此前"被清零"是误判）
- **kallsyms 解析**：109,687 符号（此前 109,641 因 names_start 错位 50 条），
  全部经 markers 429/429 + 5 重独立验证
- **MM_STRUCT_SZ**：0x340 → **0x3C0**（设备 slabinfo 实测 960）
- **mm_slab_order 重置 bug**：重置为 0 → 保持 MM_ORDER(3)
- **kernelsnitch_strings**：6 枚举 vs 5 字符串缺项，改指定索引初始化
- **FUTEX_KEY_INIT 宏**：引用不存在的类型（从未编译通过）→ 修正

### 变更

- **目录重组**：analysis/{reports,examples,evidence}、scripts/legacy/、
  research/archive/{01_ota,02_kallsyms,03_disasm,data}
- **README.md**：重写为项目入口（含诚实状态声明）
- **脚本去绝对路径**：全部改 CLI 参数/项目相对路径

### 隐私

- 所有 IMEI 哈希/emmcid/序列号替换为 `<REDACTED_*>` 占位符（当前文件+归档）
- 修正误将 emmcid 标注为 "sha256" 的错误

---

## [0.2.0] - 2026-11-09（fix/futex-key-layout → 已合并到 master）

### 新增

- `GHOSTLOCK_NO_DESTRUCTIVE` 编译开关（preload_noroot）
- `diag_params` 只读诊断组件
- Makefile 构建系统（默认 PD2055，NDK 自动发现）
- 单元测试（此时参考有误，后被 0.3.0 修正）

### 修正

- kallsyms 109,641 → 109,687（修正 names_start 错位）
- target.h 符号偏移全部修正（旧值因错位而错误）
- futex_hash 起点 bug（此时判断有误，后被 0.3.0 推翻重修正）

---

## [0.1.0] - 2026-11-08/09（初始发布）

### 新增

- vivo OTA 协议破解（替换密码 + base64，60 符号字母表）
- 7GB 固件下载（110 MB/s）
- kernel_Image 提取（含错误的 52 字节截断，后被 0.3.0 修正）
- kallsyms 初版解析（109,641 错位，后被 0.2.0 修正）
- target.h 初版（偏移错误，后被 0.2.0 修正）
- GhostLock exploit 首次设备端运行（碰撞成功，mm 定位失败）
- tools/vivo_ota.py 全机型固件下载器
- GPLv3 LICENSE

---

## 版本说明

- **0.3.0**（当前）：技术定论 + 开源工程化
- **0.2.0**：第一次系统修复（含部分错误，后来再修正）
- **0.1.0**：初始研究（多个基础错误，逐轮修正）

完整研究时间线：`RESEARCH_TIMELINE.md`
所有失败记录：`FAILED_ATTEMPTS.md`
