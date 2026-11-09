# iQOO Neo5（PD2055）临时 Root 研究项目

> **⚠️ 诚实状态声明**：**尚未在真机取得 uid=0，也尚未解锁 Bootloader。**
> 本项目是内核安全研究，当前处于「参数已修正、待真机复测」阶段。
> 请勿被任何"Root 成功 / BL 已解锁"描述误导。

---

## 项目简介

针对 **iQOO Neo5（V2055A / PD2055，骁龙870 / SM8250，Android 14，OriginOS 4，
内核 4.19.152-perf+）** 的临时 root 研究。核心思路：移植 CVE-2026-43499
（rtmutex `remove_waiter()` UAF）的 GhostLock exploit，通过 LD_PRELOAD 实现内存态提权。

本项目**不追求**持久化 Root 与 Bootloader 解锁（前者通常需解锁，后者已被 vivo 从 ABL 中删除）。

---

## 支持设备与固件

| 项 | 值 |
|----|----|
| 设备 | iQOO Neo5（PD2055 / V2055A）|
| SoC | Snapdragon 870（SM8250 / kona）|
| Android | 14 / OriginOS 4 |
| 固件 | PD2055_A_9.10.3（compiler10161353，EOL 最终版）|
| 内核 | 4.19.152-perf+（arm64，39-bit VA，KASLR）|
| Bootloader | **Locked**（无解锁通道）|

---

## 当前真实进度

| 阶段 | 状态 |
|------|------|
| vivo OTA 协议破解（jvq 1.0.3）| ✅ 完成（替换密码 + base64，60 符号字母表）|
| 固件获取（7GB 全量包）| ✅ 完成（110 MB/s 直连）|
| kallsyms 恢复 | ✅ 完成（109,687 符号，markers 429/429 + 5 重独立验证）|
| vivo futex 哈希模型 | ✅ **反汇编定论**（mm@0/[mm,addr]，≠上游 v4.19）|
| 单元测试 | ✅ 完成（16/16，独立反汇编参考）|
| 构建 | ✅ 完成（aarch64，NDK r27c）|
| **KernelSnitch mm 定位** | ⏳ **未真机验证**（原理成立，参数已修）|
| **临时 Root（uid=0）** | ❌ **未达成** |
| **Bootloader 解锁** | ❌ **不可行**（命令被删）|

---

## 已完成的技术成果

- **vivo OTA 协议完整破解**：`tools/vivo_ota.py`（查询/下载任意 vivo/iQOO 固件）
- **boot.img 正确提取**：`scripts/extract_boot_image.py`（vendor wrapper = 0，头字段完好）
- **kallsyms 全自动解析 + 6 重验证**：`scripts/parse_kallsyms.py` + `scripts/verify_kallsyms.py`
- **ARM64 反汇编取证**：`scripts/disasm_futex.py`（复现 futex 报告全部证据）
- **符号偏移自动生成**：`scripts/gen_target_offsets.py`
- **futex 哈希独立单测**：`exploit/tests/test_futex_hash.c`（16 项）
- **只读参数诊断**：`exploit/src/diag_params.c`（`make diag`，唯一可安全真机运行）

## 环境准备

```bash
# 主机单元测试（无需 NDK）
sudo apt-get install gcc make python3
pip install capstone           # 反汇编依赖

# 交叉编译（构建 aarch64 exploit）
# 安装 Android NDK r27c，然后：
export NDK_ROOT=~/android-ndk-r27c
```

## 复现流程（从固件到符号表）

```bash
# 1. 提取内核 Image
python3 scripts/extract_boot_image.py boot.img -o /tmp/kernel_Image --report

# 2. 解析 kallsyms（运行时 markers 429/429 自校验）
python3 scripts/parse_kallsyms.py --from-boot boot.img -o kallsyms.txt

# 3. 6 重独立验证
python3 scripts/verify_kallsyms.py --from-boot boot.img --kallsyms kallsyms.txt

# 4. 生成 target.h 偏移
python3 scripts/gen_target_offsets.py -o target_offsets.txt
```

## 离线反汇编验证（futex）

```bash
python3 scripts/disasm_futex.py --from-boot boot.img --kallsyms kallsyms.txt --scan-hash
```

## 测试命令

```bash
cd exploit && make test            # 16/16 单元测试 + 4/4 诊断（纯计算，不触发漏洞）
cd exploit && make preload         # aarch64 完整 payload（⚠️ 活跃 exploit）
cd exploit && make noroot-payload  # aarch64 无root payload（⚠️ 仍触发 CVE）
cd exploit && make diag            # aarch64 只读诊断（✅ 安全）
```

## 工具入口

| 工具 | 用途 |
|------|------|
| `tools/vivo_ota.py` | vivo/iQOO 固件查询/下载/协议编解码 |
| `scripts/extract_boot_image.py` | boot.img → ARM64 Image |
| `scripts/parse_kallsyms.py` | kallsyms 解析（markers 自校验）|
| `scripts/verify_kallsyms.py` | 6 重只读校验 |
| `scripts/disasm_futex.py` | futex 反汇编取证 |
| `scripts/gen_target_offsets.py` | 生成 target.h 偏移 |
| `exploit/` | GhostLock 移植源码 + 测试 + 构建 |

## 技术文档索引

见 [`docs/index.md`](docs/index.md) 或直接阅读：

1. [设备信息](docs/01_device_information.md)
2. [OTA 协议分析](docs/02_ota_protocol_analysis.md)
3. [固件提取](docs/03_firmware_extraction.md)
4. [kallsyms 恢复](docs/04_kallsyms_recovery.md)
5. [内核反汇编](docs/05_kernel_disassembly.md)
6. [futex 哈希研究](docs/06_futex_hash_research.md)
7. [KernelSnitch 移植](docs/07_kernelsnitch_porting.md)
8. [构建与测试](docs/08_build_and_testing.md)
9. [Bootloader 研究](docs/09_bootloader_research.md)
10. [已知问题与下一步](docs/10_known_issues.md)

---

## 其他文档

- [变更日志](CHANGELOG.md) · [研究时间线](RESEARCH_TIMELINE.md)
- [失败尝试（重要）](FAILED_ATTEMPTS.md) · [已知限制](KNOWN_LIMITATIONS.md)
- [安全政策](SECURITY.md) · [贡献指南](CONTRIBUTING.md)

## 许可证

原创代码与文档：**GPLv3**（`LICENSE`）。
exploit 主体源自 [NebuSec/CyberMeowfia](https://github.com/NebuSec/CyberMeowfia)（GhostLock）
及 [yijiacloud 的 K40 移植](https://github.com/yijiacloud/ghostlock-cve-2026-43499-4.19-k40)，**Apache-2.0**。
详情见 `SECURITY.md`。

## 风险提示

- 完整/noroot payload 是**活跃内核 exploit**（触发 CVE-2026-43499 + 写内核内存），可能**变砖**。
- 仅限自有硬件、合法研究。CI 与文档不提供自动触发漏洞的流程。
- 仅 `diag_params` 是只读安全的诊断工具。