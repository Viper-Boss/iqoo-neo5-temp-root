# 技术文档索引 / Technical Documentation Index

本项目完整技术文档按研究阶段组织。每篇文档独立可阅读，但建议按编号顺序浏览。

---

## 1. 设备与固件基础

### [01 - 设备信息](01_device_information.md)

- 目标设备规格（iQOO Neo5 / PD2055 / Snapdragon 870）
- 固件版本（PD2055_A_9.10.3，EOL 最终版）
- 内核配置（39-bit VA，KASLR，CONFIG_KALLSYMS 等）
- Bootloader 状态（Locked，无解锁通道）
- 安全边界（允许/禁止/谨慎操作清单）

### [02 - vivo OTA 协议分析](02_ota_protocol_analysis.md)

- 协议发现（recovery 联网更新抓取）
- 加密机制（替换密码 + base64，`jvq=1.0.3`）
- 已知明文攻击（IMEI 哈希/版本串锚定）
- 字母表破解（CP-SAT + 爬山 + 重编码 oracle）
- 关键 bug 修复（`<<6` vs `<<4`）
- 工具使用（`tools/vivo_ota.py`）
- 为新机型破解字母表的方法

### [03 - 固件提取](03_firmware_extraction.md)

- Android boot image v2 结构解析
- 内核镜像提取（`extract_boot_image.py`）
- ARM64 Image 头字段验证（**无 vendor wrapper，头字段完好**）
- 错误历史（52 字节截断误判）
- 偏移映射验证方法

---

## 2. 内核符号与反汇编

### [04 - kallsyms 恢复](04_kallsyms_recovery.md)

- kallsyms 结构概述（offsets / markers / tokens）
- vivo 自定义格式（markers u32@8 步距）
- 早期错误（109,641 错位版本）
- 错误根因（names_start 偏晚 50 条）
- 正确解析（109,687，markers 429/429）
- 6 重独立验证方法（计数/单调/markers/段序/聚簇/ARM64 抽查）
- vivo 符号过滤（commit_creds 等被删除）

### [05 - 内核反汇编](05_kernel_disassembly.md)

- 反汇编环境（capstone + `disasm_futex.py`）
- 符号映射（kallsyms 偏移 == 文件偏移）
- 函数定位方法（从 kallsyms 获取地址 → 反汇编 → 识别关键指令）
- 证据保存（完整报告 + 可复现命令）
- 交叉验证方法（多函数/多调用点/寄存器追踪）
- 关键发现（futex_key 布局、hash 参数、task_struct.mm 偏移）

---

## 3. futex 与 KernelSnitch

### [06 - futex 哈希研究](06_futex_hash_research.md)

- 上游 Linux v4.19 与 vivo 4.19.152-perf+ 的差异
- futex_key 字段顺序的三次判断（两次错误，最终正确）
- 哈希算法参数（基址、长度、initval、字顺序）
- 错误教训（为什么仅参照上游源码不够）
- 最终证据（设备固件反汇编）
- 关键发现：**vivo = mm@0/[mm,addr]，≠上游 v4.19**

### [07 - KernelSnitch 移植](07_kernelsnitch_porting.md)

- KernelSnitch 工作原理（碰撞发现 → 暴力反推 → 利用）
- 移植过程中遇到的问题（futex_key、MM_STRUCT_SZ、slab order、符号过滤、健全性门控、状态字符串）
- 设备端运行日志（历史，修复前）
- 静态验证结果（单元测试 + 反汇编）
- 尚未验证的假设（KIMAGE_TEXT_BASE、cred/pipe 偏移、真机定位）
- 下一步（设备端重测、结构体验证、替代路径）

---

## 4. 构建、测试与 Bootloader

### [08 - 构建与测试](08_build_and_testing.md)

- 环境要求（主机端 / 交叉编译 / 设备端）
- 构建命令（单元测试 / 完整 payload / 无 root payload / 只读诊断）
- 测试方法（单元测试 / kallsyms 验证 / Python 语法检查）
- 依赖清单（requirements.txt + 构建依赖）
- 常见错误（5 种典型问题 + 解决方案）
- GitHub Actions CI（工作流 + 安全边界）
- 构建 SHA256 记录

### [09 - Bootloader 研究](09_bootloader_research.md)

- 观察到的设备状态（启动参数 / Fastboot 命令）
- AVB 背景（验证链 / 状态含义 / 锁定影响）
- 锁状态管理分析（静态推断，未验证）
- xbl_config.elf 分析（能提供/不能提供的信息）
- 临时 Root vs 持久化 Root vs Bootloader 解锁（三者区分）
- 本仓库明确不做的事
- 未解决的问题

### [10 - 已知问题与下一步](10_known_issues.md)

- 问题分类（🔴 关键未解决 / 🟡 中等问题 / 🟢 低风险）
- 失败原因总结（设备端 mm 定位失败 / kallsyms 错位 / futex 三次错误判断）
- 下一步研究方向（设备端验证 / 结构体验证 / KASLR slide / 替代路径）
- 完整研究时间线（时间轴表格）

---

## 5. 项目元数据

### 根目录文档

- [CHANGELOG.md](../CHANGELOG.md)：所有版本变更日志
- [RESEARCH_TIMELINE.md](../RESEARCH_TIMELINE.md)：完整研究时间线（含失败）
- [FAILED_ATTEMPTS.md](../FAILED_ATTEMPTS.md)：失败尝试记录（9 条，含教训）
- [KNOWN_LIMITATIONS.md](../KNOWN_LIMITATIONS.md)：已知限制（能力边界 + 未决事项）
- [SECURITY.md](../SECURITY.md)：安全政策（隐私 / 许可证 / 披露）
- [CONTRIBUTING.md](../CONTRIBUTING.md)：贡献指南
- [README_CN.md](../README.md)：项目入口（中文）
- [README_EN.md](../README_EN.md)：项目入口（English）

### 分析目录

- `analysis/reports/futex_disassembly_report.md`：vivo futex 反汇编验证报告
- `analysis/examples/`：脱敏示例数据（OTA 响应 / 字母表）
- `analysis/evidence/`：实测证据（slabinfo）

### 历史归档

- `research/archive/`：75+ 个历史脚本 + 35 个中间数据文件
- `scripts/legacy/`：已取代的脚本（含说明）

---

## 阅读建议

### 新手路径

1. 先读 `README_CN.md` 或 `README_EN.md` 了解项目全貌
2. 读 `01_device_information.md` 理解目标设备
3. 读 `02_ota_protocol_analysis.md` + `03_firmware_extraction.md` 学习固件获取
4. 读 `04_kallsyms_recovery.md` 学习符号提取
5. 读 `06_futex_hash_research.md` 理解 futex 三次判断（含失败教训）
6. 读 `10_known_issues.md` 了解当前状态与下一步

### 贡献者路径

1. 读 `CONTRIBUTING.md` 了解贡献规范
2. 读 `SECURITY.md` 了解隐私与红线
3. 读 `FAILED_ATTEMPTS.md` 避免重蹈覆辙
4. 读相关技术文档（按修改模块选择）

### 复现者路径

1. 读 `08_build_and_testing.md` 搭建环境
2. 读 `README_CN.md` 的"复现流程"部分
3. 按需查阅各阶段详细文档（01-10）

---

## 文档维护原则

1. **诚实优先**：不夸大成果，明确标注未验证假设
2. **保留失败**：所有错误判断记录在 `FAILED_ATTEMPTS.md`，不删除
3. **证据驱动**：技术结论必须有反汇编/实测/单测证据，附可复现命令
4. **独立可读**：每篇文档尽量自包含，必要时交叉引用
5. **及时更新**：新发现及时修订，标注最后更新时间
