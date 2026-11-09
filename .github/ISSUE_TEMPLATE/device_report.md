---
name: Device report / 机型适配报告
about: 报告在其他 vivo/iQOO 机型上的测试结果 / Report results on another vivo/iQOO device
title: "[DEVICE] <model> <firmware>"
labels: device-report
---

## 设备信息 / Device

| 项 | 值 |
|----|-----|
| 型号 / Model | <!-- 如 iQOO Neo6 / PD2196 --> |
| SoC | |
| Android 版本 | |
| 固件版本 | |
| 内核版本（`uname -r`）| |

## 测试内容 / What was tested

- [ ] `diag_params`（只读诊断）
- [ ] `tools/vivo_ota.py query`（固件查询）
- [ ] `scripts/verify_kallsyms.py`（kallsyms 校验）
- [ ] 其他（说明）

## 结果 / Results

```bash
# 粘贴输出（请脱敏）
```

## 差异 / Differences observed

<!-- 例如：mm_struct 大小不同、futex 布局不同、OTA 协议版本不同 -->

## 脱敏确认 / Redaction confirmed

- [ ] 已移除 IMEI / emmcid / 序列号 / token / 本地绝对路径
