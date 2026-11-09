# 已知限制 / Known Limitations

> 本文档如实列出当前项目的能力边界与未决事项。**不夸大任何成果。**

---

## 核心结论现状（诚实声明）

| 目标 | 状态 | 说明 |
|------|------|------|
| 临时 Root（uid=0） | ❌ **未达成** | 尚未在真机成功获取 |
| Bootloader 解锁 | ❌ **未达成** | 原厂 ABL 存在专用处理函数，签名/模式门控未解决 |
| 持久化 Root | ❌ 未实现 | 尚无已验证方案 |
| KernelSnitch mm 定位 | ✅ 独立实验两轮各唯一匹配且候选一致 | 无独立内核读取地面真值；不等同于取得 root |

**不要使用"Root 成功"或"BL 已解锁"等未经验证的描述。**

---

## 技术验证状态

### 已验证（有反汇编/实测/单测证据）

- futex_key 布局 mm@0/addr@8、哈希 [mm,addr]、长度 4：反汇编 + 16/16 单测
- task_struct.mm @ 0x580：get_task_mm 反汇编
- hashsize = roundup_pow_of_two(256×cpus)：futex_init 反汇编 + 真机日志 0x800
- kallsyms 109,687 符号：markers 429/429 + 5 重独立验证
- MM_STRUCT_SZ 0x3C0、slab order 3：/proc/slabinfo 实测
- vivo OTA 协议字母表（60 符号）：roundtrip 100% 验证

### 未验证（假设，需真机/反汇编确认）

| 项 | 风险 | 验证方法 |
|----|------|---------|
| KIMAGE_TEXT_BASE=0xffffff8008080000 | 高（决定 slide） | 真机 KASLR 泄露 |
| 完整 target.h 中的结构体字段偏移 | 高（已发现多处与原厂反汇编不符） | 逐字段反汇编及独立交叉验证，见最新报告 |
| SLIDE_RANDOM_BOOT_ID_DATA | 中（slide 泄露） | 运行时确认 |
| mm 候选的独立地面真值 | 未完成 | 独立于时序/哈希的验证方式 |
| vivo SLUB_MIRROR 对堆喷的影响 | 中 | 真机观察 |

---

## 设备与固件限制

- 完整固件 7GB 无法上传 GitHub（仅提供下载方法 + boot.img 96MB）
- 固件无官方 SHA256（服务器 checkString 为空），仅结构验证
- OTA URL 可能有时效性
- 仅 PD2055_A_9.10.3 一个固件版本验证过（其它 vivo 机型需自行适配字母表/偏移）

## 工具/脚本限制

- `scripts/kallsyms_layout.json` 中的结构偏移仅适用于 PD2055_A_9.10.3 的 Image
- 历史脚本（`research/archive/`、`scripts/legacy/`）多为一次性探索代码，不保证可运行
- `tools/vivo_ota.py` 的字母表可能不适用于其它固件版本/机型（提供破解方法，见 docs/02）
- 反汇编需要 capstone；单元测试需要 gcc；交叉编译需要 NDK r27c+

## 安全边界（红线）

- 完整/noroot payload 均为**活跃 exploit**（触发 CVE-2026-43499 + 写内核内存），非只读
- CI 与文档**不**提供自动运行 exploit 的流程
- `diag_params` 只读取参数；独立 `ks_probe` 使用普通 futex 时序，具有线程和时间开销，不能当作完整 exploit 的验证或入口

最新证据与剩余问题：[2026-11-09 真机和固件调查](analysis/reports/device_validation_20261109.md)。

---

## 法律/版权注意

- 本仓库仅用于教育研究，仅限自有硬件
- vivo 固件/boot.img/xbl_config.elf 等属 vivo 版权，仅按需提供，请勿再分发受控镜像
- exploit 核心源自 NebuSec/CyberMeowfia（Apache-2.0），衍生部分 GPLv3（见 LICENSE 与 SECURITY.md 的许可证说明）

---

相关：`FAILED_ATTEMPTS.md`、`docs/10_known_issues.md`、`SECURITY.md`、`README.md`（进度表）。
