# 09 - Bootloader 研究 / Bootloader Research

> **后续原厂 ABL 取证纠正**：已从固件包取得并解压 abl.elf，发现厂商专用解锁命令表条目、处理函数及签名/状态校验分支，详见[最新报告](../analysis/reports/device_validation_20261109.md)。下文为此前观察和推断记录；涉及“解锁代码已完全删除”“尚缺 abl.elf”的结论已被新证据取代。仍未解锁 BL，也没有已验证的可用解锁方法。

> **文档状态**: ✅ 已完成（静态观察）  
> **最后更新**: 2026-11-09  
> **作者**: Viper-Boss

---

## 概述

本章节记录目前观察到的 Bootloader 状态、Fastboot 命令结果、AVB 相关背景和未解决的问题。

**重要声明**: 
- **没有解锁 Bootloader。**
- **没有实现解锁方法。**
- 以下内容仅为静态观察和背景分析，不包含任何已实现的解锁手段。

---

## 观察到的设备状态

### 启动参数（通过 adb 读取）

```
androidboot.verifiedbootstate=green     # AVB 验证通过
androidboot.vbmeta.device_state=locked  # 设备状态：锁定
androidboot.veritymode=enforcing        # dm-verity 强制
androidboot.securebootkeyver=4          # Secure Boot 密钥版本
androidboot.secureboot_enable=1         # Secure Boot 启用
```

### Fastboot 命令测试结果

```bash
$ fastboot flashing get_unlock_ability
(bootloader) unlock_ability: 1          # 策略位允许解锁

$ fastboot flashing unlock
(bootloader) unknown command            # 但命令不存在

$ fastboot oem unlock
(bootloader) unknown command            # 同上
```

**关键观察**: `unlock_ability=1` 表示策略上"允许解锁"，但解锁命令本身已被从 ABL（Android Bootloader）中**删除**。二者不矛盾——策略位存在于 devinfo 分区，命令处理逻辑存在于 abl.elf，vivo 只删除了后者。

---

## AVB（Android Verified Boot）背景

### 验证链

```
PBL（Primary Bootloader，ROM）
  └── 验证 XBL（eXtensible Boot Loader，xbl.elf）
       └── 验证 ABL（Android Bootloader，abl.elf）
            └── 验证 boot.img（通过 vbmeta）
                 └── 内核启动，验证 system/vendor（dm-verity）
```

### AVB 状态含义

| 状态 | 含义 | 本设备 |
|------|------|--------|
| green | 锁定 + 验证通过 | ✅ 当前状态 |
| yellow | 锁定 + 自定义密钥 | 否 |
| orange | 解锁 | 否 |
| red | 验证失败 | 否 |

### 锁定状态的影响

- **无法**刷入修改过的 boot.img（AVB 会拒绝）
- **无法**关闭 dm-verity（enforcing 模式）
- **无法**通过 fastboot 刷分区（unlock 命令不存在）

---

## 锁状态管理分析（静态推断，未验证）

> ⚠️ 以下为基于公开知识的**推断**，未经实验验证。

### 谁管理锁状态

vivo 设备的解锁状态通常存储在：
- `devinfo` 分区：一个标志位（locked/unlocked）
- `frp` 分区：Factory Reset Protection（可能关联解锁）

ABL 在 fastboot 阶段读取这些标志，决定是否执行解锁/刷写操作。

### 为什么 unlock_ability=1 但 unlock 不存在

```
unlock_ability（策略位，在 devinfo 中）= 1
    ↓
"策略允许解锁"
    ↓
但 vivo 编译 ABL 时，删除了 unlock 命令的 case 分支
    ↓
fastboot flashing unlock → "unknown command"
```

### 可能的解锁路径（理论分析，未尝试）

1. **修改 devinfo 分区**：需要 EDL 模式（9008）+ 签名 firehose → 本设备无公开 firehose
2. **利用 ABL 漏洞**：需要发现并利用 ABL 中的漏洞 → 超出本仓库范围
3. **vivo 内部工具**：不公开

**本仓库不尝试任何解锁方法。**

---

## xbl_config.elf 分析

### 基本信息

```
文件大小: 92,568 bytes
类型: ELF（Qualcomm XBL 配置）
内容: FDT（设备树）+ 内存映射配置
```

### 能提供的信息

- 内存布局（物理地址映射）
- 外设基址（UART、USB 等）
- 内核物理加载地址推导

### 不能提供的信息

- ❌ 解锁逻辑（在 abl.elf 中）
- ❌ devinfo 标志（在 devinfo 分区中）
- ❌ 密钥或签名（在硬件/OTP 中）

### 还缺的材料（如继续 BL 研究）

| 材料 | 获取方法 | 用途 |
|------|---------|------|
| `abl.elf` | 从固件包提取 | 分析 fastboot 命令处理 |
| `devinfo` 分区镜像 | 需 root 或 EDL | 查看锁状态标志 |
| `vbmeta.img` | 从固件包提取 | AVB 验证树根 |
| `fastboot getvar all` 输出 | 设备 fastboot 模式 | 完整变量清单 |
| 串口日志 | 硬件接口 | 各阶段启动细节 |

---

## 临时 Root vs 持久化 Root vs Bootloader 解锁

| 维度 | 临时 Root（本项目目标） | 持久化 Root | Bootloader 解锁 |
|------|------------------------|-------------|-----------------|
| 手段 | CVE-2026-43499 内存提权 | 改 boot/装 Magisk | fastboot flashing unlock |
| 存活 | **重启即失效** | 跨重启保留 | 永久改变设备状态 |
| 需要 BL 解锁? | **否** | 通常是 | —— |
| 本设备可行? | 研究中（见 docs/07） | 否（locked+AVB green） | **否**（命令被删） |
| 会触发 AVB red? | 否（不改分区） | 会 | 会（变 orange） |

**本仓库只追求临时 root**：全程不写任何分区，重启后设备完全恢复原状。

---

## 本仓库明确不做的事

- ❌ 修改锁状态属性
- ❌ 盲写分区
- ❌ 伪造解锁
- ❌ 寻找/利用 ABL 漏洞
- ❌ 分发 vivo 内部工具

---

## 未解决的问题

1. **ABL 中删除了哪些命令**: 需反汇编 abl.elf（本仓库未包含此文件）
2. **devinfo 分区格式**: 需 root 或 EDL 才能读取
3. **是否有其他解锁通道**: 未知（官方已停止服务）
4. **EDL firehose**: 本设备无公开签名 firehose

---

## 参考

- 设备信息: `docs/01_device_information.md`
- 固件提取: `docs/03_firmware_extraction.md`
- xbl_config.elf: 仓库根目录
- 临时/持久/解锁对比: 本文档 + `README.md`
