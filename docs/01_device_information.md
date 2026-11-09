# 01 - 设备信息 / Device Information

> **文档状态**: ✅ 已完成  
> **最后更新**: 2026-11-09  
> **作者**: Viper-Boss

---

## 目标设备

| 项目 | 值 |
|------|-----|
| **型号** | iQOO Neo5 (V2055A / PD2055) |
| **SoC** | Qualcomm Snapdragon 870 (SM8250 / kona) |
| **系统** | Android 14 / OriginOS 4 |
| **固件版本** | PD2055_A_9.10.3 (compiler10161353) |
| **内核版本** | 4.19.152-perf+ |
| **编译时间** | Thu Oct 16 14:02:35 CST 2025 |
| **Bootloader** | **Locked** (无官方解锁通道) |

## 内核配置要点

从 `/proc/config.gz` 提取（无需 root 即可读取）：

```
CONFIG_ARM64_VA_BITS=39
CONFIG_PGTABLE_LEVELS=3
CONFIG_PREEMPT=y
CONFIG_FUTEX_PI=y
CONFIG_RT_MUTEXES=y
CONFIG_KALLSYMS=y
CONFIG_KALLSYMS_ALL=y
CONFIG_IKHEADERS=y          # 可提取内核头文件验证结构体偏移
CONFIG_SLAB_FREELIST_RANDOM=y
CONFIG_SLAB_FREELIST_HARDENED=y
CONFIG_SLUB_MIRROR=y         # vivo 反利用加固
CONFIG_PANIC_ON_REFCOUNT_ERROR=y
CONFIG_PANIC_ON_OOPS=0       # 内核 oops 不 panic，设备可恢复
CONFIG_MODULE_SIG_FORCE=y    # 强制模块签名 (sha512)
CONFIG_RANDOMIZE_BASE=y      # KASLR 启用
```

## 启动链状态

```
androidboot.verifiedbootstate=green
androidboot.vbmeta.device_state=locked
androidboot.veritymode=enforcing
androidboot.securebootkeyver=4
androidboot.secureboot_enable=1
```

## Fastboot 命令测试

```bash
$ fastboot flashing get_unlock_ability
...
(bootloader) unlock_ability: 1    # 策略位允许解锁

$ fastboot flashing unlock
...
(bootloader) unknown command      # 但命令已被 vivo 从 ABL 中删除

$ fastboot oem unlock
...
(bootloader) unknown command      # 同上
```

**结论**: 设备策略位 `unlock_ability=1` 表示"允许解锁"，但 vivo 已从 Android Bootloader (ABL) 中**删除了解锁命令的处理逻辑**，因此无法通过标准 fastboot 命令解锁。

## 研究范围与安全边界

### ✅ 允许的操作

- 静态分析（反汇编、符号提取、协议逆向）
- 离线单元测试（不触发漏洞）
- 只读诊断（`diag_params`，不修改内核状态）
- 固件下载与提取（合法获取的 OTA 包）

### ❌ 禁止的操作

- 自动运行 exploit（可能崩溃设备）
- 修改分区（boot/vbmeta/abl/xbl/devinfo）
- 解锁 Bootloader（无官方通道）
- 公开个人隐私信息（IMEI/emmcid/序列号）

### ⚠️ 需谨慎的操作

- 真机运行 `preload.so` / `preload_noroot.so`（触发 CVE-2026-43499，写内核内存）
- 仅建议在**自有硬件**、**充分理解风险**、**可接受设备变砖**的前提下手动执行

---

## 参考

- 设备指纹验证: `kernel-config.txt` (仓库根目录)
- Bootloader 静态分析: `docs/09_bootloader_research.md`
- 安全边界说明: `SECURITY.md` (仓库根目录)
