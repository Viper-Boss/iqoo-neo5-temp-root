# 10 - 已知问题与下一步 / Known Issues

> **文档状态**: ✅ 已完成  
> **最后更新**: 2026-11-09  
> **Author**: Viper-Boss

---

## 概述

本章节汇总全部已知问题、失败原因、未解决问题以及下一步研究方向。

**诚实声明**: 
- **尚未在真机取得 uid=0**（临时 Root 未成功）
- **尚未解锁 Bootloader**（命令被 vivo 删除）
- 以下问题清单是最完整的状态记录

---

## 问题分类

### 🔴 关键未解决（阻塞提权）

| # | 问题 | 状态 | 影响 | 下一步 |
|---|------|------|------|--------|
| 1 | KernelSnitch mm 定位未在设备端重测 | ❌ 未测试 | 阻塞整条路线 | 在设备上运行修复版，观察是否成功定位 mm |
| 2 | KIMAGE_TEXT_BASE 未验证 | ❌ 未验证 | KASLR slide 无法校准 | 通过 boot_id 侧信道或 dmesg 泄露 |
| 3 | cred/pipe 结构体偏移未逐项验证 | ⚠️ 部分验证 | 提权写入可能失败 | 提取 kheaders（CONFIG_IKHEADERS=y） |

### 🟡 中等问题（不阻塞但有风险）

| # | 问题 | 状态 | 影响 | 下一步 |
|---|------|------|------|--------|
| 4 | SLIDE_RANDOM_BOOT_ID_DATA 是过滤符号 | ⚠️ 假设 | slide 泄露可能失败 | 运行时确认实际地址 |
| 5 | vivo SLUB_MIRROR 加固的影响 | ❓ 未知 | 堆喷可能失效 | 设备端测试时观察 |
| 6 | 时序噪声对碰撞检测的影响 | ❓ 未知 | 阶段 1 可能不稳定 | 设备端测试时观察 |
| 7 | kmalloc-rcl-* 新缓存类型 | ❓ 未知 | 堆布局可能不同 | 反汇编 kmalloc 相关函数 |

### 🟢 低风险（已绕过或影响有限）

| # | 问题 | 状态 | 对策 |
|---|------|------|------|
| 8 | vivo 符号过滤（commit_creds 等） | ✅ 已绕过 | 直接物理写 cred；用 __start_init_task |
| 9 | kallsyms 自定义 markers 格式 | ✅ 已解决 | 自研解析器 + markers 验证 |
| 10 | futex_key 布局差异 | ✅ 已解决 | 反汇编确认 mm@0/[mm,addr] |
| 11 | MM_STRUCT_SZ 错误 | ✅ 已修复 | 0x3C0（slabinfo 验证） |
| 12 | mm_slab_order 重置 bug | ✅ 已修复 | 保持 MM_ORDER(3) |
| 13 | 状态字符串数组缺项 | ✅ 已修复 | 指定索引初始化 |
| 14 | boot.img 提取 52 字节误判 | ✅ 已修复 | 正确提取（wrapper=0） |

---

## 失败原因总结

### 失败 1: 设备端 KernelSnitch mm 定位失败（历史）

**现象**:
```
[*] found 3 collisions              ← 阶段 1 成功
[-] KernelSnitch mm_struct leak failed  ← 阶段 2 失败
[-] prepare_kernel_page retry 1/12
... (12 次重试全部失败)
```

**根因**（事后分析，三个参数错误叠加）:
1. `MM_STRUCT_SZ = 0x340`（应为 0x3C0）→ 候选步长错误
2. `mm_slab_order` 被重置为 0（应为 3）→ slab 遍历错误
3. futex_key 布局当时判断混乱（但原始 typedef 恰好正确）

**修复状态**: 1 和 2 已修复，3 已确认正确。**未在设备端重测**。

### 失败 2: kallsyms 早期解析错误

**现象**: 109,641 符号（应为 109,687），init_task/commit_creds "缺失"

**根因**: names_start 偏晚 50 条，名字-偏移错位配对

**修复**: 通过 num_syms + markers 交叉验证，找到正确 names_start

### 失败 3: futex_key 布局三次错误判断

**详情**: 见 `docs/06_futex_hash_research.md` 和 `FAILED_ATTEMPTS.md`

**教训**: **上游源码 ≠ 设备内核**。必须反汇编设备固件确认。

---

## 下一步研究方向

### 优先级 1: 设备端验证（需要用户授权）

```bash
# 1. 只读参数诊断（安全）
adb push exploit/build/pd2055-4.19.152-perf/bin/diag_params /data/local/tmp/
adb shell /data/local/tmp/diag_params

# 2. 运行修复版 KernelSnitch（⚠️ 触发 CVE，可能崩溃设备）
# ⚠️ 需用户充分理解风险后手动执行
adb push exploit/build/pd2055-4.19.152-perf/bin/preload_noroot.so /data/local/tmp/
adb shell "LD_PRELOAD=/data/local/tmp/preload_noroot.so id"
```

### 优先级 2: 结构体偏移验证

```bash
# 提取 kheaders（CONFIG_IKHEADERS=y）
adb shell "cat /sys/kernel/kheaders.tar.xz" > kheaders.tar.xz
tar -xf kheaders.tar.xz
# 对比 task_struct/cred/pipe 的字段偏移
```

### 优先级 3: KASLR slide 泄露

```bash
# 方法 A: dmesg（如果可读）
adb shell "dmesg | grep 'Kernel Offset'"

# 方法 B: boot_id 侧信道（exploit 内置）
# 方法 C: kallsyms 地址泄露
```

### 优先级 4: 替代提权路径

如果 KernelSnitch 仍失败：
1. **CHEESE_BASE_HUNT**: configfs fops 劫持，不依赖 mm 定位
2. **直接 pipe physrw**: 拿到 pipe page 后即可物理读写
3. **修
改身份映射扫描区间**: 如果 DIRECT_MAP_BASE/END 不准确

---

## 完整研究时间线

| 时间 | 事件 | 状态 |
|------|------|------|
| 2026-11-08 23:00 | 开始研究 BL 解锁 → 发现不可能 | ✅ 结论 |
| 2026-11-08 23:30 | 分析所有临时 root 工具 → 均不支持 Neo5 | ✅ 结论 |
| 2026-11-09 00:00 | 用户触发 recovery 联网更新 → 抓取 OTA 日志 | ✅ 完成 |
| 2026-11-09 00:30 | OTA 协议破解（替换密码 + base64）| ✅ 完成 |
| 2026-11-09 01:40 | 固件下载完成（7GB）| ✅ 完成 |
| 2026-11-09 02:00 | kallsyms 早期解析（109,641，错位）| ❌ 错误 |
| 2026-11-09 02:34 | 构建第一版 exploit → 设备端测试失败 | ❌ 失败 |
| 2026-11-09 03:00 | 发现 MM_STRUCT_SZ/slab order 错误 | ✅ 修复 |
| 2026-11-09 03:24 | futex_key 第一次错误判断（2 u32）| ❌ 错误 |
| 2026-11-09 04:17 | futex_key 第二次错误判断（key+8）| ❌ 错误 |
| 2026-11-09 04:30 | futex_key 第三次判断（对照上游 v4.19）| ❌ 对上游对，对 vivo 错 |
| 2026-11-09 04:48 | **反汇编 vivo 内核 → 最终定论**（mm@0/[mm,addr]）| ✅ 正确 |
| 2026-11-09 05:00 | kallsyms 重新验证（109,687，6 重）| ✅ 完成 |
| 2026-11-09 05:30 | 单元测试 16/16 + 构建通过 | ✅ 完成 |
| 2026-11-09 06:00 | 修复状态字符串数组 | ✅ 完成 |
| 2026-11-09 06:30 | 开源整理（本任务）| 🔄 进行中 |

---

## 参考

- 所有文档: `docs/` 目录
- 失败尝试: `FAILED_ATTEMPTS.md`
- 时间线: `RESEARCH_TIMELINE.md`
- 已知限制: `KNOWN_LIMITATIONS.md`
- 变更日志: `CHANGELOG.md`
