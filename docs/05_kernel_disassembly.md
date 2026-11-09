# 05 - 内核反汇编 / Kernel Disassembly

> **文档状态**: ✅ 已完成  
> **最后更新**: 2026-11-09  
> **作者**: Viper-Boss

---

## 概述

本章节记录 ARM64 内核反汇编的环境搭建、符号映射、函数定位、证据保存和交叉验证方法。

**核心结论**: 
- kallsyms 符号偏移 == 正确提取的 Image 文件偏移（_text 在文件偏移 0）
- 反汇编工具：`scripts/disasm_futex.py`（capstone）
- 所有结论必须有 ARM64 指令证据，不允许猜测偏移

---

## 反汇编环境

### 依赖

```bash
# Python 3 + capstone
pip install capstone
```

### 工具

```bash
# 反汇编 futex 相关函数
python3 scripts/disasm_futex.py --from-boot boot.img --kallsyms kallsyms.txt

# 反汇编单个符号
python3 scripts/disasm_futex.py --from-boot boot.img --kallsyms kallsyms.txt \
    --sym get_futex_key --len 0x3c0

# 扫描内联 hash_futex 种子点
python3 scripts/disasm_futex.py --from-boot boot.img --kallsyms kallsyms.txt --scan-hash
```

---

## 符号映射

### 核心性质

**kallsyms 符号偏移 == 正确提取的 Image 文件偏移**

这是因为：
1. ARM64 Image 的 `_text` 在文件偏移 0
2. kallsyms_offsets 是相对 _text 的偏移
3. 因此 `symbol_offset == file_offset`

### 验证方法

反汇编已知符号，确认落在真实函数序言：

```bash
# _text @ 文件偏移 0
00000000: 00009614 b          #0x2580000   # code0 分支 ✓

# wake_up_process @ 0x870b8
000870b8: fd7bbfa9 stp        x29, x30, [sp, #-0x10]!   # 标准序言 ✓

# get_futex_key @ 0x1407d8
001407d8: ffc301d1 sub        sp, sp, #0x70              # 完整序言 ✓
```

### 自动验证

```bash
python3 scripts/verify_kallsyms.py --from-boot boot.img --kallsyms kallsyms.txt
```

输出 `[6] ARM64 spot-check` 部分会反汇编 7 个 text 符号并验证。

---

## 函数定位方法

### 1. 从 kallsyms 获取地址

```bash
# 查找符号
grep get_futex_key kallsyms.txt
# 输出: 001407d8 t get_futex_key
```

### 2. 反汇编

```bash
python3 scripts/disasm_futex.py --from-boot boot.img --kallsyms kallsyms.txt \
    --sym get_futex_key --len 0x3c0
```

### 3. 识别关键指令

对于 `get_futex_key`，关注：
- `mrs x24, sp_el0` → 获取 current 指针
- `str w8, [x2, #0x10]` → 存储到 key+16（offset 字段）
- `stp x23, x21, [x19]` → 存储到 key+0 和 key+8（mm 和 address）

---

## 证据保存

### 反汇编报告

所有关键发现记录在 `analysis/reports/futex_disassembly_report.md`，包括：

1. **get_futex_key 反汇编** → 证明 key 布局 mm@0/addr@8
2. **get_task_mm 反汇编** → 证明 task_struct.mm@0x580
3. **futex_wake 反汇编** → 证明内联 hash_futex 从 key+0 读 4 u32
4. **futex_init 反汇编** → 证明 hashsize = roundup_pow_of_two(256×cpus)
5. **12 处种子扫描** → 证明所有内联点使用 0xdeadbeff（长度 4）

### 可复现命令

```bash
# 复现报告中的所有证据
python3 scripts/disasm_futex.py --from-boot boot.img --kallsyms kallsyms.txt --scan-hash
```

---

## 交叉验证方法

### 1. 多函数验证

不依赖单一函数，而是反汇编多个相关函数：

```
get_futex_key  → key 布局
get_task_mm    → task_struct.mm 偏移
futex_wake     → hash_futex 内联
futex_init     → hashsize 计算
```

### 2. 多调用点验证

对于内联函数（如 hash_futex），扫描所有调用点：

```bash
python3 scripts/disasm_futex.py --from-boot boot.img --kallsyms kallsyms.txt --scan-hash
```

输出：
```
found 12 seed sites: 0x139468 0x139f9c 0x139fd4 0x13a314 0x13be88 ...
(each 0xdeadbeff = JHASH_INITVAL + (4<<2) => hash length 4 u32)
```

### 3. 寄存器追踪

追踪寄存器值，确认语义：

```asm
mrs   x24, sp_el0            ; x24 = current
ldr   x23, [x24, #0x580]     ; x23 = current->mm (需验证)
```

通过反汇编 `get_task_mm` 验证 `task_struct.mm@0x580`：

```asm
ldr x20, [x21, #0x580]   ; x21=task, 返回值 x20=task->mm
```

→ 确认 `current->[0x580]` 就是 `mm`。

---

## 关键发现

### futex_key 布局（vivo ≠ 上游）

| 项目 | 上游 Linux v4.19 | **vivo 4.19.152-perf+** |
|------|------------------|-------------------------|
| 布局 | address@0, mm@8 | **mm@0, address@8** |
| 哈希输入 | [addr, mm] | **[mm, addr]** |

**证据**: `get_futex_key@0x140a3c`: `stp x23(=mm), x21(=addr), [x19]`

### hash_futex 参数

```
基址: key+0
长度: 4 u32
initval: key+16 (offset)
字顺序: [mm_lo, mm_hi, addr_lo, addr_hi]
```

**证据**: `futex_wake@0x13be88` 加载 key+0/+4/+8/+12，种子 0xdeadbeff

### task_struct.mm 偏移

```
task_struct.mm @ 0x580
```

**证据**: `get_task_mm@0x3ccf8`: `ldr x20, [x21, #0x580]`

---

## 工具使用

### 基本用法

```bash
# 反汇编单个符号
python3 scripts/disasm_futex.py --from-boot boot.img --kallsyms kallsyms.txt \
    --sym <symbol_name> --len <hex_length>

# 示例
python3 scripts/disasm_futex.py --from-boot boot.img --kallsyms kallsyms.txt \
    --sym get_futex_key --len 0x3c0
```

### 默认输出

不带 `--sym` 参数时，自动反汇编：
- `get_task_mm`（0x40 字节）
- `get_futex_key`（0x60 字节）
- `futex_init`（0x90 字节）
- `futex_wake`（0xa0 字节）

### 扫描模式

```bash
# 扫描 futex 区所有内联 hash_futex 种子点
python3 scripts/disasm_futex.py --from-boot boot.img --kallsyms kallsyms.txt --scan-hash
```

---

## 已知限制

1. **capstone 依赖**: 需要 `pip install capstone`
2. **符号必须存在**: 如果符号被 vivo 过滤（如 `commit_creds`），无法反汇编
3. **内联函数**: 需要扫描所有调用点，不能直接定位

---

## 参考

- 反汇编工具: `scripts/disasm_futex.py`
- 完整报告: `analysis/reports/futex_disassembly_report.md`
- futex 哈希研究: `docs/06_futex_hash_research.md`
- 历史脚本: `research/archive/03_disassembly/`
