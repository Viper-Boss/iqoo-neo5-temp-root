# 04 - kallsyms 符号表恢复 / Kallsyms Recovery

> **文档状态**: ✅ 已完成  
> **最后更新**: 2026-11-09  
> **作者**: Viper-Boss

---

## 概述

本章节记录从 ARM64 内核镜像中提取 kallsyms 符号表的完整过程，包括：

- kallsyms 结构概述
- vivo 自定义格式（markers u32@8 步距）
- 早期错误（109,641 错位版本）
- 错误根因（names_start 偏晚 50 条）
- 正确解析（109,687，markers 429/429 验证）
- 6 重独立验证方法
- vivo 符号过滤（commit_creds 等被删除）

**结论**: 成功提取 109,687 个符号，全部经 markers 交叉验证。vivo 主动过滤了提权敏感符号。

---

## kallsyms 结构概述

Linux 内核的 kallsyms 包含以下部分：

```
┌─────────────────────────────────┐
│ kallsyms_offsets (s32 × N)      │  符号偏移（相对 _text）
├─────────────────────────────────┤
│ relative_base (u64)             │  _text 的虚拟地址
├─────────────────────────────────┤
│ num_syms (u64)                  │  符号数量
├─────────────────────────────────┤
│ names (compressed)              │  压缩的符号名
├─────────────────────────────────┤
│ markers (u32 × N/256)           │  每 256 个符号的偏移标记
├─────────────────────────────────┤
│ token_table (256 strings)       │  压缩令牌表
├─────────────────────────────────┤
│ token_index (u16 × 256)         │  令牌索引
└─────────────────────────────────┘
```

### 标准格式（上游 Linux）

- **markers**: 紧凑 u32 数组，`markers[k]` = 第 `256*k` 个符号在 names 区的字节偏移
- **names**: `[u8 len][tokens...]` 格式（4.19），或带 0x80 扩展长度（5.x+）

### vivo 自定义格式

vivo 4.19.152-perf+ 使用**非标准 markers 格式**：

```c
// 标准上游
u32 markers[N/256];  // 紧凑数组

// vivo 自定义
u32 markers[N/256] @ 8-byte stride;  // 每个 marker 占 8 字节（高 4 字节为 0）
```

这导致 `vmlinux-to-elf` 等工具失败（找不到标准 markers）。

---

## 早期错误：109,641 错位版本

### 错误现象

早期解析报告：
- 符号数量：109,641
- names_start: 0x1febb9b
- offsets_start: 0x1f805bc

**问题**: `init_task`、`commit_creds`、`_text`、`_stext` 等关键符号"缺失"。

### 错误根因

**names_start 偏晚 50 条**，导致：
- 解析出 109,641 个名字（应为 109,687）
- 名字与偏移错位配对（第 i 个名字对应第 i+50 个偏移）
- 关键符号"消失"（实际在错位的前 50 条中）

### 发现过程

1. 检查 offsets 表尾部：发现 109,691 个非递减 s32
2. 检查 num_syms 位置：0x1feb8cc 处 u32 = 0x1AC77 = **109,687**
3. 暴力搜索 names_start：从 0x1feb7a8 开始，找到 0x1feb9cc 时解析出恰好 109,687 个名字
4. markers 交叉验证：429/429 全部匹配

### 修正后的正确结构

```
offsets_start : 0x1f80600  (109,687 × s32)
num_syms      : u32 @ 0x1feb900 = 0x1AC77 = 109,687
names_start   : 0x1feba00
names_end     : 0x2159082  (zero-length terminator)
markers       : 0x2159100  (429 × u32 @ 8-byte stride)
token_table   : 0x2159f00  (256 tokens)
token_index   : 0x215a300  (256 × u16)
```

**注意**: 这些偏移是**正确提取的 Image**（无 52 字节截断）内的偏移。旧镜像偏移需 +52。

---

## 正确解析流程

### 工具

```bash
# 1. 提取内核镜像
python3 scripts/extract_boot_image.py boot.img -o kernel_Image

# 2. 解析 kallsyms（运行时 markers 自校验）
python3 scripts/parse_kallsyms.py kernel_Image -o kallsyms.txt

# 3. 6 重独立验证
python3 scripts/verify_kallsyms.py --image kernel_Image --kallsyms kallsyms.txt
```

### 验证输出

```
[+] extracted kernel Image: 50759696 bytes

[1] count consistency
  [PASS] parsed names == num_syms (109687 == 109687)

[2] offsets array (re-read from image)
  [PASS] monotonic non-decreasing (0 violations)
  [PASS] offsets[0] == 0 (_text), got 0x0
  [PASS] matches committed dump (109687 rows, 0 mismatches)

[3] markers cross-check
  [PASS] markers[k] == name[256k] offset (429/429)

[4] section ordering (independent pairing proof)
      type T: n= 29503 min=0x00000000 med=0x00a60598 max=0x029199b8
      type R: n=   667 min=0x01980000 med=0x01d3dc28 max=0x0266dad0
      type D: n=  3025 min=0x0291a000 med=0x02fb8d10 max=0x03069000
      type B: n=  1299 min=0x03069000 med=0x0338c6e8 max=0x03b80700
  [PASS] text median 0xa60598 < bss median 0x338c6e8

[5] source-adjacent clustering
  [PASS] mm/ashmem.c: 4 syms span 2432 bytes (<0x8000)
  [PASS] kernel/cred.c: 4 syms span 776 bytes (<0x8000)

[6] ARM64 spot-check (text symbol offset == file offset)
      wake_up_process        @0x000870b8: stp x29, x30, [sp, #-0x10]!
      printk                 @0x000e0c28: sub sp, sp, #0x120
      panic                  @0x000400a0: sub sp, sp, #0x160
      schedule               @0x0179ffe0: stp x29, x30, [sp, #-0x20]!
      get_futex_key          @0x001407d8: sub sp, sp, #0x70
      kallsyms_lookup_name   @0x0014c278: sub sp, sp, #0xe0
      do_exit                @0x00045d60: sub sp, sp, #0x80
  [PASS] 7/7 text probes decode to valid ARM64

========================================================
 Result: 9 passed, 0 failed
========================================================
```

---

## 6 重独立验证

仅 markers 429/429 匹配**不足以**证明所有符号偏移正确（markers 只验证每 256 个符号的边界）。因此增加 5 重额外验证：

### 1. 计数一致性

```
parsed names == num_syms == offsets count
```

### 2. offsets 数组单调性

```
offsets[i] <= offsets[i+1]  (0 violations)
offsets[0] == 0  (_text)
```

### 3. markers 交叉验证

```
markers[k] == (byte offset of name[256*k]) - names_start
429/429 exact matches
```

### 4. 段序分层（独立配对证明）

```
text(T/t) < rodata(R/r) < data(D/d) < bss(B/b)
```

如果名字-偏移错位，类型会随机散布在各段。实际观察到完美分层 → **配对正确**。

### 5. 同源符号聚簇

同一 `.c` 文件定义的函数应有相邻偏移：

```
ashmem_ioctl, ashmem_mmap, ashmem_open, ashmem_release
  → span 2432 bytes (< 0x8000)
```

### 6. ARM64 序言抽查

text 符号的文件偏移应解码为真实 ARM64 指令：

```
wake_up_process @0x870b8: stp x29, x30, [sp, #-0x10]!  (标准序言)
```

7/7 通过 → **符号偏移 == 文件偏移**（_text 在文件偏移 0）。

---

## vivo 符号过滤

### 被过滤的符号

以下在通用内核中必然存在的符号，在本 kallsyms 中被**精确移除**：

```
commit_creds          prepare_kernel_cred    init_cred
kernel_init           init_task              _end
__init_begin          __bss_start            _edata        _sdata
```

### 过滤目的

这是 vivo 的**反利用加固**：
- 阻止 `commit_creds(prepare_kernel_cred(0))` 经典提权路径
- 阻止 `kallsyms_lookup_name("commit_creds")` 动态解析
- 增加 exploit 开发难度

### 对策

本 exploit **不调用** `commit_creds`，而是：
1. 用 `__start_init_task`（段起始符号，未被过滤）代替 `init_task`
2. 通过 pipe 物理内存写**直接**修改 `current->cred` 的 uid/gid/caps
3. 运行时从 `init_task.real_cred` 读出 `init_cred`

因此符号过滤**不致命**，但任何依赖 `kallsyms_lookup_name()` 的工具在此设备上都会失败。

---

## 工具使用

### 解析 kallsyms

```bash
# 从 boot.img 直接解析（推荐）
python3 scripts/parse_kallsyms.py --from-boot boot.img -o kallsyms.txt

# 从已提取的 kernel_Image 解析
python3 scripts/parse_kallsyms.py kernel_Image -o kallsyms.txt
```

### 验证 kallsyms

```bash
# 6 重验证
python3 scripts/verify_kallsyms.py --from-boot boot.img --kallsyms kallsyms.txt

# 或从已提取的 Image
python3 scripts/verify_kallsyms.py --image kernel_Image --kallsyms kallsyms.txt
```

### 生成 target.h 偏移

```bash
python3 scripts/gen_target_offsets.py --kallsyms kallsyms.txt -o target_offsets.txt
```

---

## 已知限制

1. **vivo 自定义 markers**: 标准工具（`vmlinux-to-elf`）无法处理
2. **符号过滤**: 部分关键符号被删除，需 workaround
3. **结构常量**: `scripts/kallsyms_layout.json` 中的偏移仅适用于 PD2055_A_9.10.3

---

## 参考

- 解析工具: `scripts/parse_kallsyms.py`
- 验证工具: `scripts/verify_kallsyms.py`
- 偏移生成: `scripts/gen_target_offsets.py`
- 结构常量: `scripts/kallsyms_layout.json`
- 错误历史: `FAILED_ATTEMPTS.md`（109,641 错位版本）
- 历史脚本: `research/archive/02_kallsyms/`
