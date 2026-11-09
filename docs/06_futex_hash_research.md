# 06 - futex 哈希研究 / Futex Hash Research

> **文档状态**: ✅ 已完成  
> **最后更新**: 2026-11-09  
> **作者**: Viper-Boss

---

## 概述

本章节记录 futex 哈希算法的完整研究过程，包括：

- 上游 Linux v4.19 与 vivo 4.19.152-perf+ 的差异
- futex_key 字段顺序的三次判断（两次错误，最终正确）
- 哈希算法参数（基址、长度、initval、字顺序）
- 错误教训（为什么仅参照上游源码不够）
- 最终证据（设备固件反汇编）

**核心结论**: vivo 4.19.152-perf+ 使用**旧版 mainline 布局**（mm@0, address@8），与上游 Linux v4.19（address@0, mm@8）**相反**。哈希 = `jhash2([mm_lo, mm_hi, addr_lo, addr_hi], offset)`，**依赖 mm**。

---

## 背景：KernelSnitch 为什么需要 futex 哈希

KernelSnitch 技术通过 futex 哈希碰撞来定位内核 `mm_struct` 地址：

1. **碰撞发现**: 创建多个用户态 futex，通过时序侧信道检测哪些地址哈希到同一 bucket
2. **暴力反推**: 遍历所有可能的 mm 候选地址，计算 `futex_hash(addr, candidate)`
3. **匹配验证**: 如果某候选值使所有碰撞地址都哈希到同一 bucket，则该候选就是真实 mm

**前提**: 用户态的 futex 哈希实现必须与内核**逐位一致**，否则暴力反推会失败。

---

## 三次判断，两次错误

### 第一次判断（v1）: "内核只哈希 2 个 u32，不含 mm"

**结论**: 错误

**依据**: 错误地分析了 `hash_futex()` 的 `sizeof(key->both.word)/4` 参数。

**错误原因**: 混淆了 `sizeof(key->both.word)`（8 字节 = 2 u32）和完整的哈希长度。

### 第二次判断（v2, commit e34852b）: "内核从 key+8 哈希 4 个 u32，仍不含 mm"

**结论**: 仍然错误

**依据**: 对照上游 v4.19 源码，"修复"了 v1 的错误。但参考结构体也抄反了。

**错误原因**: 
1. 误以为 `&key->both.word` 是 key+8（实际上在 vivo 中是 key+0，在上游中也是 key+0 但字段名不同）
2. **参考结构体 `kernel_futex_key_t` 也抄反了**（ptr@0, word@8），与错误的 exploit typedef 犯了同一个错
3. "错代码 vs 错参考"互相匹配 → 假通过

### 第三次判断（v3, commit 43460fa）: "对照上游 v4.19，address@0/mm@8，哈希=[addr,mm]"

**结论**: 对上游对，但对 vivo 错！

**依据**: 逐字核对 Linux v4.19 `include/linux/futex.h`。

**错误原因**: 
1. 上游 v4.19 确实是 `address@0, mm@8`（v3 对此判断正确）
2. **但 vivo 4.19.152-perf+ 不是上游！** vivo 保留了旧版 mainline 布局（mm@0, address@8）
3. 以上游为参照做出的"修复"，对这个设备反而是错的

### 第四次判断（v4, 最终）: 反汇编 vivo 固件，mm@0/[mm,addr]

**结论**: 正确（有反汇编铁证）

**依据**: 对 PD2055 boot.img 中的真实内核进行反汇编。

**证据链**:
1. `get_futex_key@0x1407d8`: `stp x23(=mm), x21(=addr), [x19]` → mm@0, addr@8
2. `get_task_mm@0x3ccd8`: `ldr x20, [x21, #0x580]` → task_struct.mm@0x580
3. `futex_wake@0x13be88`: 加载 key+0/+4/+8/+12 → 哈希从 key+0 读 4 u32
4. 12 处内联 hash_futex 种子全为 0xdeadbeff → 长度恒为 4 u32

---

## vivo vs 上游 Linux v4.19

### futex_key 字段顺序

| 字段 | 上游 v4.19 | **vivo 4.19.152-perf+** |
|------|-----------|------------------------|
| 偏移 0 | `address` (unsigned long) | **`mm`** (mm_struct *) |
| 偏移 8 | `mm` (mm_struct *) | **`address`** (unsigned long) |
| 偏移 16 | `offset` (int) | `offset` (int) |

### 哈希输入

| 项目 | 上游 v4.19 | **vivo 4.19.152-perf+** |
|------|-----------|------------------------|
| 基址 | key+0 | key+0 |
| 长度 | 4 u32 | 4 u32 |
| initval | key+16 (offset) | key+16 (offset) |
| 字顺序 | [addr_lo, addr_hi, mm_lo, mm_hi] | **[mm_lo, mm_hi, addr_lo, addr_hi]** |

### hashsize 计算

| 项目 | 上游 v4.19 | **vivo 4.19.152-perf+** |
|------|-----------|------------------------|
| 公式 | roundup_pow_of_two(256 × cpus) | **相同** |

---

## 关键教训

### 为什么仅参照上游源码不够

> **上游源码 ≠ 设备内核**

vivo 对内核做了多项定制修改：
1. **futex_key 布局反转**（mm@0 而非 address@0）
2. **kallsyms 符号过滤**（删除 commit_creds 等）
3. **markers 自定义格式**（u32@8 步距）
4. **SLUB_MIRROR 等加固**（反利用）

以上游源码为参照的模型，在 vivo 设备上可能全部失效。

### 为什么必须反汇编设备固件

只有反汇编**设备实际运行的内核**，才能确认：
1. 结构体字段顺序是否被修改
2. 函数是否被内联或修改
3. 编译器优化是否改变了预期行为

### 验证方法

不依赖单一证据，而是：
1. **多函数交叉验证**（get_futex_key + get_task_mm + futex_wake）
2. **多调用点验证**（12 处内联 hash_futex 种子）
3. **寄存器追踪**（确认 current->mm 的语义）
4. **独立单元测试**（参考实现从反汇编导出，不复制 exploit 代码）

---

## 用户态实现（futex_hash.h）

### 当前实现（与 vivo 一致）

```c
typedef union {
    struct {
        uint64_t i_seq;
        unsigned long pgoff;
        unsigned int offset;
    } shared;
    struct {
        union {
            void *mm;              /* @0  (target: current->mm) */
            uint64_t __tmp;
        };
        unsigned long address;     /* @8  (page-aligned uaddr) */
        unsigned int offset;       /* @16 */
    } private;
    struct {
        uint64_t ptr;              /* @0  (aliases private.mm) */
        unsigned long word;        /* @8  (aliases private.address) */
        unsigned int offset;       /* @16 */
    } both;
} futex_key_t;

_Static_assert(OFFSET_OF(futex_key_t, private.mm) == 0, "target: private.mm @0");
_Static_assert(OFFSET_OF(futex_key_t, private.address) == 8, "target: private.address @8");
_Static_assert(OFFSET_OF(futex_key_t, both.offset) == 16, "both.offset @16");

uint32_t futex_hash_no_trunc(futex_key_t *key)
{
    return jhash2((uint32_t *)key, 4, key->both.offset);
}
```

### 单元测试

```bash
make test
# 16/16 PASS（含 target≠upstream 断言）
```

---

## 反汇编证据（详细）

### get_futex_key（私有 futex 路径）

```asm
001407f8: mrs   x24, sp_el0          ; x24 = current
00140808: and   w8, w0, #0xfff       ; w8 = uaddr & 0xfff（页内偏移）
0014080c: ldr   x23, [x24, #0x580]   ; x23 = current->mm
00140810: str   w8, [x2, #0x10]      ; key+16 = offset
00140824: mov   x19, x2              ; x19 = key
00140858: sub   x21, x0, x8          ; x21 = 页对齐地址
0014085c: cbz   w1, #0x140a3c        ; 私有 futex → 跳到 0x140a3c
...
00140a3c: stp   x23, x21, [x19]      ; key+0 = mm, key+8 = address
```

### futex_wake（内联 hash_futex）

```asm
0013be74: bl    #0x1407d8            ; call get_futex_key
0013be7c: ldp   w12, w26, [x29,#-0x1c] ; w12=key+12, w26=key+16(=offset)
0013be84: ldp   w11, w8,  [x29,#-0x24] ; w11=key+4, w8=key+8
0013be8c: ldur  w9,       [x29,#-0x28] ; w9=key+0
0013be80: mov   w10, #0xbeff          ; 种子低半
0013be88: movk  w10, #0xdead, lsl#16  ; 种子 = 0xdeadbeff
0013be90: add   w10, w26, w10        ; init = 0xdeadbeff + offset
0013be94: add   w8,  w8,  w10        ; c = init + key+8
0013be98: add   w9,  w9,  w10        ; a = init + key+0
0013be9c: add   w10, w11, w10        ; b = init + key+4
```

### 种子常量分析

```
0xdeadbeff = 0xdeadbeef + 16
           = JHASH_INITVAL + (4 << 2)
           = JHASH_INITVAL + (length << 2)
```

→ **length = 4**（4 个 u32 = 16 字节）

### 12 处内联点

```
0x139468  0x139f9c  0x139fd4  0x13a314  0x13be88  0x13c8a0
0x13deac  0x13e03c  0x13e198  0x13e228  0x13e274  0x13f594
```

全部使用相同的种子 0xdeadbeff（长度 4），证实哈希参数一致。

---

## 工具使用

### 复现反汇编

```bash
python3 scripts/disasm_futex.py --from-boot boot.img --kallsyms kallsyms.txt --scan-hash
```

### 运行单元测试

```bash
cd exploit && make test
# 16/16 PASS
```

---

## 已知限制

1. **仅验证了静态 Image**: 反汇编基于 boot.img 中的静态内核，运行时行为可能不同（但布局/字顺序等相对量不受影响）
2. **仅分析了私有 futex**: 共享 futex 的 inode/pgoff 路径未展开（exploit 只用私有 futex）
3. **KernelSnitch 尚未在设备端验证成功**: 哈希已与目标内核一致，但定位 mm 还需正确的 mm_struct 大小/slab 参数/扫描区间/时序稳定性

---

## 参考

- 反汇编报告: `analysis/reports/futex_disassembly_report.md`
- 反汇编工具: `scripts/disasm_futex.py`
- 单元测试: `exploit/tests/test_futex_hash.c`
- futex 实现: `exploit/src/kernelsnitch/futex_hash.h`
- KernelSnitch: `docs/07_kernelsnitch_porting.md`
- 失败尝试: `FAILED_ATTEMPTS.md`（三次判断的详细记录）
