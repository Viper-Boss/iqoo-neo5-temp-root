# vivo 4.19.152-perf+ 内核 futex 实现静态反汇编验证报告

> 目标：用真实 ARM64 反汇编证据，确认 vivo PD2055 内核的 `hash_futex()` /
> `get_futex_key()` 是否修改了 Linux v4.19 上游的 futex key 布局、哈希输入顺序、
> 哈希长度、哈希桶数量计算。
>
> **方法**：纯静态离线分析。不触发漏洞、不连接设备、不修改任何分区。
> **样本**：仓库内 `boot.img`（PD2055_A_9.10.3，100,663,296 B）。
> **工具**：`scripts/extract_boot_image.py`（提取 Image）+ capstone 5.0.9（反汇编）。
> **符号定位**：仓库内 `kallsyms.txt`（109,687 符号，markers 429/429 验证）。

---

## 0. 结论速览

| 项目 | 上游 Linux v4.19 | **vivo 4.19.152-perf+（实测）** | 是否被 vivo 修改 | 可信度 |
|------|------------------|-------------------------------|:---:|:---:|
| `futex_key` 字段布局 | address@0, mm@8, offset@16 | **mm@0, address@8, offset@16** | **是（与上游相反）** | 高（直接反汇编） |
| 哈希输入字顺序 | [addr_lo, addr_hi, mm_lo, mm_hi] | **[mm_lo, mm_hi, addr_lo, addr_hi]** | **是** | 高 |
| 哈希输入长度 | 4 × u32 | **4 × u32** | 否 | 高（种子常量证实） |
| 哈希 initval | both.offset | **both.offset (key+16)** | 否 | 高 |
| 哈希读取基址 | &key->both.word | **key+0** | 见下注 | 高 |
| hashsize 计算 | roundup_pow_of_two(256×cpus) | **同上游** | 否 | 高 |
| 哈希是否依赖 mm | 是 | **是** | 否 | 高 |

> **注（关键）**：vivo 的 `futex_key` 用的是 **旧版 mainline 布局**（mm/ptr 在偏移 0，
> address/word 在偏移 8），而上游 v4.19 在 2018 年后改成了 address/word 在偏移 0。
> vivo 4.19.152-perf+ 保留/回退了旧布局。**这与上游 v4.19 源码不一致**，因此任何
> 以上游 v4.19 `futex.h` 为准的用户态模型在本机都是错的。

> **对仓库历史的影响**：commit `e34852b` 曾把用户态 typedef "修正"为上游 v4.19 布局
> （address@0），并据此得出"哈希=[addr,mm]"。**该结论对 vivo 是错误的**，本报告用
> 反汇编证据予以推翻。原始 K40 exploit 的 typedef（mm@0）反而是与 vivo 匹配的。

---

## 1. 内核 Image 提取（可复现）

```
$ python3 scripts/extract_boot_image.py boot.img -o kernel_Image_v2 --report
[+] wrote kernel_Image_v2 (50759696 bytes)
    boot magic       : ANDROID!
    header_version   : 2
    page_size        : 4096
    kernel_size      : 50759696
    vendor wrapper   : 0 bytes before ARM64 Image (magic@0x38)
    ARM64 code0/1    : 0x14960000 0x00000000
    text_offset      : 0x80000
    image_size field : 0x3b84000
    flags field      : 0xa
```

**修正了此前两个错误认知**：
1. ARM64 magic 在标准偏移 0x38，**vendor wrapper = 0 字节**（此前"52 字节 vivo 头"是误判，
   旧 `kernel_Image` 被错误砍掉前 52 字节，导致所有文件偏移错位 52）。
2. `text_offset=0x80000`、`image_size`、`flags` **均完好未被清零**（此前"vivo 清零头字段"是误判）。

**偏移映射验证**（kallsyms 偏移 == Image 文件偏移，因 `_text` 在文件偏移 0）：

```
_text @ 0x0:        b #0x2580000              (code0 分支，合法 Image 头)
wake_up_process @0x870b8: stp x29,x30,[sp,#-0x10]!   (教科书函数序言)
get_futex_key @0x1407d8: sub sp,sp,#0x70; stp x29,x30,[sp,#0x20]; ...  (完整序言)
```
三个独立符号均落在合法函数入口 → 映射 `文件偏移 = kallsyms 偏移` 成立。**可信度：高**。

---

## 2. `get_futex_key` 反汇编 → futex_key 字段布局

符号地址（来自 kallsyms.txt）：`get_futex_key = 0x1407d8`（类型 t，static）。

函数签名（上游）：`get_futex_key(u32 __user *uaddr, int fshared, union futex_key *key, int rw)`
→ 寄存器：x0=uaddr, x1=fshared, **x2=key**, x3=rw。

### 2.1 关键指令（私有 futex 路径）

```asm
001407f8: mrs   x24, sp_el0          ; x24 = current（arm64 用 sp_el0 存 current）
00140808: and   w8, w0, #0xfff       ; w8 = uaddr & 0xfff  = 页内偏移
0014080c: ldr   x23, [x24, #0x580]   ; x23 = current->[0x580]  (= current->mm，见 §3)
00140810: str   w8, [x2, #0x10]      ; key[0x10] = 页内偏移   → offset @ +16
00140824: mov   x19, x2              ; x19 = key（保存到被调用者保存寄存器）
00140858: sub   x21, x0, x8          ; x21 = uaddr - (uaddr&0xfff) = 页对齐地址
0014085c: cbz   w1, #0x140a3c        ; fshared==0（私有 futex）→ 跳 0x140a3c
...
00140a3c: stp   x23, x21, [x19]      ; key[0]=x23=mm, key[8]=x21=address
```

`stp Xt1, Xt2, [Xn]` 语义：Xt1→[Xn+0]，Xt2→[Xn+8]。故：
- **key+0 = x23 = current->mm**
- **key+8 = x21 = 页对齐用户地址**
- **key+16 = 页内偏移（w8）**

另一条路径（0x140ac8/0x140ad0，文件-backed）同样是 `str x10,[x19]`(key+0) 与
`str x8,[x19,#8]`(key+8)，布局一致。

### 2.2 结论

vivo `futex_key` 物理布局（私有 futex）：

```
偏移 0  .. 7   : mm 指针        (private.mm / both 第一个被哈希的字)
偏移 8  .. 15  : 页对齐地址      (private.address)
偏移 16 .. 19  : offset (int)   (both.offset，页内偏移)
偏移 20 .. 23  : padding
sizeof = 24
```

**与上游 v4.19（address@0, mm@8）相反。可信度：高**（stp 语义明确，寄存器来源清晰）。

---

## 3. `task_struct.mm` 偏移交叉验证

为证明 §2 中 `current->[0x580]` 就是 `mm`（而非猜测），反汇编 `get_task_mm`：

符号地址：`get_task_mm = 0x3ccd8`。
`get_task_mm(task)`：`mm = task->mm; if (mm) mmgrab(mm); return mm;`

```asm
0003ccec: mov   x21, x0              ; x21 = task
0003ccf8: ldr   x20, [x21, #0x580]   ; x20 = task->[0x580]
0003ccfc: cbz   x20, #0x3cd1c        ; if (x20 == NULL) goto ret
...
0003cd24: mov   x0, x20              ; return x20
0003cd34: ret
```

返回值 x20 = `task->[0x580]`，即 **`task_struct.mm` 偏移 = 0x580**。

→ 反推 §2 中 `ldr x23, [x24, #0x580]`（x24=current）确为 `current->mm`。
**key+0 = current->mm 得证。可信度：高**（独立函数交叉验证）。

---

## 4. `hash_futex` 反汇编 → 哈希输入顺序与长度

`hash_futex()` 是 static 小函数，被**内联**进各调用者（kallsyms 无独立符号）。
通过交叉引用分析所有内联点。

### 4.1 全区域内联点扫描

在 futex 代码区（0x139000–0x140000）扫描 jhash2 种子常量 `0xdeadbeff` 的构造
（`mov wN,#0xbeff; movk wN,#0xdead,lsl#16`）：

```
找到 12 处内联 hash_futex 种子点（全部为 0xdeadbeff）：
  0x139468 0x139f9c 0x139fd4 0x13a314 0x13be88 0x13c8a0
  0x13deac 0x13e03c 0x13e198 0x13e228 0x13e274 0x13f594
```

**种子 = 0xdeadbeff 的含义**：jhash2 中 `a=b=c = JHASH_INITVAL + (length<<2) + initval`，
`JHASH_INITVAL=0xdeadbeef`。`0xdeadbeff = 0xdeadbeef + 16`，故 `length<<2 = 16` →
**length = 4 个 u32**。12 处全部一致 → **哈希长度恒为 4 u32。可信度：高**。

### 4.2 哈希基址与字顺序（futex_wake @ 0x13be10 详析）

`futex_wake` 中 `&key = x29-0x28`（见 `sub x2, x29, #0x28` 后 `bl get_futex_key`）。

```asm
0013be74: bl    #0x1407d8            ; get_futex_key(uaddr, fshared, &key, ...)
0013be7c: ldp   w12, w26, [x29,#-0x1c] ; w12=key+12, w26=key+16(=offset)
0013be84: ldp   w11, w8,  [x29,#-0x24] ; w11=key+4,  w8=key+8
0013be8c: ldur  w9,       [x29,#-0x28] ; w9=key+0
0013be80/88: mov/movk w10, #0xdeadbeff ; 种子
0013be90: add   w10, w26, w10        ; init = 0xdeadbeff + offset(key+16)
0013be94: add   w8,  w8,  w10        ; c = init + key+8
0013be98: add   w9,  w9,  w10        ; a = init + key+0
0013be9c: add   w10, w11, w10        ; b = init + key+4
0013bea0..: __jhash_mix(a,b,c) 的 sub/eor/ror 序列（ror #28/#26/#24/#16/#13...）
0013bee8: add   w11, w11, w12        ; a += key+12（第 4 个字，jhash2 尾轮）
0013bf3c: ldr   w10, [x10,#0xe40]    ; w10 = futex_hashsize（全局）
0013bf48: sub   w10, w10, #1         ; hashsize-1
0013bf54: and   x9, x10, x9          ; hash & (hashsize-1)
0013bf58: lsl   x10, x9, #6          ; ×64（sizeof futex_hash_bucket）
0013bf50: ldr   x8, [x12,#0xe30]     ; futex_queues 基址
```

被哈希的 4 个字 = **key+0, key+4, key+8, key+12**（基址 = key+0），initval = key+16。
结合 §2 布局（mm@key+0, address@key+8）：

```
哈希输入 = [key+0, key+4, key+8, key+12]
         = [mm_lo, mm_hi, address_lo, address_hi]
initval  = offset (key+16)
```

### 4.3 第二调用者交叉验证（0x13a314，do_futex 区）

```asm
0013a308: ldp w12, w24, [x29,#-0x6c]  ; key+12, key+16(offset)
0013a310: ldp w8,  w10, [x29,#-0x78]  ; key+0,  key+4
0013a318: ldur w9,      [x29,#-0x70]  ; key+8
```
key 槽 = x29-0x78，被哈希字 = key+0,+4,+8,+12，基址 key+0。**与 futex_wake 一致。**

### 4.4 结论

- 哈希读取基址 = **key+0**（非 key+8）。
- 哈希输入顺序 = **[mm_lo, mm_hi, addr_lo, addr_hi]**。
- 哈希长度 = **4 u32**（12 处种子全部 0xdeadbeff）。
- initval = **offset @ key+16**。
- 桶选择 = `hash & (futex_hashsize-1)`，bucket 大小 64B。**与上游一致。**
- **哈希依赖 mm**（mm 是被哈希的前两个字）。

**可信度：高**（多个独立内联点 + 种子常量 + 加载偏移三重印证）。

---

## 5. `futex_init` 反汇编 → hashsize 计算

符号地址：`futex_init = 0x2597b30`。

```asm
02597b54: ldrb w0, [x9,#0xbc8]    ; 读 nr_cpu_ids / possible cpus 相关字节
02597b58: bl   #0x571118          ; 调用（返回 cpu 数）
02597b5c: lsl  w8, w0, #8         ; w8 = cpus << 8 = 256 * cpus
02597b64: sub  x8, x8, #1         ; x8 = 256*cpus - 1
02597b6c: clz  x8, x8             ; 前导零计数
02597b74: neg  x8, x8             ; 取负
02597b8c: lsl  x2, x21, x8        ; x2 = 1 << (64 - clz(256*cpus-1)) = roundup_pow_of_two(256*cpus)
02597b98: str  x2, [x19,#0xe40]   ; futex_hashsize = x2  （全局 @0x2d8de40）
02597ba0: bl   #0x259f1ac         ; alloc_large_system_hash(...) → 输出 futex_shift
02597ba4: ldr  w8, [sp,#0x10]     ; w8 = futex_shift
02597bc0: lsl  x8, x21, x8        ; x8 = 1 << futex_shift
02597bc4: str  x8, [x19,#0xe40]   ; futex_hashsize = 1 << futex_shift
```

这与上游 v4.19 完全一致：
```c
futex_hashsize = roundup_pow_of_two(256 * num_possible_cpus());
futex_queues = alloc_large_system_hash(..., &futex_shift, ...);
futex_hashsize = 1UL << futex_shift;
```
且 `futex_hashsize` 全局位于 `0x2d8d000+0xe40`，与 §4.2 futex_wake 中
`ldr w10,[x10,#0xe40]`（adrp x10,#0x2d8d000）读取的位置一致。**可信度：高**。

设备实测佐证：此前真机日志 `futex_init hashsize=0x800 (cpus=8)`，
`roundup_pow_of_two(256×8)=2048=0x800` ✓。

---

## 6. 与用户态模型对照

| 模型 | typedef 布局 | 哈希基址 | 哈希字顺序 | 与 vivo 内核一致？ |
|------|-------------|---------|-----------|:---:|
| 上游 v4.19 源码 | address@0, mm@8 | key+0 | [addr, mm] | ❌ |
| 原始 K40 exploit | mm@0, address@8 | key+0 | [mm, addr] | ✅ |
| e34852b "修复" | address@0, mm@8 | key+0 | [addr, mm] | ❌（错误修复）|
| **本分支修复后** | **mm@0, address@8** | **key+0** | **[mm, addr]** | **✅** |

**最终修复方向**：用户态 typedef 必须用 **mm@0, address@8, offset@16**（vivo/旧 mainline 布局），
哈希从 **key+0** 读 4 个 u32，initval=offset。即恢复原始 K40 exploit 的物理布局，
但补充 `_Static_assert` 钉死偏移、保留 memset 清零、保留 mm 依赖探针与健全性门控。

---

## 7. 可信度与未决项

**高可信度（直接反汇编证据）**：
- futex_key 布局 mm@0/address@8/offset@16（get_futex_key stp + get_task_mm 交叉验证）
- 哈希从 key+0 读 4 u32、initval=offset、字顺序 [mm,addr]（futex_wake + 第二调用者 + 12 处种子）
- hashsize = roundup_pow_of_two(256×cpus)（futex_init）
- 哈希依赖 mm

**假设/未决（需进一步确认）**：
- 反汇编基于 `boot.img` 内的静态 Image；运行期 KASLR 不改变这些**相对**结论
  （布局、字顺序、长度均为相对量，与 slide 无关）。
- 仅分析了私有 futex 路径与 hash 长度；共享 futex 的 inode/pgoff 语义未逐字段展开
  （但 exploit 只用私有 futex，不影响结论）。
- 未动态验证（任务禁止真机触发）。所有结论均来自静态反汇编 + 上游源码对照。

---

## 8. 复现命令

```bash
# 1. 提取 Image
python3 scripts/extract_boot_image.py boot.img -o /tmp/kernel_Image_v2 --report

# 2. 反汇编（需 capstone：pip3 install capstone）
python3 scripts/disasm_futex.py /tmp/kernel_Image_v2 --sym get_futex_key
python3 scripts/disasm_futex.py /tmp/kernel_Image_v2 --sym futex_wake
python3 scripts/disasm_futex.py /tmp/kernel_Image_v2 --sym futex_init
python3 scripts/disasm_futex.py /tmp/kernel_Image_v2 --scan-hash   # 扫描全部 hash_futex 内联点
```

*（disasm_futex.py 见 scripts/，从 kallsyms.txt 解析符号地址，无需硬编码。）*
