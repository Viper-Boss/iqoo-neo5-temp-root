# Boot Image Analysis — PD2055_A_9.10.3

本文件记录从 `boot.img` 提取内核与 kallsyms 的**已验证**结构，供社区复现。
所有数字由 `scripts/extract_boot_image.py` + `scripts/verify_kallsyms.py` 复核。

## boot.img (96 MB = 100,663,296 B)

从 7GB 全量 OTA 包 `PD2055_A_9.10.3_full.zip` 提取。

### Android boot image v2 头
```
magic          : ANDROID!
header_version : 2
kernel_size    : 50,759,696 B (48.4 MB)
kernel_addr    : 0x8000
ramdisk_size   : 821,139 B
page_size      : 4096
```

### 内核 Image 布局（修正：无 vendor 包装头）
内核 blob = `boot.img[page_size : page_size + kernel_size]`。
ARM64 Image magic `"ARM\x64"` 位于 blob 偏移 **0x38**（标准位置），故：

```
vendor wrapper : 0 字节   ← 修正！此前"52 字节 vivo 头"是误判
ARM64 Image    : blob[0:] = 50,759,696 B（完整，_text 在文件偏移 0）
```

ARM64 Image 头字段（**均完好，未被清零**——此前"vivo 清零头字段"亦为误判）：
```
code0       = 0x14960000   (b 分支，跳过头部)
code1       = 0x00000000
text_offset = 0x80000
image_size  = 0x3b84000
flags       = 0xa
```

> ⚠️ 早期分析曾把内核 blob 砍掉前 52 字节（`kernel_raw[52:]`），导致所有文件偏移
> 错位 52。正确做法是 `kernel_raw[0:]`（magic 在标准 0x38）。本仓库的
> `kallsyms.txt` 符号偏移是 kallsyms **值**（相对 _text），不受此影响；但任何
> "符号偏移 == 文件偏移"的用法必须基于**正确提取**的 Image。

## Kallsyms 结构（在正确提取的 Image 内，全部经 markers 交叉验证）

| 结构 | 文件偏移 | 大小/数量 | 备注 |
|------|---------|----------|------|
| offsets 表 | `0x1f80600` | 109,687 × s32 | 首值=0，尾值=0x3b80708，0 单调违反 |
| num_syms | u32 @ `0x1feb900` | = 0x1AC77 = 109,687 | 与解析计数一致 |
| names | `0x1feba00` .. `0x2159082` | 压缩 | 4.19 格式 `[u8 len][tokens]`，无 0x80 扩展 |
| markers | `0x2159100` | 429 × u32 @ **8 字节步距** | vivo 自定义（上游为紧凑 u32 数组）|
| token table | `0x2159f00` | 256 tokens | |
| token index | `0x215a300` | 256 × u16 | |

这些常量存于 `scripts/kallsyms_layout.json`，每次运行 `parse_kallsyms.py` /
`verify_kallsyms.py` 都会用 markers 重新验证。

### 验证方法（决定性）
全部 **429 个 markers** 满足：
```
markers[k] == (name[256*k] 的字节偏移) − names_start
```
**429/429 精确匹配** → 证明 names_start、num_syms、offsets 表对齐逐字节正确。
`_text` 偏移 == 0 → 符号偏移已相对 `_text`（CONFIG_KALLSYMS_BASE_RELATIVE）。

另有 5 重独立校验（见 `verify_kallsyms.py`）：计数一致、offsets 单调、段序分层
（text < rodata < data < bss）、同源符号聚簇、ARM64 序言抽查（符号偏移==文件偏移，
get_futex_key@0x1407d8 / get_task_mm@0x3ccd8 / wake_up_process@0x870b8 均落在真实序言）。

复现：
```bash
python3 scripts/extract_boot_image.py boot.img -o /tmp/kernel_Image --report
python3 scripts/parse_kallsyms.py --from-boot boot.img -o /tmp/kallsyms.txt
python3 scripts/verify_kallsyms.py --from-boot boot.img --kallsyms kallsyms.txt
```

## vivo 反逆向 + 符号过滤

1. kallsyms_markers 用 u32@8 步距（非标准紧凑数组）
2. **符号过滤**：从 kallsyms 删除提权敏感符号——
   `commit_creds`、`prepare_kernel_cred`、`init_cred`、`kernel_init`、
   `init_task`、`_end`、`__init_begin`、`__bss_start`、`_edata`、`_sdata`。
   对策见 README §6.5（用 `__start_init_task` 代替 `init_task`；本 exploit 直接改
   cred 而非调用 commit_creds）。
3. **futex_key 布局与上游 v4.19 相反**：vivo 用旧 mainline 布局 mm@0/address@8，
   哈希 = jhash2([mm,addr], offset)。详见 `analysis/futex_disassembly_report.md`。

> 注：此前"ARM64 Image 头字段被清零"的说法是误判——头字段完好（text_offset=0x80000）。

## xbl_config.elf (92 KB)

XBL 配置，内含 FDT（内存映射、外设基址），可推导内核物理加载地址。
**不含**解锁逻辑或 devinfo 标志（那些在 abl.elf / devinfo 分区）。

---

> 7GB 完整固件包因体积无法上传 GitHub。下载方法见 README §5 与 `tools/vivo_ota.py`。
