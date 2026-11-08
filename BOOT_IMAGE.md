# Boot Image Analysis — PD2055_A_9.10.3

本文件记录从 `boot.img` 提取内核与 kallsyms 的**已验证**结构，供社区复现。

## boot.img (96 MB)

从 7GB 全量 OTA 包 `PD2055_A_9.10.3_full.zip` 中提取。

### Android boot image v2 头
```
magic:          ANDROID!
kernel_size:    50,759,696 bytes (48.4 MB)
kernel_addr:    0x8000
ramdisk_size:   821,139 bytes
page_size:      4096
header_version: 2
```

### 内核 Image 布局
内核数据从 `page_size`(4096) 偏移开始，但真正的 ARM64 Image 前有一个 **52 字节 vivo 包装头**：
```
[0 .. 51]    vivo 自定义头（52 字节，大部分为 0）
[52 .. end]  ARM64 kernel Image (48.4 MB)
```

ARM64 Image 头（偏移 52 处）：
- `code0 = 0x00000000` (NOP)
- `magic = "ARM\x64"` @ +4 ✓
- `text_offset = 0` ← **被 vivo 清零**（正常应为 0x80000）
- `image_size = 0`   ← **被 vivo 清零**
- `flags = 0`        ← **被 vivo 清零**

这些字段被清零是反逆向措施，导致 `vmlinux-to-elf`、`ghostlock-extract` 等工具失败。

## Kallsyms 结构（全部经 markers 交叉验证）

| 结构 | 文件偏移 | 大小/数量 | 备注 |
|------|---------|----------|------|
| offsets 表 | `0x1f805cc` .. `0x1feb7a8` | 109,687 × s32 | 首值=0, 尾值=0x3b80708, 0 单调违反 |
| num_syms | u32 @ `0x1feb8cc` | = 0x1AC77 = 109,687 | 与解析计数完全一致 |
| names | `0x1feb9cc` .. `0x215904e` | 压缩 | 4.19 格式 `[u8 len][tokens]`，无 0x80 扩展 |
| markers | `0x21590cc` | 429 × u32 @ **8 字节步距** | vivo 自定义（上游是紧凑 u32 数组） |
| token table | `0x2159ecc` | 256 tokens, 909 B | token[48]='0' |
| token index | `0x215a2cc` | 256 × u16 | 验证 256/256 |

### 验证方法（决定性）
全部 **429 个 markers** 满足：
```
markers[k] == (name[256*k] 的字节偏移) − names_start
```
**429/429 精确匹配** → 证明 `names_start=0x1feb9cc`、`num_syms=109687`、
offsets 表对齐三者逐字节正确。`_text` 偏移 == 0 → offsets 已相对 `_text`
（CONFIG_KALLSYMS_BASE_RELATIVE，relative_base 即 `_text` VA）。

复现：`python3 scripts/verify_kallsyms.py`

## vivo 反逆向 + 符号过滤

1. ARM64 Image 头字段清零（text_offset / image_size / flags）
2. kallsyms_markers 用 u32@8 步距（非标准紧凑数组）
3. **符号过滤**：从 kallsyms 删除了提权敏感符号——
   `commit_creds`、`prepare_kernel_cred`、`init_cred`、`kernel_init`、
   `init_task`、`_end`、`__init_begin`、`__bss_start`、`_edata`、`_sdata`。
   对策见 README §6.5（用 `__start_init_task` 代替 `init_task`；本 exploit
   直接改 cred 而非调用 commit_creds）。

## xbl_config.elf (92 KB)

XBL 配置，内含 FDT（内存映射、外设基址），可推导内核物理加载地址。
**不含**解锁逻辑或 devinfo 标志（那些在 abl.elf / devinfo 分区）。

---

> 7GB 完整固件包因体积无法上传 GitHub。下载方法见 README §5 与 `tools/vivo_ota.py`。
