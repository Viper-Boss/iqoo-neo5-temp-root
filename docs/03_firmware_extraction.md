# 03 - 固件提取 / Firmware Extraction

> **文档状态**: ✅ 已完成  
> **最后更新**: 2026-11-09  
> **作者**: Viper-Boss

---

## 概述

本章节记录从 vivo OTA 固件包中提取 ARM64 内核镜像的完整过程，包括：

- Android boot image v2 结构解析
- 内核镜像提取（`extract_boot_image.py`）
- ARM64 Image 头字段验证
- vivo 反逆向措施分析
- 错误历史（52 字节截断误判）

**结论**: boot.img 使用标准 Android v2 头，内核镜像从 `page_size` 偏移开始，**无 vendor wrapper**（早期"52 字节 vivo 头"是误判）。

---

## 固件获取

### 下载方法

通过破解的 vivo OTA 协议获取下载 URL（详见 `docs/02_ota_protocol_analysis.md`）：

```bash
# 查询固件 URL
python3 tools/vivo_ota.py query PD2055 V2055A 9.10.3

# 下载（~7GB，~110 MB/s）
python3 tools/vivo_ota.py download <url> PD2055_A_9.10.3_full.zip
```

### 固件包内容

```
PD2055_A_9.10.3_full.zip (7,039,074,100 bytes, 317 entries)
├── boot.img           (100,663,296 bytes)    ← 内核 + ramdisk
├── recovery.img       (100,663,296 bytes)
├── dtbo.img           (25,165,824 bytes)
├── system.img         (多个 sparse 分片)
├── vendor.img         (多个 sparse 分片)
├── odm.img            (多个 sparse 分片)
└── ...
```

---

## boot.img 结构解析

### Android boot image v2 头

```c
struct boot_img_hdr {
    char magic[8];              // "ANDROID!"
    uint32_t kernel_size;       // 内核大小
    uint32_t kernel_addr;       // 内核加载地址
    uint32_t ramdisk_size;      // ramdisk 大小
    uint32_t ramdisk_addr;      // ramdisk 加载地址
    uint32_t second_size;       // 第二阶段大小
    uint32_t second_addr;       // 第二阶段加载地址
    uint32_t tags_addr;         // 标签地址
    uint32_t page_size;         // 页大小
    uint32_t header_version;    // 头版本 (0/1/2)
    uint32_t os_version;        // OS 版本
    char name[16];              // 名称
    char cmdline[512];          // 命令行
    // ... v1/v2 扩展字段
};
```

### PD2055 boot.img 实际值

```
magic          : ANDROID!
header_version : 2
kernel_size    : 50,759,696 bytes (48.4 MB)
kernel_addr    : 0x8000
ramdisk_size   : 821,139 bytes
page_size      : 4096
```

---

## 内核镜像提取

### 提取方法

使用 `scripts/extract_boot_image.py`：

```bash
# 从 boot.img 提取 ARM64 内核镜像
python3 scripts/extract_boot_image.py boot.img -o kernel_Image --report
```

### 提取逻辑

```python
# 1. 解析 boot image 头
hdr = parse_boot_header(data)
page_size = hdr['page_size']  # 4096
kernel_size = hdr['kernel_size']  # 50,759,696

# 2. 提取内核 blob
kernel_raw = data[page_size : page_size + kernel_size]

# 3. 定位 ARM64 Image 头
# ARM64 magic "ARM\x64" 在 Image 偏移 0x38
magic_pos = kernel_raw.find(b"ARM\x64")
image_start = magic_pos - 0x38

# 4. 提取真实 Image
kernel_Image = kernel_raw[image_start:]
```

### 提取结果

```
[+] wrote kernel_Image (50759696 bytes)
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

---

## ARM64 Image 头字段

### 标准 ARM64 Image 头

```c
struct arm64_image_header {
    uint32_t code0;           // 偏移 0x00: 分支指令
    uint32_t code1;           // 偏移 0x04: 保留
    uint64_t text_offset;     // 偏移 0x08: .text 段偏移
    uint64_t image_size;      // 偏移 0x10: 镜像大小
    uint64_t flags;           // 偏移 0x18: 标志位
    uint32_t res2;            // 偏移 0x20: 保留
    uint32_t res3;            // 偏移 0x24: 保留
    uint32_t res4;            // 偏移 0x28: 保留
    uint16_t magic;           // 偏移 0x2c: 0x564d ("MV")
    uint16_t res5;            // 偏移 0x2e: 保留
    uint32_t res6;            // 偏移 0x30: 保留
    uint64_t res7;            // 偏移 0x34: 保留
    uint32_t magic2;          // 偏移 0x38: "ARM\x64" (0x644d5241)
    uint32_t res8;            // 偏移 0x3c: 保留
};
```

### PD2055 实际值

```
code0       = 0x14960000   (b 分支，跳过头部)
code1       = 0x00000000
text_offset = 0x80000      (512 KB)
image_size  = 0x3b84000    (62.5 MB)
flags       = 0xa
magic2      = 0x644d5241   ("ARM\x64" @ 偏移 0x38)
```

**结论**: 头字段**完好未被清零**（早期"vivo 清零头字段"是误判）。

---

## 错误历史：52 字节截断误判

### 早期错误分析

早期版本的 `parse_boot.py` 错误地认为：

```python
# 错误代码
kernel_Image = kernel_raw[52:]  # 砍掉前 52 字节
```

**理由**: 观察到 ARM64 magic 在 `kernel_raw[0x38]`，误以为前面有 52 字节的 vendor wrapper。

### 实际情况

ARM64 Image 的 magic 就在标准位置 `0x38`，**没有 vendor wrapper**：

```python
# 正确代码
kernel_Image = kernel_raw[0:]  # 完整提取，_text 在文件偏移 0
```

### 影响

- 旧镜像（`kernel_raw[52:]`）比正确镜像小 52 字节
- 所有文件偏移错位 52
- **符号偏移（kallsyms 值）不受影响**（它们是相对 _text 的）
- 但任何"符号偏移 == 文件偏移"的用法都基于错误镜像

### 修正

`scripts/extract_boot_image.py` 已修正为正确提取（`kernel_raw[0:]`）。

---

## 验证方法

### 1. 偏移映射验证

反汇编已知符号，确认落在真实函数序言：

```bash
# _text @ 文件偏移 0
00000000: 00009614 b          #0x2580000   # code0 分支 ✓

# wake_up_process @ 0x870b8
000870b8: fd7bbfa9 stp        x29, x30, [sp, #-0x10]!   # 标准序言 ✓

# get_futex_key @ 0x1407d8
001407d8: ffc301d1 sub        sp, sp, #0x70              # 完整序言 ✓
```

### 2. kallsyms 交叉验证

```bash
python3 scripts/verify_kallsyms.py --from-boot boot.img --kallsyms kallsyms.txt
```

输出：
```
[1] count consistency
  [PASS] parsed names == num_syms (109687 == 109687)

[2] offsets array
  [PASS] monotonic non-decreasing (0 violations)
  [PASS] offsets[0] == 0 (_text)

[3] markers cross-check
  [PASS] markers[k] == name[256k] offset (429/429)

[6] ARM64 spot-check
  [PASS] 7/7 text probes decode to valid ARM64
```

---

## 工具使用

### 提取内核镜像

```bash
# 从 boot.img 提取
python3 scripts/extract_boot_image.py boot.img -o kernel_Image --report

# 输出
[+] wrote kernel_Image (50759696 bytes)
```

### 反汇编验证

```bash
# 需要 capstone: pip install capstone
python3 scripts/disasm_futex.py --from-boot boot.img --kallsyms kallsyms.txt --sym wake_up_process --len 0x20
```

输出：
```
=== wake_up_process @ 0x870b8 ===
  000870b8: fd7bbfa9 stp        x29, x30, [sp, #-0x10]!
  000870bc: fd030091 mov        x29, sp
  000870c0: 61008052 mov        w1, #3
  ...
```

---

## 已知限制

1. **固件体积**: 完整固件包 7GB，无法直接上传 GitHub
2. **下载链接**: OTA URL 可能有时效性，需重新查询
3. **签名验证**: 固件包无官方 SHA256（`checkString` 为空），仅结构验证

---

## 参考

- 提取工具: `scripts/extract_boot_image.py`
- 验证工具: `scripts/verify_kallsyms.py`
- 反汇编工具: `scripts/disasm_futex.py`
- 错误历史: `FAILED_ATTEMPTS.md`（52 字节截断误判）
- kallsyms 恢复: `docs/04_kallsyms_recovery.md`
