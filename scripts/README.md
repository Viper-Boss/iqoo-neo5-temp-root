# scripts/ — 分析与验证工具

本目录是 **可复现的权威流水线**（全新克隆即可运行，无开发者绝对路径）。
历史/探索脚本在 `legacy/`（仅作记录，非复现所需）。

依赖：Python 3；反汇编需 `pip install capstone`。

---

## 权威流水线（按顺序）

### A) 从固件到内核符号

```bash
# 1. 从 boot.img 提取 ARM64 kernel Image（解析 v2 头，定位真实 Image）
python3 extract_boot_image.py ../boot.img -o /tmp/kernel_Image --report

# 2. 解析 kallsyms（运行时用 markers 429/429 自校验；可直接从 boot.img）
python3 parse_kallsyms.py ../boot.img --from-boot -o ../kallsyms.txt

# 3. 6 重独立只读校验（计数/markers/单调/段序/聚簇/ARM64 抽查）
python3 verify_kallsyms.py --from-boot ../boot.img --kallsyms ../kallsyms.txt

# 4. 生成 target.h 偏移
python3 gen_target_offsets.py --kallsyms ../kallsyms.txt -o ../target_offsets.txt
```

`parse_kallsyms.py` / `verify_kallsyms.py` 读取 `kallsyms_layout.json`（结构偏移常量），
**每次运行都用 markers 交叉验证**证明常量与镜像一致；不一致则报错退出、不输出错误表。
校验脚本只读、默认不覆盖任何原始数据、缺输入时报清晰错误（exit 2）。

### B) futex 实现静态验证（反汇编）

```bash
# 复现 analysis/reports/futex_disassembly_report.md 的全部证据
python3 disasm_futex.py --from-boot ../boot.img --kallsyms ../kallsyms.txt --scan-hash

# 单独反汇编某符号
python3 disasm_futex.py --from-boot ../boot.img --kallsyms ../kallsyms.txt \
    --sym get_futex_key --len 0x3c0
```

输出：`get_task_mm`（证 task_struct.mm@0x580）、`get_futex_key`（证 key 布局 mm@0/addr@8）、
`futex_init`（证 hashsize=roundup_pow2(256×cpus)）、`futex_wake`（内联 hash_futex）、
以及 12 个 hash_futex 内联种子点（全部 0xdeadbeff ⇒ 长度 4 u32）。

---

## kallsyms 正确结构（PD2055_A_9.10.3，正确提取的 Image，_text@文件偏移0）

```
offsets : 0x1f80600 .. (109,687 × s32)
num_syms: u32 @ 0x1feb900 = 0x1AC77 = 109687
names   : 0x1feba00 .. 0x2159082   ([u8 len][tokens], 4.19 格式)
markers : 0x2159100                (429 × u32 @ 8 字节步距 — vivo 自定义)
tokens  : table 0x2159f00 / index 0x215a300
```

> 符号偏移（kallsyms 值）== 正确 Image 中的文件偏移（_text@0），已由反汇编验证
> （_text@0、get_futex_key@0x1407d8、get_task_mm@0x3ccd8 均落在真实函数序言）。

---

## vivo OTA 协议（jvq 1.0.3）

工作工具在 **`../tools/vivo_ota.py`**（已内置破解好的字母表，可直接查询/下载任意
vivo/iQOO 机型固件，或解密/加密协议串）。破解**过程**的历史脚本在 `legacy/`。

关键提醒：base64 第三字节是 `((v2&3)<<6)|v3`（**不是 `<<4`**）。

---

## legacy/

历史发现脚本（kallsyms 定位、OTA 破解过程）。已被上述权威工具取代，且部分基于早期
被错误截断 52 字节的镜像（偏移比正确值小 52）——**不要复用其硬编码偏移**。详见
`legacy/README.md`。
