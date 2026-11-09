# iQOO Neo5 (PD2055) Temporary Root Research

> **⚠️ Honest Status**: **No on-device uid=0 achieved, no Bootloader unlock.**
> This is a kernel security research project, currently at the "parameters fixed, awaiting on-device re-test" stage.
> Do not be misled by any "Root success / BL unlocked" claims.

---

## Project Overview

Temporary root research for **iQOO Neo5 (V2055A / PD2055, Snapdragon 870 / SM8250, Android 14,
OriginOS 4, kernel 4.19.152-perf+)**. Core approach: port the CVE-2026-43499
(rtmutex `remove_waiter()` UAF) GhostLock exploit via LD_PRELOAD for in-memory privilege escalation.

This project **does not pursue** persistent Root or Bootloader unlock (the former usually requires unlock,
the latter has been removed by vivo from ABL).

---

## Supported Device & Firmware

| Item | Value |
|------|-------|
| Device | iQOO Neo5 (PD2055 / V2055A) |
| SoC | Snapdragon 870 (SM8250 / kona) |
| Android | 14 / OriginOS 4 |
| Firmware | PD2055_A_9.10.3 (compiler10161353, final EOL) |
| Kernel | 4.19.152-perf+ (arm64, 39-bit VA, KASLR) |
| Bootloader | **Locked** (no unlock channel) |

---

## Current Real Progress

| Stage | Status |
|-------|--------|
| vivo OTA protocol crack (jvq 1.0.3) | ✅ Done (substitution cipher + base64, 60-symbol alphabet) |
| Firmware acquisition (7GB full package) | ✅ Done (110 MB/s direct) |
| kallsyms recovery | ✅ Done (109,687 symbols, markers 429/429 + 5 independent verifications) |
| vivo futex hash model | ✅ **Disassembly conclusion** (mm@0/[mm,addr], ≠upstream v4.19) |
| Unit tests | ✅ Done (16/16, independent disassembly reference) |
| Build | ✅ Done (aarch64, NDK r27c) |
| **KernelSnitch mm localization** | ⏳ **Not on-device verified** (sound in principle, parameters fixed) |
| **Temporary Root (uid=0)** | ❌ **Not achieved** |
| **Bootloader unlock** | ❌ **Not feasible** (command removed) |

---

## Completed Technical Achievements

- **Full vivo OTA protocol crack**: `tools/vivo_ota.py` (query/download any vivo/iQOO firmware)
- **Correct boot.img extraction**: `scripts/extract_boot_image.py` (vendor wrapper = 0, header fields intact)
- **Automated kallsyms parse + 6-way verification**: `scripts/parse_kallsyms.py` + `scripts/verify_kallsyms.py`
- **ARM64 disassembly evidence**: `scripts/disasm_futex.py` (reproduce all futex report evidence)
- **Symbol offset auto-generation**: `scripts/gen_target_offsets.py`
- **Independent futex hash unit tests**: `exploit/tests/test_futex_hash.c` (16 tests)
- **Read-only parameter diagnostic**: `exploit/src/diag_params.c` (`make diag`, the only safe on-device tool)

## Environment Setup

```bash
# Host unit tests (no NDK required)
sudo apt-get install gcc make python3
pip install capstone           # disassembly dependency

# Cross-compilation (build aarch64 exploit)
# Install Android NDK r27c, then:
export NDK_ROOT=~/android-ndk-r27c
```

## Reproducible Pipeline (from firmware to symbol table)

```bash
# 1. Extract kernel Image
python3 scripts/extract_boot_image.py boot.img -o /tmp/kernel_Image --report

# 2. Parse kallsyms (runtime markers 429/429 self-verification)
python3 scripts/parse_kallsyms.py --from-boot boot.img -o kallsyms.txt

# 3. 6-way independent verification
python3 scripts/verify_kallsyms.py --from-boot boot.img --kallsyms kallsyms.txt

# 4. Generate target.h offsets
python3 scripts/gen_target_offsets.py -o target_offsets.txt
```

## Offline Disassembly Verification (futex)

```bash
python3 scripts/disasm_futex.py --from-boot boot.img --kallsyms kallsyms.txt --scan-hash
```

## Test Commands

```bash
cd exploit && make test            # 16/16 unit tests + 4/4 diagnostic (pure computation, no exploit trigger)
cd exploit && make preload         # aarch64 full payload (⚠️ active exploit)
cd exploit && make noroot-payload  # aarch64 no-root payload (⚠️ still triggers CVE)
cd exploit && make diag            # aarch64 read-only diagnostic (✅ safe)
```

## Tool Entry Points

| Tool | Purpose |
|------|---------|
| `tools/vivo_ota.py` | vivo/iQOO firmware query/download/protocol encode-decode |
| `scripts/extract_boot_image.py` | boot.img → ARM64 Image |
| `scripts/parse_kallsyms.py` | kallsyms parse (markers self-verification) |
| `scripts/verify_kallsyms.py` | 6-way read-only verification |
| `scripts/disasm_futex.py` | futex disassembly evidence |
| `scripts/gen_target_offsets.py` | generate target.h offsets |
| `exploit/` | GhostLock port source + tests + build |

## Technical Documentation Index

See [`docs/index.md`](docs/index.md) or read directly:

1. [Device Information](docs/01_device_information.md)
2. [OTA Protocol Analysis](docs/02_ota_protocol_analysis.md)
3. [Firmware Extraction](docs/03_firmware_extraction.md)
4. [kallsyms Recovery](docs/04_kallsyms_recovery.md)
5. [Kernel Disassembly](docs/05_kernel_disassembly.md)
6. [Futex Hash Research](docs/06_futex_hash_research.md)
7. [KernelSnitch Porting](docs/07_kernelsnitch_porting.md)
8. [Build and Testing](docs/08_build_and_testing.md)
9. [Bootloader Research](docs/09_bootloader_research.md)
10. [Known Issues & Next Steps](docs/10_known_issues.md)

---

## Other Documentation

- [Changelog](CHANGELOG.md) · [Research Timeline](RESEARCH_TIMELINE.md)
- [Failed Attempts (important)](FAILED_ATTEMPTS.md) · [Known Limitations](KNOWN_LIMITATIONS.md)
- [Security Policy](SECURITY.md) · [Contributing](CONTRIBUTING.md)

## License

Original code & documentation: **GPLv3** (`LICENSE`).
Exploit core derived from [NebuSec/CyberMeowfia](https://github.com/NebuSec/CyberMeowfia) (GhostLock)
and [yijiacloud's K40 port](https://github.com/yijiacloud/ghostlock-cve-2026-43499-4.19-k40), **Apache-2.0**.
See `SECURITY.md` for details.

## Risk Warning

- Full/noroot payloads are **active kernel exploits** (trigger CVE-2026-43499 + write kernel memory), may **brick device**.
- Only for own hardware, legal research. CI & docs do not provide automated exploit-trigger workflows.
- Only `diag_params` is read-only safe diagnostic tool.