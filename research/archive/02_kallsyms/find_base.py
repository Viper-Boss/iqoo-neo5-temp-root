# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import struct
data = open(r"firmware\kernel_Image", "rb").read()

# scan for u64 values in kernel-virtual range 0xffffff8000000000..0xffffffc000000000
# that look like a kernel base (0xffffff8008xxxxxx / 0xffffff808xxxxxxx)
print("=== scanning for relative_base candidates ===")
hits = []
for off in range(0, len(data)-8, 4):
    v = struct.unpack_from("<Q", data, off)[0]
    if 0xffffff8000000000 <= v < 0xffffffc000000000:
        # plausible: page-aligned-ish, low bits small
        if v & 0x3ffff == 0 or (v & 0xffff) < 0x1000:
            hits.append((off, v))
print(f"{len(hits)} raw hits; showing ones near the names/token area (0x2000000-0x2200000):")
for off, v in hits:
    if 0x1f00000 < off < 0x2200000:
        # check the following u64 = plausible num_syms (10k-200k)
        nxt = struct.unpack_from("<Q", data, off+8)[0]
        print(f"  @{off:#x}: base={v:#x} next_u64={nxt} ({'PLAUSIBLE num_syms' if 10000 < nxt < 200000 else ''})")

print("\n=== all hits with plausible num_syms following ===")
for off, v in hits:
    nxt = struct.unpack_from("<Q", data, off+8)[0]
    if 10000 < nxt < 200000:
        # and check names start right after: data[off+16] = plausible len
        ln = data[off+16]
        tok0 = data[off+17] if off+17 < len(data) else 0
        print(f"  @{off:#x}: base={v:#x} num_syms={nxt} names[0]={ln} tok0={tok0}")

# also: find num_syms by searching backward from names_end for u64 values 10k-200k
print("\n=== u64s 10k-200k in the 64KB before token_table ===")
for off in range(0x2159ecc - 65536, 0x2159ecc - 8, 4):
    v = struct.unpack_from("<Q", data, off)[0]
    if 10000 < v < 200000:
        print(f"  @{off:#x}: {v}")
