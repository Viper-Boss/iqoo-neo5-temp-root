# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import json
syms = []
with open(r"firmware\kallsyms.txt") as f:
    for line in f:
        parts = line.rstrip("\n").split(" ", 1)
        off = int(parts[0], 16)
        nm = parts[1]
        syms.append((off, nm))
symtab = {}
for off, nm in syms:
    symtab[nm[1:]] = off
# also keep raw with type for inspection
raw = [nm for _, nm in syms]

# search for init_task-like and commit_creds-like with any prefix
for key in list(symtab.keys()):
    if key.endswith('init_task') or key.startswith('init_task'):
        print(f"symtab '{key}': {symtab[key]:#x}")
for key in list(symtab.keys()):
    if 'commit_creds' in key or 'kernel_cred' in key:
        print(f"cred: '{key}': {symtab[key]:#x}")

# count symbols — maybe our parse dropped the first ~50 entries (names_start off)
print(f"\ntotal: {len(syms)}")
# The first symbols (offset 0): kernel entry symbols. In a standard kernel:
# _text, _stext... those might be in the MISSING first entries!
# Our names_start=0x1febb9b parse may have started mid-way.
# offsets table has 109691 entries; we have 109641 names -> 50 missing!

# The first 50 names are missing -> look at first offset entries
import struct
data = open(r"firmware\kernel_Image", "rb").read()
OFFS_START = 0x1f805bc
for i in range(60):
    off = struct.unpack_from("<i", data, OFFS_START + 4*i)[0]
    if off > 0x5000:
        print(f"first entries: entry[50] off={struct.unpack_from('<i', data, OFFS_START+4*50)[0]:#x}")
        print(f"  offsets[0..5]: {[hex(struct.unpack_from('<i', data, OFFS_START+4*i)[0]) for i in range(6)]}")
        break
# what do our first parsed names correspond to?
print(f"\nour first parsed name offset: {syms[0][0]:#x} name: {syms[0][1]}")
# find which index in offsets matches syms[0]
target_off = syms[0][0]
for i in range(200):
    off = struct.unpack_from("<i", data, OFFS_START + 4*i)[0]
    if off == target_off:
        print(f"our first name matches offsets[{i}]")
        break
