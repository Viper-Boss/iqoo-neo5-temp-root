# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import struct
data = open(r"firmware\kernel_Image", "rb").read()
tt_start = 0x2159ecc
names_end = 0x2159e2f

# dump the last 128 bytes before names_end
print("=== tail of names (hex) ===")
seg = data[names_end-128:names_end+16]
for i in range(0, 144, 16):
    print(f"{names_end-128+i:#x}: {seg[i:i+16].hex()}  {''.join(chr(b) if 32<=b<127 else '.' for b in seg[i:i+16])}")

# try parsing backward from names_end: each entry = [len][data]
# walk backward: entry at p: data[p] = len; entry total = 1+len
# A valid names blob: walking backward from end, every position must align to entry boundaries
# The vivo format may use 0x80-bit for big entries:
# 4.19 kallsyms: len field: if len >= 128: two-byte extended
print("\n=== backward parse attempt ===")
p = names_end
entries = 0
while p > names_end - 300000 and entries < 200000:
    # walk back: find entry boundary. Entry size = 1 + len (or 2 + extended)
    # try: the byte at p-1 is the last byte of an entry; we need the len byte...
    # forward parse is easier: guess start, parse forward.
    break

# Instead: dump bytes at 16-byte intervals walking back, looking for structure
print("\n=== sample bytes walking back ===")
for off in range(0, 256, 16):
    p = names_end - off
    print(f"-{off}: {data[p-16:p].hex()}")
