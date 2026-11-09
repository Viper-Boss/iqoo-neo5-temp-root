# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import struct

data = open(r"firmware\kernel_Image", "rb").read()

# Use the tool's exact method: the candidate followed by alnum
seq = b"".join(b"%c\0" % i for i in range(ord("0"), ord("9")+1))
cands = []
pos = -1
while True:
    pos = data.find(seq, pos+1)
    if pos == -1: break
    after = data[pos+len(seq):pos+len(seq)+1]
    if after.isalnum():
        cands.append(pos)
print("alnum-followed candidates:", [hex(p) for p in cands])

# tool: position of '0' token; walk back exactly 48 tokens to table start
for pos in cands:
    # tokens 0..47 before '0'
    p = pos
    for i in range(48):
        p = data.rfind(b"\x00", 0, p)
        if p == -1: break
    tt_start = p + 1  # after the last zero
    # hmm - tool walks back char by char; token table start = after token 0's preceding zero
    # find end: scan 256 tokens forward
    p2 = tt_start
    for i in range(256):
        e = data.find(b"\x00", p2)
        if e == -1: p2 = len(data); break
        p2 = e + 1
    tt_end = p2
    region = data[tt_start:tt_end]
    print(f"cand @{pos:#x}: tt {tt_start:#x}-{tt_end:#x} ({tt_end-tt_start}B)")
    # bytes right after tt_end = token_index (aligned 2?)
    for skip in (0,1,2,3):
        ti = tt_end + skip
        if ti+512 > len(data): continue
        idx = struct.unpack("<256H", data[ti:ti+512])
        if idx[0]==0 and 200 < idx[255] < 2000:
            # verify strings by offset
            good = 0
            for k in range(256):
                off = idx[k]
                e2 = region.find(b"\x00", off)
                if e2 == -1: e2 = len(region)
                tok = region[off:e2]
                # token k = k-th string in region
                # count: the k-th null-terminated string
            # simpler: k-th string via split
            strs = region.split(b"\x00")
            strs = [s for s in strs if s] if strs[0] else strs[1:]
            # hmm — just check first few
            print(f"  ti@{ti:#x}: idx[0..5]={idx[:6]} last={idx[255]}")
    # dump 64 bytes before tt_start
    print("  before tt:", data[tt_start-64:tt_start].hex())
