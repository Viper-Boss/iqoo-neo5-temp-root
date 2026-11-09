# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import struct

data = open(r"firmware\kernel_Image", "rb").read()

# The tool picks the candidate where the next char is alnum
seq = b"".join(b"%c\0" % i for i in range(ord("0"), ord("9")+1))
positions = []
pos = -1
while True:
    pos = data.find(seq, pos+1)
    if pos == -1: break
    after = data[pos+len(seq):pos+len(seq)+2]
    if after[0:1].isalnum() or after == b":\x00" or after == b":\x01":
        positions.append((pos, after))
print("followed-by-alnum candidates:", positions)

# walk backward to find token table start (token for '0' is at index 48)
# full token table: 256 tokens; '0'..'9' at indices 48..57
# walk back from pos of '0' to table start
for pos, _ in positions:
    p = pos - 1
    # walk back 48 tokens
    count = 0
    while count < 60 and p > 0:
        p -= 1
        if data[p] == 0:
            count += 1
    tt_start = p + 1
    # token table region
    region_start = tt_start
    # find the end: 256 tokens from tt_start
    p2 = tt_start
    for i in range(256):
        e = data.find(b"\x00", p2)
        if e == -1: break
        p2 = e + 1
    tt_end = p2
    print(f"candidate @{pos:#x}: table {tt_start:#x}-{tt_end:#x} ({tt_end-tt_start} bytes)")
    # check token_index right after (aligned)
    for skip in range(0, 8):
        ti = tt_end + skip
        if ti % 2: continue
        idx = struct.unpack("<256H", data[ti:ti+512])
        if idx[0] == 0 and idx[255] <= 2000:
            prev = 0
            ok = all(v >= prev for v in idx) or True
            print(f"  token_index candidate @{ti:#x}: idx[1]={idx[1]} idx[255]={idx[255]}")
            # verify: strings
            region = data[tt_start:tt_end]
            strs = region.split(b"\x00")
            strs = [s for s in strs if s]
            # token i should be at offset idx[i]
            good = 0
            for i in range(min(256, len(strs))):
                off = idx[i]
                e2 = region.find(b"\x00", off)
                if e2 < 0: e2 = len(region)
                if region[off:e2] == strs[i]:
                    good += 1
            print(f"  string verification: {good}/256")
            if good > 200:
                print("  *** CONFIRMED TOKEN TABLE+INDEX ***")
                # dump the area BEFORE token table (markers should be there)
                print("  256 bytes before tt_start:", data[tt_start-256:tt_start].hex())
