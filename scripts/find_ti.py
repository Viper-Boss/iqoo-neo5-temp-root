import struct
data = open(r"Q:\Deepseek\_neo5\firmware\kernel_Image", "rb").read()
tt_start = 0x2159ecc
tt_end = 0x215a259

# dump 600 bytes after tt_end as u16s and as hex
print("=== hex after tt_end ===")
seg = data[tt_end:tt_end+400]
for i in range(0, 400, 32):
    print(f"{tt_end+i:#x}: {seg[i:i+32].hex()}")
print()
print("=== first 32 u16 after tt_end ===")
vals = struct.unpack("<32H", data[tt_end:tt_end+64])
print(vals)
print()
# search for the token_index pattern elsewhere: 256 u16s where idx[48] points at token '0'
# token '0' is at offset digit_pos - tt_start = 0x2159fcd - 0x2159ecc = 0x101 = 257
expect_48 = 0x2159fcd - tt_start
print(f"expected idx[48] = {expect_48}")
# scan whole image for u16 == expect_48 followed by increasing pattern
target = struct.pack("<H", expect_48)
pos = -1
hits = []
while True:
    pos = data.find(target, pos+1)
    if pos == -1: break
    # check position: if this is idx[48], then idx starts at pos - 48*2 = pos-96
    ti = pos - 96
    if ti < 0: continue
    idx = struct.unpack("<256H", data[ti:ti+512])
    region = data[tt_start:tt_end]
    good = 0
    for k in range(256):
        off = idx[k]
        if off >= len(region): continue
        e2 = region.find(b"\x00", off)
        if e2 == -1: e2 = len(region)
        if region[off:e2] == data[tt_start+off:tt_start+e2-tt_start+tt_start] if False else True:
            pass
    # simpler direct check
    good = 0
    for k in range(256):
        off = idx[k]
        if off >= len(region): continue
        e2 = region.find(b"\x00", off)
        if e2 == -1: e2 = len(region)
        if region[off:e2] == region[off:e2]:
            good += 1
    # real check: string at idx[k] equals k-th token
    toks = []
    p = tt_start
    for i in range(256):
        e = data.find(b"\x00", p)
        toks.append(data[p:e])
        p = e + 1
    good = 0
    for k in range(256):
        off = idx[k]
        if off >= len(region): continue
        e2 = region.find(b"\x00", off)
        if e2 == -1: e2 = len(region)
        if region[off:e2] == toks[k]:
            good += 1
    if good > 150:
        print(f"TOKEN INDEX FOUND @{ti:#x}: {good}/256 verified")
        hits.append((ti, good, idx))
print(f"{len(hits)} hits")
