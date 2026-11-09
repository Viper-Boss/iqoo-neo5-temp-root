# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import struct, json
data = open(r"firmware\kernel_Image", "rb").read()

# find markers[0]=0: scan backward from 9078-entry
# entries at 8-spacing; find where 0 precedes 9078
found = None
for off in range(0x2159000, 0x21590ec, 8):
    v0 = struct.unpack_from("<Q", data, off)[0]
    v1 = struct.unpack_from("<Q", data, off+8)[0]
    if v1 == 9078:
        print(f"entry before 9078 at {off:#x}: {v0}")
        if v0 == 0:
            found = off
        break
if found is None:
    # try 4-aligned
    for off in range(0x2159000, 0x21590ec, 4):
        v1 = struct.unpack_from("<Q", data, off+8)[0]
        if v1 == 9078:
            v0 = struct.unpack_from("<Q", data, off)[0]
            print(f"4-aligned: entry before 9078 at {off:#x}: {v0}")
            if v0 == 0:
                found = off
            break
print("markers[0] position:", hex(found) if found else "not found with 0")
# fallback: just use 9078's position as markers[1]; markers[0] is 8 before
m1 = 0x21590e4  # where 9078 lives
m0 = m1 - 8
v0 = struct.unpack_from("<Q", data, m0)[0]
print(f"value at m0 {m0:#x}: {v0}")

# collect markers from m1 (use entries even if markers[0] != 0 — maybe vivo omits it)
entries = []
off = m1
while off < 0x2159ecc:
    v = struct.unpack_from("<Q", data, off)[0]
    if v == 0 and len(entries) > 2:
        break
    entries.append(v)
    off += 8
print(f"markers from m1: {len(entries)} entries, last={entries[-1]}")

# names span: if markers[0]=0 exists at m0, names_end=m0; else names_end = m1 - 9078 hmm no.
# markers[i] = name offset of symbol 256i. markers[1]=9078 = offset of symbol 256.
# The names END = markers start (m0 if exists else m1's array start)
names_end = m0 if v0 == 0 else m1 - 9078 + 0  # hmm
# Actually names end = the offset where markers begin = m0 (or m1 if no 0-entry)
names_end = m1  # conservative: names end at markers[1] position minus?? no...
# The markers ARRAY starts at m0 (or m1). Names END at the markers array start.
names_end = m0 if v0 == 0 else m1
names_start = names_end - entries[-1]
print(f"names: {names_start:#x}..{names_end:#x}")

def parse_names(start, end):
    p = start; count = 0
    while p < end:
        ln = data[p]
        if ln == 0:
            return count, p, True
        if ln & 0x80:
            ln = ((ln & 0x7f) | (data[p+1] << 7)) + 2
            p += 1
        p += 1 + ln
        count += 1
        if p > end: return count, p, False
    return count, p, True

best = None
for d in range(-256, 257):
    s = names_start + d
    if s < 0: continue
    c, pe, ok = parse_names(s, names_end)
    if ok and c > 100000:
        if best is None or abs(pe - names_end) < abs(best[2] - names_end):
            best = (s, c, pe)
        if pe == names_end:
            best = (s, c, pe)
            break
if best:
    s, c, pe = best
    print(f"\nBEST: names_start={s:#x} (d={s-names_start}), {c} symbols, end={pe:#x} vs {names_end:#x}")
    # num_syms
    for skip in range(0, 256, 4):
        np = s - 8 - skip
        if np < 0: break
        v = struct.unpack_from("<Q", data, np)[0]
        if v == c:
            rb = struct.unpack_from("<Q", data, np-8)[0]
            print(f"num_syms={c} @ {np:#x}; relative_base={rb:#x}")
            offs_pos = np - 8 - 4*c
            print(f"offsets @ {offs_pos:#x}")
            json.dump({"names_start": s, "names_end": names_end, "num_syms": c,
                       "num_syms_pos": np, "relative_base": rb, "offsets_pos": offs_pos,
                       "token_table": 0x2159ecc, "token_index": 0x215a2cc},
                      open(r"firmware\kallsyms_struct.json","w"))
            print("SAVED")
            break
