# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import struct, json
data = open(r"firmware\kernel_Image", "rb").read()

# markers[0] = 0 at 0x21590dc (one entry before 9078)
MARKERS0 = 0x21590dc
v = struct.unpack_from("<Q", data, MARKERS0)[0]
assert v == 0, hex(v)
print(f"markers[0] = 0 @ {MARKERS0:#x} ✓")

# read all markers from MARKERS0 until zeros
entries = []
off = MARKERS0
while off < 0x2159ecc:
    v = struct.unpack_from("<Q", data, off)[0]
    if v == 0 and len(entries) > 2:  # trailing zeros start
        break
    entries.append(v)
    off += 8
print(f"markers: {len(entries)} entries, last={entries[-1]}")

names_end = MARKERS0
names_start = names_end - entries[-1]
print(f"names: {names_start:#x} .. {names_end:#x} ({entries[-1]} bytes)")

def parse_names(start, end):
    p = start; count = 0
    while p < end:
        ln = data[p]
        if ln == 0:
            return count, p, True  # zero entry = terminator
        if ln & 0x80:
            ln = ((ln & 0x7f) | (data[p+1] << 7)) + 2
            p += 1
        p += 1 + ln
        count += 1
        if p > end:
            return count, p, False
    return count, p, True

count, p_end, ok = parse_names(names_start, names_end)
print(f"parse: {count} symbols, ended at {p_end:#x} (target {names_end:#x}), ok={ok}")
if not ok or p_end != names_end:
    # try small deltas
    for d in range(-64, 65):
        s = names_start + d
        if s < 0: continue
        c2, pe, ok2 = parse_names(s, names_end)
        if ok2 and c2 > 100000 and pe == names_end:
            print(f"EXACT: start {s:#x} (delta {d}), {c2} symbols")
            names_start = s
            count = c2
            ok = True
            break

if ok and p_end == names_end or True:
    # even if not exact, use the best
    print(f"\nusing names_start={names_start:#x}, count={count}")
    # find num_syms: u64 == count before names_start
    for skip in range(0, 128, 4):
        np = names_start - 8 - skip
        if np < 0: break
        v = struct.unpack_from("<Q", data, np)[0]
        if v == count:
            print(f"num_syms = {count} @ {np:#x} ✓")
            rb = struct.unpack_from("<Q", data, np-8)[0]
            print(f"relative_base = {rb:#x} @ {np-8:#x}")
            offs_pos = np - 8 - 4*count
            print(f"offsets table @ {offs_pos:#x}")
            # verify a couple offsets
            off0 = struct.unpack_from("<i", data, offs_pos)[0]
            off_last = struct.unpack_from("<i", data, offs_pos + 4*(count-1))[0]
            print(f"offsets[0]={off0} offsets[-1]={off_last}")
            json.dump({"names_start": names_start, "names_end": names_end,
                       "num_syms": count, "num_syms_pos": np, "relative_base": rb,
                       "offsets_pos": offs_pos, "token_table": 0x2159ecc,
                       "token_index": 0x215a2cc},
                      open(r"firmware\kallsyms_struct.json","w"))
            print("SAVED kallsyms_struct.json")
            break
    else:
        print("num_syms u64 not found - dumping u64s before names_start:")
        for skip in range(8, 80, 4):
            np = names_start - skip
            v = struct.unpack_from("<Q", data, np)[0]
            print(f"  {np:#x}: {v}")
