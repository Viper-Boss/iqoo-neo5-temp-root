# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import struct, json
data = open(r"firmware\kernel_Image", "rb").read()

# read the full region 0x2159000-0x2159ecc as u64s at 4-mod-8 alignment
region_start = 0x21590e4  # one entry earlier to catch markers[0]=0
region_end = 0x2159ec4
entries = []
for off in range(region_start, region_end, 8):
    v = struct.unpack_from("<Q", data, off)[0]
    entries.append((off, v))

# find the longest increasing run ending before the zeros
# trim trailing zeros
while entries and entries[-1][1] == 0:
    entries.pop()
print(f"after trim: {len(entries)} entries, last = {entries[-1]}")
# check first
print(f"first few: {entries[:6]}")

# markers[0] should be 0; if first != 0, back up one entry
if entries[0][1] != 0:
    v = struct.unpack_from("<Q", data, region_start-8)[0]
    if v == 0:
        entries.insert(0, (region_start-8, 0))
        print(f"prepended 0 entry at {region_start-8:#x}")

markers = [v for _, v in entries]
mono = all(markers[i] <= markers[i+1] for i in range(len(markers)-1))
print(f"entries: {len(entries)}, monotonic: {mono}")
print(f"first: {markers[:4]}, last: {markers[-4:]}")

names_end = entries[0][0]  # markers start = names end
last_marker = markers[-1]
names_start = names_end - last_marker
print(f"\nnames_end: {names_end:#x}")
print(f"last_marker: {last_marker} -> names_start: {names_start:#x}")

# parse names from names_start
def parse_names(start, end):
    p = start; count = 0
    while p < end:
        ln = data[p]
        if ln == 0:
            return count, p >= end - 8  # allow trailing padding zeros
        if ln & 0x80:
            ln = ((ln & 0x7f) | (data[p+1] << 7)) + 2
            p += 1
        p += 1 + ln
        count += 1
        if p > end: return count, False
    return count, True

count, ok = parse_names(names_start, names_end)
print(f"parse from exact: count={count} ok={ok}")

if not ok:
    # try nearby offsets
    for delta in range(1, 128):
        for d in (-delta, delta):
            s = names_start + d
            if s < 0: continue
            c2, ok2 = parse_names(s, names_end)
            if ok2 and c2 > 50000:
                print(f"found at names_start{d:+d}: {s:#x} ({c2} symbols)")
                names_start = s
                count = c2
                ok = True
                break
        if ok: break

if ok:
    print(f"\n*** NAMES: {names_start:#x}..{names_end:#x}, {count} symbols ***")
    # num_syms search
    for skip in range(0, 64, 4):
        np = names_start - 8 - skip
        v = struct.unpack_from("<Q", data, np)[0]
        if v == count:
            print(f"num_syms = {count} @ {np:#x}")
            rb = struct.unpack_from("<Q", data, np-8)[0]
            print(f"relative_base = {rb:#x} @ {np-8:#x}")
            offs_pos = np - 8 - 4*count
            off0 = struct.unpack_from("<i", data, offs_pos)[0]
            print(f"offsets @ {offs_pos:#x}, offsets[0] = {off0}")
            # save
            json.dump({"names_start": names_start, "names_end": names_end,
                       "num_syms": count, "num_syms_pos": np, "relative_base": rb,
                       "offsets_pos": offs_pos, "token_table": 0x2159ecc,
                       "token_index": 0x215a2cc},
                      open(r"firmware\kallsyms_struct.json","w"))
            print("SAVED kallsyms_struct.json")
            break
