# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import struct
data = open(r"firmware\kernel_Image", "rb").read()

# markers: u64 array starting 0x21590ec (aligned 4 mod 8)
MARKERS_START = 0x21590ec
MARKERS_END = 0x2159ec4  # just before token_table 0x2159ecc
n_entries = (MARKERS_END - MARKERS_START) // 8
print(f"markers entries: {n_entries}")
markers = []
for i in range(n_entries):
    v = struct.unpack_from("<Q", data, MARKERS_START + 8*i)[0]
    markers.append(v)
print(f"first: {markers[:5]}")
print(f"last:  {markers[-5:]}")
# sanity: increasing
mono = all(markers[i] < markers[i+1] for i in range(len(markers)-1))
print(f"monotonic: {mono}")
print(f"num_syms estimate: {n_entries * 256} = {n_entries*256}")

names_end = MARKERS_START
last_marker = markers[-1]
print(f"\nnames end (markers start): {names_end:#x}")
print(f"last marker value: {last_marker} ({last_marker/1024:.1f} KB)")
names_start_guess = names_end - last_marker
print(f"names start guess: {names_start_guess:#x}")

# verify: parse names forward from guess (or nearby - the names may have alignment padding)
# entry: [len][tokens...]; len==0 terminates? or names end exactly at markers_start
# try parse from candidates near the guess
def parse_names(start, end):
    p = start
    count = 0
    while p < end:
        ln = data[p]
        if ln == 0:
            return count, (p == end-1 or p == end)  # zero entry at end (padding included)
        if ln & 0x80:
            ln = ((ln & 0x7f) | (data[p+1] << 7)) + 2
            p += 1
        p += 1 + ln
        count += 1
        if p > end:
            return count, False
    return count, p == end

# search near the guess: names_start could be the exact or with padding
for delta in range(0, 64):
    for d2 in (0, -4, -8):
        start = names_start_guess - delta + d2
        if start < 0: continue
        # quick plausibility: data[start] = small len, data[start+1] = token idx
        ln = data[start]
        if ln == 0 or ln > 60: continue
        count, ok = parse_names(start, names_end)
        if ok and count > 50000:
            print(f"\n*** NAMES START FOUND: {start:#x} ({count} symbols) ***")
            # num_syms = count
            # find num_syms u64: right before names_start (aligned)
            for skip in range(0, 32):
                np = start - 8 - skip
                if np < 0: break
                v = struct.unpack_from("<Q", data, np)[0]
                if v == count:
                    print(f"num_syms ({count}) at {np:#x} ✓")
                    # relative_base right before
                    rb = struct.unpack_from("<Q", data, np-8)[0]
                    print(f"relative_base at {np-8:#x}: {rb:#x}")
                    # offsets table: right before relative_base: 4*count bytes
                    offs_pos = np - 8 - 4*count
                    print(f"offsets table at {offs_pos:#x}")
                    # save everything
                    struct.pack
                    with open(r"firmware\kallsyms_struct.json", "w") as f:
                        import json
                        json.dump({"names_start": start, "names_end": names_end,
                                   "num_syms": count, "num_syms_pos": np,
                                   "relative_base": rb, "offsets_pos": offs_pos,
                                   "markers_start": MARKERS_START, "token_table": 0x2159ecc,
                                   "token_index": 0x215a2cc}, f)
                    print("saved structure JSON")
                    break
            break
    else:
        continue
    break
