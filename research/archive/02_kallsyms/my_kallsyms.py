# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import struct, re, sys

data = open(r"firmware\kernel_Image", "rb").read()
print(f"Image size: {len(data)} ({len(data)/1048576:.1f} MB)")

# ============ 1. Find kallsyms_token_table ============
# 256 short null-terminated strings, mostly alnum
# signature: long run of alternating printable + \x00
best = None
run_start = None
run_len = 0
i = 0
runs = []
while i < len(data) - 1:
    c = data[i]
    ok = (0x20 < c < 0x7f and c != 0) # printable
    if ok:
        if run_start is None:
            run_start = i
        run_len += 1
    else:
        if c == 0 and run_len > 2:
            # string end - continue run
            run_len += 1
        else:
            if run_start is not None and run_len > 400:
                runs.append((run_start, i - run_start, run_len))
            run_start = None; run_len = 0
    i += 1

print(f"found {len(runs)} candidate text runs > 400")
# token table: ~256 strings; region length 300-1200; density of \x00 ~ 1/2
for st, en, ln in runs:
    if 300 < (en-st) < 2000:
        region = data[st:en]
        zeros = region.count(0)
        strings = region.split(b'\x00')
        strings = [s for s in strings if len(s) > 0]
        if 200 < len(strings) < 300 and zeros > 150:
            print(f"TOKEN TABLE CANDIDATE: {st:#x}-{en:#x} ({len(strings)} strings, {zeros} zeros)")

# Let me be more systematic: search for the exact token_table+token_index pattern
# token_index: 256 u16s starting with 0x0000, increasing, each <= ~1500
print("\n=== token_index search ===")
tt_candidates = []
for m in re.finditer(rb'(?:[\x20-\x7e]\x00){20,}', data):
    st = m.start()
    # count strings in this run
    seg = data[st:m.end()]
    n_str = seg.count(0)
    if 100 <= n_str <= 400:
        tt_candidates.append((st, m.end()))
print(f"{len(tt_candidates)} token_table regions with 100-400 strings")

# For each candidate: check if followed (after alignment) by plausible token_index
for tt_st, tt_en in tt_candidates:
    # token table ends... token_index follows (aligned to 2? or right after?)
    # try offsets after tt_en
    for skip in range(0, 16):
        ti_st = tt_en + skip
        if ti_st + 512 > len(data): break
        idx = struct.unpack('<256H', data[ti_st:ti_st+512])
        # validate: idx[0]==0, increasing, max < 2000, diffs match string lengths
        if idx[0] != 0: continue
        ok = True
        prev = 0
        for v in idx:
            if v < prev or v > 4000: ok = False; break
            prev = v
        if not ok: continue
        # verify: token at idx[k] = string k
        region = data[tt_st:tt_en]
        strings = region.split(b'\x00')
        strings = [s for s in strings if len(s) > 0]
        if len(strings) < 200: continue
        match = 0
        for k in range(min(256, len(strings))):
            off = idx[k]
            if off < len(region):
                # extract string at off in region
                e = region.find(b'\x00', off)
                if e < 0: e = len(region)
                if region[off:e] == strings[k] if k < len(strings) else False:
                    match += 1
        if match > 100:
            print(f"FOUND: token_table @{tt_st:#x}, token_index @{ti_st:#x}, matches={match}/256, last={idx[255]}")
