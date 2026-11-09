# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import struct
data = open(r"firmware\kernel_Image", "rb").read()
tt_start = 0x2159ecf

# scan backward from tt_start for the markers pattern (u64: 0, increasing by 0x200..0x40000)
for esize in (8, 4):
    fmt = "<%dQ" % 4 if esize == 8 else "<4I"
    # search every aligned position in the 8KB before tt
    found = []
    for pos in range(tt_start - 8192, tt_start - 32, esize):
        try:
            entries = struct.unpack_from(fmt, data, pos)
        except Exception:
            continue
        if entries[0] != 0: continue
        ok = True
        for i in range(1, 4):
            if not (entries[i-1] + 0x200 <= entries[i] <= entries[i-1] + 0x40000):
                ok = False; break
        if ok:
            found.append((pos, entries))
    print(f"esize={esize}: {len(found)} marker candidates")
    for pos, entries in found[-3:]:
        print(f"  @{pos:#x}: {entries}")
