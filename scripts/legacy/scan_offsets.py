import struct

data = open(r"../../kernel_Image", "rb").read()

# scan for long strictly-increasing s32 runs with small values
# region: anywhere in the image before the names
best_runs = []

def check_run(pos, min_len=5000):
    """check if s32 at pos starts a long increasing run; return length"""
    count = 0
    prev = -1
    p = pos
    while p + 4 <= len(data):
        v = struct.unpack_from("<i", data, p)[0]
        if v < 0 or v >= 0x4000000:
            break
        if v <= prev:
            break
        prev = v
        count += 1
        p += 4
    return count

# scan at 4-byte steps in the region before names (0x1f00000-0x1fe0000)
# but the run could start anywhere; sample first
import sys
region_lo, region_hi = 0x1f00000, 0x1ff0000
pos = region_lo
runs = []
while pos < region_hi:
    c = check_run(pos, 5000)
    if c > 5000:
        runs.append((pos, c))
        pos += c * 4  # skip past
    else:
        pos += 4

print(f"found {len(runs)} increasing runs > 5000:")
for p, c in runs[:10]:
    v0 = struct.unpack_from("<i", data, p)[0]
    vlast = struct.unpack_from("<i", data, p + 4*(c-1))[0]
    print(f"  @{p:#x}: {c} entries, first={v0} ({v0:#x}), last={vlast} ({vlast:#x})")
    # what follows the run?
    after = p + 4*c
    v_next = struct.unpack_from("<Q", data, after)[0]
    print(f"    u64 after: {v_next:#x}")
