# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
#!/usr/bin/env python3
"""Scan the futex code region for every inlined hash_futex() instance and
confirm: (a) jhash2 seed 0xdeadbeff (= JHASH_INITVAL + (4<<2), proving length 4),
(b) the 4 hashed words are loaded from key+0,+4,+8,+12 (base = key+0).

This cross-checks the futex_wake finding against futex_wait/futex_requeue/etc.
so the conclusion does not rest on a single function.
"""
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
data = open("/root/kimg", "rb").read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True

# futex text region (from kallsyms): do_futex 0x1393f0 .. ~0x13f000
REGION_START = 0x139000
REGION_END   = 0x140000

# Scan for the seed constant construction: mov wN,#0xbeff ; movk wN,#0xdead,lsl#16
# We detect any 'movk wN, #0xdead, lsl #16' and look back for 'mov wN, #0xbeff'.
code = data[REGION_START:REGION_END]
insns = list(md.disasm(code, REGION_START))

seed_sites = []
for i, ins in enumerate(insns):
    if ins.mnemonic == "movk" and "0xdead" in ins.op_str and "lsl #16" in ins.op_str:
        # check preceding mov for #0xbeff into same reg
        reg = ins.op_str.split(",")[0].strip()
        for j in range(max(0, i-3), i):
            if insns[j].mnemonic == "mov" and insns[j].op_str.startswith(reg+",") and "0xbeff" in insns[j].op_str:
                seed_sites.append(ins.address)
                break

print(f"Found {len(seed_sites)} inlined hash_futex seed sites (0xdeadbeff) in futex region:")
for a in seed_sites:
    print(f"  seed @ 0x{a:x}")

# For each seed site, look at the surrounding loads to find the key base.
# The key slot is addressed off x29 (frame). We look for ldp/ldur from [x29,#imm]
# in the ~12 instructions before the seed and report the offsets.
print("\nFor each site, nearby [x29,#imm] loads (key words) within -16..+8 insns:")
for a in seed_sites:
    idx = next(k for k,ins in enumerate(insns) if ins.address == a)
    lo, hi = max(0, idx-16), min(len(insns), idx+10)
    offs = []
    for ins in insns[lo:hi]:
        if ins.mnemonic in ("ldp","ldur","ldr") and "x29" in ins.op_str:
            offs.append((ins.address, ins.mnemonic, ins.op_str))
    print(f"\n  --- seed @0x{a:x} ---")
    for addr,m,o in offs:
        print(f"    {addr:08x}: {m:<5} {o}")
