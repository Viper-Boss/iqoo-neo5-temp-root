# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
#!/usr/bin/env python3
"""Analyze get_futex_key to determine the futex_key field layout in the vivo kernel.

get_futex_key(u32 __user *uaddr, int fshared, union futex_key *key, int rw)
  x0=uaddr, x1=fshared, x2=key, x3=rw

Upstream v4.19 stores (for a PRIVATE futex):
  key->both.offset    = address % PAGE_SIZE;   // expect store to [key+16]
  address            -= offset;
  key->private.mm     = mm;                     // expect store to [key+8]
  key->private.address = address;               // expect store to [key+0]

We disassemble and find every STR/STP/STUR that writes into the key object,
reporting the byte offset, to confirm word/address@0, ptr/mm@8, offset@16.
"""
import sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

data = open("/root/kimg", "rb").read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True

START = 0x1407d8   # get_futex_key
# disassemble until we've passed the function (bounded)
code = data[START:START+0x400]

# Track which registers currently alias the key pointer (x2 at entry).
key_regs = {"x2"}
print("=== get_futex_key disassembly (key=x2 at entry) ===")
stores = []
for insn in md.disasm(code, START):
    m, ops = insn.mnemonic, insn.op_str
    # track mov <dst>, x2  (key copied to callee-saved reg)
    if m in ("mov",) and ops.endswith("x2") :
        dst = ops.split(",")[0].strip()
        if dst.startswith("x"):
            key_regs.add(dst)
    # also track mov xN, x2 style where source is a known key reg
    if m == "mov":
        parts = [p.strip() for p in ops.split(",")]
        if len(parts) == 2 and parts[1] in key_regs and parts[0].startswith("x"):
            key_regs.add(parts[0])
    # record stores into a key register
    if m in ("str", "stur", "stp"):
        for kr in key_regs:
            if f"[{kr}" in ops.replace(" ", ""):
                stores.append((insn.address, m, ops))
                print(f"  {insn.address:08x}: {m:<6} {ops}   <-- key store ({kr})")
                break
    if m == "ret":
        print(f"  {insn.address:08x}: ret  (function end)")
        break

print(f"\nkey-aliased registers seen: {sorted(key_regs)}")
print(f"total key stores: {len(stores)}")
