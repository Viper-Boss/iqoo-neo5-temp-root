# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
#!/usr/bin/env python3
"""Disassemble futex_wake to find the inlined hash_futex() and determine
exactly which bytes of the futex_key it feeds into jhash2.

futex_wake @ 0x13be10. It calls get_futex_key (0x1407d8), then inlines
hash_futex(&key). We look for:
  - the bl to get_futex_key
  - the address of the key stack slot (passed as &key)
  - subsequent ldr/ldp loads from that slot feeding the jhash2 mix
"""
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
data = open("/root/kimg", "rb").read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True

START = 0x13be10   # futex_wake
END   = START + 0x260
code = data[START:END]
GFK = 0x1407d8

print("=== futex_wake disassembly ===")
for insn in md.disasm(code, START):
    note = ""
    if insn.mnemonic == "bl":
        # bl target is in op_str like "#0x1407d8"
        tgt = insn.op_str.replace("#", "")
        try:
            if int(tgt, 16) == GFK:
                note = "   <== call get_futex_key"
        except ValueError:
            pass
    print(f"  {insn.address:08x}: {insn.bytes.hex():<8} {insn.mnemonic:<8} {insn.op_str}{note}")
    if insn.address > END - 8:
        break
