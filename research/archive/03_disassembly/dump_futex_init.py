# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
#!/usr/bin/env python3
"""Disassemble futex_init (hashsize calc) and re-confirm the hash base in a
second caller (futex_wait) so the conclusion does not rest on one function."""
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
data = open("/root/kimg", "rb").read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True

def dump(start, length, label, stop_on_ret=False):
    print(f"\n=== {label} @ 0x{start:x} ===")
    code = data[start:start+length]
    for insn in md.disasm(code, start):
        print(f"  {insn.address:08x}: {insn.bytes.hex():<8} {insn.mnemonic:<8} {insn.op_str}")
        if stop_on_ret and insn.mnemonic == "ret":
            break

# futex_init @ 0x2597b30 — verify hashsize = roundup_pow_of_two(256*cpus)
dump(0x2597b30, 0x120, "futex_init", stop_on_ret=False)
