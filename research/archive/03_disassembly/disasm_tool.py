# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
#!/usr/bin/env python3
"""Disassemble ARM64 ranges from the raw kernel Image using capstone."""
import sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, CS_MODE_ARM

IMG = sys.argv[1] if len(sys.argv) > 1 else "/root/kimg"
data = open(IMG, "rb").read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True

def disasm(start, length, label=""):
    print(f"\n=== {label} @ file 0x{start:x} .. 0x{start+length:x} ===")
    code = data[start:start+length]
    for insn in md.disasm(code, start):
        print(f"  {insn.address:08x}: {insn.bytes.hex():<8} {insn.mnemonic:<10} {insn.op_str}")

if __name__ == "__main__":
    # Verify offset mapping: _text@0 should be code0 (a branch), and known
    # text symbols should start with a function prologue.
    import struct
    print(f"Image size: {len(data)}")
    print(f"first 8 bytes (code0/code1): {struct.unpack_from('<II', data, 0)}")
    disasm(0, 0x10, "_text / Image header code0")
    # wake_up_process @ 0x870b8 (corrected kallsyms)
    disasm(0x870b8, 0x28, "wake_up_process (expect prologue)")
    # get_futex_key @ 0x1407d8
    disasm(0x1407d8, 0x30, "get_futex_key head")
