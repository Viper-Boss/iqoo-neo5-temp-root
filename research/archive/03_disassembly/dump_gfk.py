# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
#!/usr/bin/env python3
"""Full disassembly of get_futex_key with value-flow notes around the key stores."""
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
data = open("/root/kimg", "rb").read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True
START = 0x1407d8
code = data[START:START+0x3c0]
for insn in md.disasm(code, START):
    print(f"  {insn.address:08x}: {insn.bytes.hex():<8} {insn.mnemonic:<8} {insn.op_str}")
    if insn.mnemonic == "ret":
        break
