# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
#!/usr/bin/env python3
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
data = open("/root/kimg", "rb").read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True
START = 0x140a00
code = data[START:START+0x1a0]
for insn in md.disasm(code, START):
    mark = ""
    if "x19" in insn.op_str and insn.mnemonic in ("str","stp","stur"):
        mark = "   <== KEY STORE"
    print(f"  {insn.address:08x}: {insn.bytes.hex():<8} {insn.mnemonic:<8} {insn.op_str}{mark}")
    if insn.address > 0x140b40 and insn.mnemonic == "ret":
        break
