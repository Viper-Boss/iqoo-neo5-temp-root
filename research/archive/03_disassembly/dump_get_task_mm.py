# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
#!/usr/bin/env python3
"""Confirm task_struct.mm offset by disassembling get_task_mm().
get_task_mm(task): mm = task->mm; if (mm) mmgrab(mm); return mm;
The load `ldr xN, [x0, #imm]` reveals offsetof(task_struct, mm)."""
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
data = open("/root/kimg", "rb").read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True
START = 0x0003ccd8   # get_task_mm
code = data[START:START+0x60]
print("=== get_task_mm @ 0x%x (x0 = task) ===" % START)
for insn in md.disasm(code, START):
    print(f"  {insn.address:08x}: {insn.bytes.hex():<8} {insn.mnemonic:<8} {insn.op_str}")
    if insn.mnemonic == "ret":
        break
