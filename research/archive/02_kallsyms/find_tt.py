# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import struct, re

data = open(r"firmware\kernel_Image", "rb").read()

# find token_table via the tool's method: "0\0 1\0 2\0... 9\0" sequence
seq = b"".join(b"%c\0" % i for i in range(ord("0"), ord("9")+1))
pos = -1
positions = []
while True:
    pos = data.find(seq, pos+1)
    if pos == -1: break
    positions.append(pos)
print("digit-token sequence at:", [hex(p) for p in positions])
