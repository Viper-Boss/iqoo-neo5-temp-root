# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import struct
data = open(r"firmware\kernel_Image", "rb").read()
for off in range(0x2159080, 0x21590f0, 8):
    v = struct.unpack_from("<Q", data, off)[0]
    print(f"{off:#x}: {v}")
