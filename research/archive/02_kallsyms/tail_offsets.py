# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import struct
d=open(r"firmware\kernel_Image","rb").read()
S=0x1f805bc
def v(i): return struct.unpack_from("<i",d,S+4*i)[0]
print("index around 109,635..109,700:")
for i in range(109635,109700):
    print(f"  [{i}] 0x{v(i):08x} ({v(i)})")
