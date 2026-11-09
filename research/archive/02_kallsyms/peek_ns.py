# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import struct
data = open(r"firmware\kernel_Image", "rb").read()
ns = 0x1febe46
print("=== 128 bytes before names_start (hex) ===")
seg = data[ns-128:ns]
for i in range(0, 128, 16):
    print(f"{ns-128+i:#x}: {seg[i:i+16].hex()}")
print()
print("=== as u32 (last 20) ===")
for i in range(80, 0, -4):
    v = struct.unpack_from("<I", data, ns-i)[0]
    print(f"  ns-{i}: {v:#x} ({v})")
print()
print("=== as u64 (last 8) ===")
for i in range(64, 0, -8):
    v = struct.unpack_from("<Q", data, ns-i)[0]
    print(f"  ns-{i}: {v:#x}")
