# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import struct
data = open(r"firmware\kernel_Image", "rb").read()
end = 0x1feb7a8
print("=== 96 bytes after offsets table end ===")
for skip in range(0, 96, 8):
    v = struct.unpack_from("<Q", data, end+skip)[0]
    v32 = struct.unpack_from("<I", data, end+skip)[0]
    print(f"  +{skip}: u64={v:#x} u32={v32}")
print()
print("hex:")
seg = data[end:end+96]
for i in range(0, 96, 16):
    print(f"  {end+i:#x}: {seg[i:i+16].hex()}")
