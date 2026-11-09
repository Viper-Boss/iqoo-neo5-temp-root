# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
data = open(r"firmware\kernel_raw", "rb").read()
# Image header: ARMd at +4 => Image starts at 52
img = data[52:]
print("Image[0:8]:", img[:8].hex())
import struct
# arm64 Image header fields:
# 0x00: text_offset (u32)? no: 0x00 code0(u32) code1(u32) 0x08 text_offset(u64)... 
# actual: code0, code1 at 0/4? hmm: offsets: 0x00 code0, 0x04 code1(magic ARMd), 0x08 text_off, 0x10 image_size, 0x18 flags, 0x1c magic2...
text_off = struct.unpack("<Q", img[0x08:0x10])[0]
image_size = struct.unpack("<Q", img[0x10:0x18])[0]
flags = struct.unpack("<Q", img[0x18:0x20])[0]
print(f"text_offset=0x{text_off:x} image_size=0x{image_size:x} ({image_size}) flags=0x{flags:x}")
core = img[:image_size] if image_size > 1000000 else img
open(r"firmware\kernel_Image", "wb").write(core)
print(f"saved kernel_Image: {len(core)} bytes")
