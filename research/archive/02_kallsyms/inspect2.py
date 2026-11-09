# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import struct
data = open(r"firmware\kernel_Image", "rb").read()
for off in (52, 35288710, 35288706, 35288714-4):
    hdr = data[off:off+64]
    if len(hdr) < 64: continue
    code0, magic = struct.unpack("<II", hdr[0:8])
    text_off = struct.unpack("<Q", hdr[8:16])[0]
    img_sz = struct.unpack("<Q", hdr[16:24])[0]
    print(f"offset {off}: code0={code0:#x} magic={magic:#x} text_off={text_off:#x} img_size={img_sz:#x} ({img_sz})")
    print("  hex:", hdr[:32].hex())

# what is between 56 and 35288714? Sample some offsets
for off in (700612, 700620, 1000000, 20000000, 35000000):
    print(f"around {off}: {data[off:off+16].hex()}")
# check gzip at 700612
gz = data[700612:700620]
print("gzip?", gz[:3].hex() == "1f8b08", gz.hex())
# check what precedes the 2nd ARMd
print("before 2nd ARMd:", data[35288714-64:35288714].hex())
