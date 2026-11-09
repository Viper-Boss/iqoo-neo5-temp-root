# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import struct
data = open(r"firmware\kernel_Image", "rb").read()
tt_start = 0x2159ecf

# print u64 values from tt_start-512 to tt_start
print("=== u64 view (before token_table) ===")
for off in range(tt_start-512, tt_start, 8):
    v = struct.unpack_from("<Q", data, off)[0]
    if v != 0:
        print(f"  @{off:#x} (tt-{tt_start-off}): {v:#x} ({v})")
print("(zeros omitted)")

print()
print("=== u32 view (last 256 bytes) ===")
for off in range(tt_start-256, tt_start, 4):
    v = struct.unpack_from("<I", data, off)[0]
    if v != 0:
        print(f"  @{off:#x}: {v:#x} ({v})")
