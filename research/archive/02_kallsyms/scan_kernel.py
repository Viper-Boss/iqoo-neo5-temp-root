# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
data = open(r"firmware\kernel_raw", "rb").read()
print(f"blob size: {len(data)}")
# search for arm64 Image magic ARM\x64
target = b"ARM\x64"
pos = []
i = data.find(target)
while i >= 0 and len(pos) < 10:
    pos.append(i)
    i = data.find(target, i+1)
print("ARM\x64 magic at offsets:", pos[:10])
# search gzip magic
g = data.find(b"\x1f\x8b\x08")
print("gzip magic at:", g)
# search LZ4 frame
lz4 = data.find(b"\x04\x22\x4d\x18")
print("lz4 frame at:", lz4)
# check head structure again
print("first 64 bytes:", data[:64].hex())
