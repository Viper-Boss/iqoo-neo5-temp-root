# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import zipfile
z = zipfile.ZipFile(r"firmware\PD2055_A_9.10.3_full.zip")
for n in ('boot.img', 'recovery.img', 'firmware-update/xbl_config.elf', 'firmware-update/dtbo.img'):
    data = z.read(n)
    out = r"firmware" + '\\' + n.split('/')[-1]
    open(out, 'wb').write(data)
    print(f"extracted {n} -> {out} ({len(data)} bytes)")
