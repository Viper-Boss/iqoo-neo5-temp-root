# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import json, string
base = open(r"br\conf_final2.txt","rb").read()
i0 = base.find(b"%40") + 3
i1 = base.find(b"&fileLength", i0)
name = base[i0:i1].decode("latin-1")
pos125 = 125 - 104
variants = []
for c in string.ascii_letters + string.digits:
    variants.append(name[:pos125] + c + name[pos125+1:])
json.dump(variants, open(r"br\name_variants.json","w"))
print(f"{len(variants)} variants; base name: {name}")
