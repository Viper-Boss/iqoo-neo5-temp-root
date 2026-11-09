# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import re

syms = []
with open(r"firmware\kallsyms_fixed.txt") as f:
    for line in f:
        parts = line.rstrip("\n").split(" ", 1)
        off = int(parts[0], 16)
        raw = parts[1]           # first char = type, rest = name
        syms.append((off, raw[0], raw[1:]))

print(f"total: {len(syms)} symbols")

def search(pattern, limit=25):
    rx = re.compile(pattern)
    hits = [(o, t, n) for o, t, n in syms if rx.search(n)]
    print(f"\n=== /{pattern}/ -> {len(hits)} hits ===")
    for o, t, n in hits[:limit]:
        print(f"  {t} 0x{o:08x}  {n}")
    return hits

# The critical missing ones — find their real names
for pat in [
    r'^init_task$', r'init_task$', r'^commit_creds', r'commit_creds',
    r'prepare_kernel_cred', r'^kernel_init', r'kernel_init$',
    r'^init_cred', r'init_cred$', r'^_end$', r'^__init_begin',
    r'^__bss_start', r'^_edata', r'^_sdata', r'^__init_end',
]:
    search(pat, limit=8)

# Cred-related (for the cred-patching approach)
search(r'cred', limit=40)