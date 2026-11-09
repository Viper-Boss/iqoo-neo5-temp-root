# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import json
syms = []
with open(r"firmware\kallsyms.txt") as f:
    for line in f:
        parts = line.rstrip("\n").split(" ", 1)
        off = int(parts[0], 16)
        nm = parts[1]
        syms.append((off, nm))
symtab = {}
for off, nm in syms:
    symtab[nm[1:]] = off

# init_task: may appear as init_task with type 'D' — check exact matches
for key in symtab:
    if key.startswith('init_task') or key == 'init_task':
        print(f"'{key}': {symtab[key]:#x}")
# commit_creds variants
for key in symtab:
    if 'commit_cred' in key or 'prepare_kernel_cred' in key:
        print(f"'{key}': {symtab[key]:#x}")
# selinux_enforcing / security_hook_heads
for key in symtab:
    if 'selinux_state' in key or 'selinux_enforc' in key:
        print(f"'{key}': {symtab[key]:#x}")
# _text/_stext
for key in symtab:
    if key in ('_text','_stext','_etext','__init_begin'):
        print(f"'{key}': {symtab[key]:#x}")
