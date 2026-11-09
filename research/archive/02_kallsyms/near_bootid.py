# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
syms={}
for line in open(r"firmware\kallsyms_fixed.txt"):
    o,raw=line.rstrip("\n").split(" ",1); syms[raw[1:]]=int(o,16)
for s in ['random_boot_id_data','sysctl_bootid','boot_id','loggers','nfulnl_logger','nf_log_syslog','ashmem_fops','selinux_state']:
    print(f"  {s:24s} {('0x%08x'%syms[s]) if s in syms else 'MISSING'}")
# neighbors of sysctl_bootid
print("\n  symbols near sysctl_bootid (0x%08x):"%syms.get('sysctl_bootid',0))
b=syms.get('sysctl_bootid',0)
near=sorted([(v,k) for k,v in syms.items() if abs(v-b)<0x40])
for v,k in near: print(f"    0x{v:08x} {k}")
