# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import json

# read kallsyms.txt: format "offset name-with-type-prefix"
syms = []
with open(r"firmware\kallsyms.txt") as f:
    for line in f:
        parts = line.rstrip("\n").split(" ", 1)
        off = int(parts[0], 16)
        nm = parts[1]
        syms.append((off, nm))

print(f"{len(syms)} symbols")
symtab = {}
for off, nm in syms:
    # strip type char (first char)
    name = nm[1:]
    symtab[name] = off

# verify known symbols
for probe in ('el0_sve_acc', 'cpu_switch_to', 'ret_from_fork'):
    if probe in symtab:
        print(f"  {probe}: {symtab[probe]:#x}")

need = ['init_task','init_uts_ns','empty_zero_page','root_task_group',
        'selinux_state','security_hook_heads','kmalloc_caches',
        'anon_pipe_buf_ops','nfulnl_logger','sysctl_bootid',
        'ashmem_fops','ashmem_misc','ashmem_ioctl','compat_ashmem_ioctl',
        'ashmem_mmap','ashmem_open','ashmem_release','ashmem_show_fdinfo',
        'configfs_read_file','configfs_write_bin_file',
        'generic_file_splice_read','noop_llseek','remove_waiter',
        'kallsyms_lookup_name','_stext','_text','commit_creds','prepare_kernel_cred',
        'modprobe_path','loggers','selinux_enforcing','panic','printk',
        'stack_chk_guard','init_cred','init_nsproxy','init_fs','init_files',
        'selinux_enforcing','kmalloc_caches','futex_requeue','rt_mutex_start_proxy_lock',
        'task_struct','mm_struct','vfsmount','file_operations']
print("\n=== target.h offsets (from _text) ===")
out = []
for sy in need:
    if sy in symtab:
        l = f"#define {sy.upper()}_OFF 0x{symtab[sy]:08x}ULL  /* kallsyms: {sy} */"
    else:
        l = f"/* {sy}: NOT FOUND */"
    print(l); out.append(l)
open(r"firmware\target_offsets.txt","w").write("\n".join(out))
print("\nsaved target_offsets.txt")
