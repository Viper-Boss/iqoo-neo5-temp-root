import re

syms = {}
with open(r"Q:\Deepseek\_neo5\firmware\kallsyms_fixed.txt") as f:
    for line in f:
        off_s, raw = line.rstrip("\n").split(" ", 1)
        off = int(off_s, 16)
        typ, name = raw[0], raw[1:]
        # keep the FIRST occurrence for each name (lowest address)
        if name not in syms:
            syms[name] = (off, typ)

def g(name):
    if name in syms:
        return syms[name][0]
    return None

# ---- target.h symbol map (offset from _text) ----
# (macro_name, kallsyms_symbol, optional_delta, note)
want = [
    ("INIT_TASK_OFF",            "__start_init_task", 0,      "init_task section start (init_task symbol filtered by vivo)"),
    ("INIT_UTS_NS_OFF",          "init_uts_ns",       0,      "init_uts_ns"),
    ("EMPTY_ZERO_PAGE_OFF",      "empty_zero_page",   0,      "empty_zero_page"),
    ("ROOT_TASK_GROUP_OFF",      "root_task_group",   0,      "root_task_group"),
    ("SELINUX_ENFORCING_OFF",    "selinux_state",     0,      "selinux_state; .enforcing at +0 (4.19 DEVELOP=y)"),
    ("SECURITY_HOOK_HEADS_OFF",  "security_hook_heads",0,     "security_hook_heads"),
    ("KMALLOC_CACHES_OFF",       "kmalloc_caches",    0,      "kmalloc_caches"),
    ("ANON_PIPE_BUF_OPS_OFF",    "anon_pipe_buf_ops", 0,      "anon_pipe_buf_ops"),
    ("ASHMEM_MISC_OFF",          "ashmem_misc",       0,      "ashmem_misc (miscdevice)"),
    ("ASHMEM_MISC_FOPS_OFF",     "ashmem_misc",       0x10,   "ashmem_misc.fops (+0x10 in struct miscdevice)"),
    ("ASHMEM_FOPS_OFF",          "ashmem_fops",       0,      "ashmem_fops"),
    ("ASHMEM_IOCTL_OFF",         "ashmem_ioctl",      0,      "ashmem_ioctl"),
    ("ASHMEM_COMPAT_IOCTL_OFF",  "compat_ashmem_ioctl",0,     "compat_ashmem_ioctl"),
    ("ASHMEM_MMAP_OFF",          "ashmem_mmap",       0,      "ashmem_mmap"),
    ("ASHMEM_OPEN_OFF",          "ashmem_open",       0,      "ashmem_open"),
    ("ASHMEM_RELEASE_OFF",       "ashmem_release",    0,      "ashmem_release"),
    ("ASHMEM_SHOW_FDINFO_OFF",   "ashmem_show_fdinfo",0,      "ashmem_show_fdinfo"),
    ("CONFIGFS_READ_ITER_OFF",   "configfs_read_file",0,      "configfs_read_file (4.19 .read)"),
    ("CONFIGFS_BIN_WRITE_ITER_OFF","configfs_write_bin_file",0,"configfs_write_bin_file (4.19)"),
    ("COPY_SPLICE_READ_OFF",     "generic_file_splice_read",0,"generic_file_splice_read"),
    ("NOOP_LLSEEK_OFF",          "noop_llseek",       0,      "noop_llseek"),
    ("REMOVE_WAITER_OFF",        "remove_waiter",     0,      "remove_waiter (CVE-2026-43499 UAF func)"),
    ("KALLSYMS_LOOKUP_NAME_OFF", "kallsyms_lookup_name",0,    "kallsyms_lookup_name"),
    ("MODPROBE_PATH_OFF",        "modprobe_path",     0,      "modprobe_path"),
    ("LOGGERS_OFF",              "loggers",           0,      "loggers (nf_log)"),
    ("NFULNL_LOGGER_OFF",        "nfulnl_logger",     0,      "nfulnl_logger"),
    ("SYSCTL_BOOTID_OFF",        "sysctl_bootid",     0,      "sysctl_bootid"),
    ("PANIC_OFF",                "panic",             0,      "panic"),
    ("PRINTK_OFF",               "printk",            0,      "printk"),
    ("INIT_NSPROXY_OFF",         "init_nsproxy",      0,      "init_nsproxy"),
    ("INIT_FS_OFF",              "init_fs",           0,      "init_fs"),
    ("INIT_FILES_OFF",           "init_files",        0,      "init_files"),
]

lines = []
missing = []
print("=== CORRECTED target.h offsets (offset from _text, verified kallsyms) ===\n")
for macro, sym, delta, note in want:
    base = g(sym)
    if base is None:
        missing.append((macro, sym))
        lines.append(f"/* {macro}: symbol '{sym}' NOT FOUND */")
        print(f"  /* {macro:32s} '{sym}' NOT FOUND */")
        continue
    val = base + delta
    d = f" +{delta:#x}" if delta else ""
    lines.append(f"#define {macro} 0x{val:08x}ULL   /* {sym}{d} — {note} */")
    print(f"  #define {macro:32s} 0x{val:08x}ULL   /* {sym}{d} */")

print(f"\nmissing: {len(missing)}")

with open(r"Q:\Deepseek\_neo5\firmware\target_offsets_FIXED.txt", "w") as f:
    f.write("/* Corrected target.h offsets — verified against kallsyms_fixed.txt */\n")
    f.write("/* num_syms=109687, names@0x1feb9cc, offsets@0x1f805cc, markers 429/429 verified */\n\n")
    f.write("\n".join(lines))
print("\nsaved target_offsets_FIXED.txt")

# Also record the filtered (vivo-removed) symbols for documentation
filtered = ['commit_creds','prepare_kernel_cred','init_cred','kernel_init',
            'init_task','_end','__init_begin','__bss_start','_edata','_sdata']
print("\n=== vivo-filtered symbols (present in generic kernel, absent here) ===")
for s in filtered:
    print(f"  {s:24s} {'PRESENT' if g(s) is not None else 'FILTERED (absent)'}")