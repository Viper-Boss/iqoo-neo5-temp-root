# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import struct

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

# __start_init_task = the init_task struct start!
print("__start_init_task:", hex(symtab.get('__start_init_task', 0)))
# init_task itself: on many kernels the symbol init_task exists.
# If not, __start_init_task is equivalent (it IS init_task's start).
INIT_TASK = symtab.get('init_task', symtab.get('__start_init_task'))
print("INIT_TASK =", hex(INIT_TASK))

# commit_creds/prepare_kernel_cred may genuinely be absent? unlikely.
# Search raw names:
for off, nm in syms:
    if 'commit_cred' in nm.lower():
        print(f"found: {nm} @ {off:#x}")
for off, nm in syms:
    if 'prepare_kernel' in nm.lower():
        print(f"found: {nm} @ {off:#x}")

# selinux_state exists; selinux_enforcing doesn't (4.19 uses selinux_state.enforcing)
data = open(r"firmware\kernel_Image", "rb").read()
OFFS_START = 0x1f805bc
count = 109691

# regenerate final offsets list
need = {
    'KIMAGE_TEXT_BASE': None,  # = 0
    'INIT_TASK_OFF': INIT_TASK,
    'INIT_UTS_NS_OFF': symtab.get('init_uts_ns'),
    'EMPTY_ZERO_PAGE_OFF': symtab.get('empty_zero_page'),
    'ROOT_TASK_GROUP_OFF': symtab.get('root_task_group'),
    'SELINUX_ENFORCING_OFF': symtab.get('selinux_state'),  # selinux_state; enforcing at +0
    'SECURITY_HOOK_HEADS_OFF': symtab.get('security_hook_heads'),
    'KMALLOC_CACHES_OFF': symtab.get('kmalloc_caches'),
    'ANON_PIPE_BUF_OPS_OFF': symtab.get('anon_pipe_buf_ops'),
    'NFULNL_LOGGER_OFF': symtab.get('nfulnl_logger'),
    'SYSCTL_BOOTID_OFF': symtab.get('sysctl_bootid'),
    'ASHMEM_MISC_FOPS_OFF': symtab.get('ashmem_misc') and symtab.get('ashmem_misc') + 0x10,
    'ASHMEM_FOPS_OFF': symtab.get('ashmem_fops'),
    'ASHMEM_IOCTL_OFF': symtab.get('ashmem_ioctl'),
    'ASHMEM_COMPAT_IOCTL_OFF': symtab.get('compat_ashmem_ioctl'),
    'ASHMEM_MMAP_OFF': symtab.get('ashmem_mmap'),
    'ASHMEM_OPEN_OFF': symtab.get('ashmem_open'),
    'ASHMEM_RELEASE_OFF': symtab.get('ashmem_release'),
    'ASHMEM_SHOW_FDINFO_OFF': symtab.get('ashmem_show_fdinfo'),
    'CONFIGFS_READ_ITER_OFF': symtab.get('configfs_read_file'),
    'CONFIGFS_BIN_WRITE_ITER_OFF': symtab.get('configfs_write_bin_file'),
    'COPY_SPLICE_READ_OFF': symtab.get('generic_file_splice_read'),
    'NOOP_LLSEEK_OFF': symtab.get('noop_llseek'),
    'INIT_UTS_NS_OFF2': symtab.get('init_uts_ns'),
    'SLIDE_LOGGERS_0_1_OFF': symtab.get('loggers'),
    'SLIDE_SYSCTL_BOOTID_OFF': symtab.get('sysctl_bootid'),
}
print("\n=== FINAL target.h VALUES (offsets from _text, kernel VA base 0xffffff8008080000) ===")
for k, v in need.items():
    if v is not None:
        print(f"#define {k} 0x{v:08x}ULL")
    else:
        print(f"/* {k}: unresolved */")
