import struct, json

data = open(r"Q:\Deepseek\_neo5\firmware\kernel_Image", "rb").read()

OFFS_START = 0x1f805bc
OFFS_COUNT = 109691
NAMES_END = 0x21590cc  # markers start
# names soup region: from ~0x1feb9c8 to NAMES_END
NAMES_LO = 0x1feb9c8

toks = []
p = 0x2159ecc
for i in range(256):
    e = data.find(b"\x00", p)
    toks.append(data[p:e]); p = e + 1

def parse_names_ext(start, end, max_entries=200000):
    """with 0x80 extension (4.19 style for long names)"""
    p = start
    entries = []
    while p < end and len(entries) < max_entries:
        ln = data[p]
        if ln == 0:
            break
        if ln & 0x80:
            ln = ((ln & 0x7f) | (data[p+1] << 7)) + 2
            p += 1
        if p + 1 + ln > end:
            break
        nm = b"".join(toks[t] for t in data[p+1:p+1+ln])
        entries.append(nm)
        p += 1 + ln
    return entries, p

# find start such that count == OFFS_COUNT and end lands at NAMES_END
best = None
for delta in range(0, 4096):
    for d in (-delta, delta) if delta else (0,):
        s = 0x1febe46 + d
        if s < NAMES_LO: continue
        entries, pe = parse_names_ext(s, NAMES_END)
        if len(entries) == OFFS_COUNT:
            print(f"FOUND: start={s:#x} (delta {d}): {len(entries)} entries, ends at {pe:#x}")
            best = (s, entries)
            break
        if len(entries) >= OFFS_COUNT - 50 and pe >= NAMES_END - 200:
            if best is None:
                best = (s, entries)
    if best: break

if best:
    s, entries = best
    print(f"using start {s:#x}, {len(entries)} names")
    # pair with offsets
    symbols = []
    for i, nm in enumerate(entries):
        off = struct.unpack_from("<i", data, OFFS_START + 4*i)[0]
        symbols.append((off, nm))
    # first few (offset, name)
    for o, n in symbols[:5]:
        print(f"  off={o:#x} {n.decode('latin-1')[:60]}")
    # save (offsets from _text — exactly what target.h needs!)
    with open(r"Q:\Deepseek\_neo5\firmware\kallsyms.txt","w") as f:
        for o, n in symbols:
            f.write(f"{o:08x} {n.decode('latin-1')}\n")
    print("SAVED kallsyms.txt (offset from _text!)")
    json.dump({"offsets_start": OFFS_START, "names_start": s, "count": len(entries),
               "token_table": 0x2159ecc, "token_index": 0x215a2cc},
              open(r"Q:\Deepseek\_neo5\firmware\kallsyms_struct.json","w"))

    symtab = {}
    for o, n in symbols:
        nm = n.decode('latin-1')
        parts = nm.split(' ', 1)
        symtab[parts[1] if len(parts) == 2 else nm] = o

    need = ['init_task','init_uts_ns','empty_zero_page','root_task_group',
            'selinux_state','security_hook_heads','kmalloc_caches',
            'anon_pipe_buf_ops','nfulnl_logger','sysctl_bootid',
            'ashmem_fops','ashmem_misc','ashmem_ioctl','compat_ashmem_ioctl',
            'ashmem_mmap','ashmem_open','ashmem_release','ashmem_show_fdinfo',
            'configfs_read_file','configfs_write_bin_file',
            'generic_file_splice_read','noop_llseek','remove_waiter',
            'kallsyms_lookup_name','_stext','_text','commit_creds','prepare_kernel_cred',
            'modprobe_path','loggers','selinux_enforcing','panic','printk',
            'selinux_state','kmalloc_caches','init_task','stack_chk_guard',
            'selinux_hooks','init_cred','init_nsproxy','init_fs','init_files']
    print("\n=== target.h offsets (from _text) ===")
    out = []
    for sy in need:
        if sy in symtab:
            l = f"#define {sy.upper()}_OFF 0x{symtab[sy]:08x}ULL"
        else:
            l = f"/* {sy}: NOT FOUND */"
        print(l); out.append(l)
    open(r"Q:\Deepseek\_neo5\firmware\target_offsets.txt","w").write("\n".join(out))
else:
    print("exact match not found; best-effort:")
    entries, pe = parse_names_ext(0x1febe46, NAMES_END)
    print(f"  from 0x1febe46: {len(entries)} entries")
