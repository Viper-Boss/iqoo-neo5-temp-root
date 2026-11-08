import struct, json

data = open(r"../../kernel_Image", "rb").read()

# known segment of offsets table: 0x1f80f94 (starts at value 175980)
# find table start: scan backward allowing non-decreasing (>=) values in [0, 0x4000000)
def scan_back(pos):
    p = pos
    while p - 4 >= 0:
        v = struct.unpack_from("<i", data, p-4)[0]
        v_next = struct.unpack_from("<i", data, p)[0]
        if v < 0 or v > 0x4000000 or v > v_next:
            break
        p -= 4
    return p

start = scan_back(0x1f80f94)
v0 = struct.unpack_from("<i", data, start)[0]
print(f"table start: {start:#x}, first value: {v0} ({v0:#x})")
# scan forward to find end (allowing equals, values in range)
p = start
count = 0
last_v = -1
while p + 4 <= len(data):
    v = struct.unpack_from("<i", data, p)[0]
    if v < 0 or v > 0x4000000:
        break
    if v < last_v:
        break
    last_v = v
    count += 1
    p += 4
end = p
print(f"table end: {end:#x}, {count} entries, last value: {last_v} ({last_v:#x})")

# what follows: relative_base + num_syms?
for skip in range(0, 32, 4):
    rb = struct.unpack_from("<Q", data, end+skip)[0]
    if 0xffffff8000000000 <= rb < 0xffffffc000000000:
        print(f"relative_base at end+{skip}: {rb:#x}")
        # num_syms after
        for skip2 in range(0, 32, 4):
            nv = struct.unpack_from("<Q", data, end+skip+8+skip2)[0]
            nv32 = struct.unpack_from("<I", data, end+skip+8+skip2)[0]
            if 50000 < nv < 300000 or 50000 < nv32 < 300000:
                print(f"  num_syms candidate at +{8+skip2}: u64={nv} u32={nv32}")
                break
        break

# names start = after the structure
# try: end + rb(8) + num(8 or 4)
for layout in [(8,8),(8,4),(4,8),(4,4)]:
    ns_pos = end + layout[0]
    rb = struct.unpack_from("<Q", data, end)[0]
    if not (0xffffff8000000000 <= rb < 0xffffffc000000000):
        # rb might need alignment
        for a in range(0, 8, 4):
            rb2 = struct.unpack_from("<Q", data, end+a)[0]
            if 0xffffff8000000000 <= rb2 < 0xffffffc000000000:
                rb = rb2
                end_aligned = end + a
                break
        else:
            continue
    ns_pos = end_aligned + 8
    num = struct.unpack_from("<Q", data, ns_pos)[0]
    if 50000 < num < 300000:
        names_start = ns_pos + 8
        print(f"\nSTRUCTURE: rb={rb:#x} @ {end_aligned:#x}, num_syms={num} @ {ns_pos:#x}, names @ {names_start:#x}")
        # verify names parse
        toks = []
        pp = 0x2159ecc
        for i in range(256):
            e = data.find(b"\x00", pp)
            toks.append(data[pp:e]); pp = e + 1
        # parse with 4.19 format
        p = names_start
        symbols = []
        for i in range(num):
            if p >= len(data): break
            ln = data[p]
            if ln == 0:
                print(f"  terminator at entry {i}")
                break
            try:
                nm = b"".join(toks[t] for t in data[p+1:p+1+ln])
            except Exception:
                print(f"  bad token at entry {i}")
                break
            p += 1 + ln
            off = struct.unpack_from("<i", data, start + 4*i)[0]
            symbols.append((rb + off, nm))
        print(f"  parsed {len(symbols)} symbols, names consumed to {p:#x} (target: markers @ 0x21590cc)")
        if len(symbols) > 100000:
            # SUCCESS - dump everything
            for a, n in symbols[:3]: print(f"    {a:#x} {n.decode('latin-1')}")
            for a, n in symbols[-2:]: print(f"    {a:#x} {n.decode('latin-1')}")
            with open(r"../../kallsyms.txt","w") as f:
                for a, n in symbols:
                    f.write(f"{a:016x} {n.decode('latin-1')}\n")
            json.dump({"offsets_start": start, "num_syms": num, "relative_base": rb,
                       "names_start": names_start, "token_table": 0x2159ecc,
                       "token_index": 0x215a2cc},
                      open(r"../../kallsyms_struct.json","w"))
            print("  SAVED kallsyms.txt")
            # target offsets
            symtab = {}
            for a, n in symbols:
                nm = n.decode('latin-1')
                parts = nm.split(' ', 1)
                symtab[parts[1] if len(parts) == 2 else nm] = a
            text_base = symtab.get('_text', symbols[0][0])
            print(f"  _text: {text_base:#x}")
            need = ['init_task','init_uts_ns','empty_zero_page','root_task_group',
                    'selinux_state','security_hook_heads','kmalloc_caches',
                    'anon_pipe_buf_ops','nfulnl_logger','sysctl_bootid',
                    'ashmem_fops','ashmem_misc','ashmem_ioctl','compat_ashmem_ioctl',
                    'ashmem_mmap','ashmem_open','ashmem_release','ashmem_show_fdinfo',
                    'configfs_read_file','configfs_write_bin_file',
                    'generic_file_splice_read','noop_llseek','remove_waiter',
                    'kallsyms_lookup_name','_stext','commit_creds','prepare_kernel_cred',
                    'modprobe_path','loggers','selinux_enforcing','panic','printk']
            print("  === target.h offsets ===")
            out = []
            for sy in need:
                if sy in symtab:
                    l = f"#define {sy.upper()}_OFF 0x{symtab[sy]-text_base:08x}ULL  /* {symtab[sy]:#x} */"
                else:
                    l = f"/* {sy}: NOT FOUND */"
                print("  "+l); out.append(l)
            open(r"../../target_offsets.txt","w").write("\n".join(out))
        break
