import struct, json
data = open(r"Q:\Deepseek\_neo5\firmware\kernel_Image", "rb").read()

MARKERS0 = 0x21590cc
names_len = 1495175
names_start = MARKERS0 - names_len
names_end = MARKERS0

# 4.19 format: entry = [u8 len][len bytes]  (no 0x80 extension!)
def parse_names(start, end):
    p = start; count = 0
    while p < end:
        ln = data[p]
        if ln == 0:
            return count, p
        p += 1 + ln
        count += 1
        if p > end:
            return count, p
    return count, p

c, pe = parse_names(names_start, names_end)
print(f"4.19-format parse from {names_start:#x}: {c} symbols, ended at {pe:#x} (end={names_end:#x})")

# find exact landing
for d in range(-16, 17):
    s = names_start + d
    c2, pe2 = parse_names(s, names_end)
    if pe2 == names_end:
        print(f"EXACT: start={s:#x} (d={d}): {c2} symbols")
        names_start = s; c = c2
        break

# structure before: [offsets][relative_base u64][num_syms u64][names]
# num_syms at names_start-8, relative_base at names_start-16
ns_pos = names_start - 8
rb_pos = names_start - 16
num_syms_v = struct.unpack_from("<Q", data, ns_pos)[0]
rb = struct.unpack_from("<Q", data, rb_pos)[0]
print(f"\nnum_syms candidate (ns-8): {num_syms_v}")
print(f"relative_base candidate (ns-16): {rb:#x}")
if not (10000 < num_syms_v < 500000 and 0xffffff8000000000 <= rb < 0xffffffc000000000):
    # try other spacings / u32 num_syms
    for layout in ((12, 20), (16, 24), (8, 12), (4, 8), (8, 16)):
        npos = names_start - layout[0]
        rpos = names_start - layout[1]
        nv = struct.unpack_from("<Q", data, npos)[0]
        rv = struct.unpack_from("<Q", data, rpos)[0]
        nv32 = struct.unpack_from("<I", data, npos)[0]
        print(f"layout {layout}: num={nv} (u32:{nv32}) rb={rv:#x}")

# offsets table: ends at rb_pos
offs_pos = rb_pos - 4 * c
print(f"\noffsets table: {offs_pos:#x}..{rb_pos:#x} ({c} s32)")
o0 = struct.unpack_from("<i", data, offs_pos)[0]
o1 = struct.unpack_from("<i", data, offs_pos+4)[0]
olast = struct.unpack_from("<i", data, offs_pos + 4*(c-1))[0]
print(f"offsets[0]={o0} ({o0:#x}) [1]={o1} last={olast} ({olast:#x})")
mono = True
prev = None
bad = 0
for i in range(0, c, 997):
    v = struct.unpack_from("<i", data, offs_pos + 4*i)[0]
    if prev is not None and v < prev:
        bad += 1
    prev = v
print(f"monotonicity (sampled): {bad} violations")

# PARSE ALL with 4.19 format
toks = []
p = 0x2159ecc
for i in range(256):
    e = data.find(b"\x00", p)
    toks.append(data[p:e]); p = e + 1

symbols = []
pp = names_start
for i in range(c):
    ln = data[pp]
    nm = b"".join(toks[t] for t in data[pp+1:pp+1+ln])
    pp += 1 + ln
    off = struct.unpack_from("<i", data, offs_pos + 4*i)[0]
    symbols.append((rb + off, nm))

print(f"\nparsed {len(symbols)} symbols")
for a, n in symbols[:4]: print(f"  {a:#x} {n.decode('latin-1')}")
for a, n in symbols[-3:]: print(f"  {a:#x} {n.decode('latin-1')}")

with open(r"Q:\Deepseek\_neo5\firmware\kallsyms.txt","w") as f:
    for a, n in symbols:
        f.write(f"{a:016x} {n.decode('latin-1')}\n")
json.dump({"names_start": names_start, "num_syms": c, "relative_base": rb,
           "offsets_pos": offs_pos, "token_table": 0x2159ecc, "token_index": 0x215a2cc},
          open(r"Q:\Deepseek\_neo5\firmware\kallsyms_struct.json","w"))
print("SAVED")

# target offsets
symtab = {}
for a, n in symbols:
    nm = n.decode('latin-1')
    parts = nm.split(' ', 1)
    symtab[parts[1] if len(parts) == 2 else nm] = a
text_base = symtab.get('_text', symbols[0][0])
print(f"\n_text: {text_base:#x}")
need = ['init_task','init_uts_ns','empty_zero_page','root_task_group',
        'selinux_state','security_hook_heads','kmalloc_caches',
        'anon_pipe_buf_ops','nfulnl_logger','sysctl_bootid',
        'ashmem_fops','ashmem_misc','ashmem_ioctl','compat_ashmem_ioctl',
        'ashmem_mmap','ashmem_open','ashmem_release','ashmem_show_fdinfo',
        'configfs_read_file','configfs_write_bin_file',
        'generic_file_splice_read','noop_llseek','remove_waiter',
        'kallsyms_lookup_name','_stext','commit_creds','prepare_kernel_cred',
        'modprobe_path','loggers','selinux_enforcing','panic','printk']
print("\n=== target.h offsets ===")
out = []
for sy in need:
    if sy in symtab:
        l = f"#define {sy.upper()}_OFF 0x{symtab[sy]-text_base:08x}ULL  /* {symtab[sy]:#x} */"
    else:
        l = f"/* {sy}: NOT FOUND */"
    print(l); out.append(l)
open(r"Q:\Deepseek\_neo5\firmware\target_offsets.txt","w").write("\n".join(out))
