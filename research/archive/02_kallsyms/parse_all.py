# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import struct, json
data = open(r"firmware\kernel_Image", "rb").read()

# markers: u32 values at 8-byte stride; find markers[0]=0
# values found: 2838@0x21590d4, 6085@0x21590dc, 9078@0x21590e4...
# walk backward until u32 == 0
pos = 0x21590d4
while True:
    v = struct.unpack_from("<I", data, pos - 8)[0]
    if v == 0 or v > 3000:
        break
    pos -= 8
print(f"markers start (first 0): {pos-8:#x}")
m_start = pos - 8
# verify
v = struct.unpack_from("<I", data, m_start)[0]
print(f"value at m_start: {v}")
if v != 0:
    m_start = pos
    print("using pos as start")

# collect markers
entries = []
off = m_start
while off + 8 <= 0x2159ecc:
    v = struct.unpack_from("<I", data, off)[0]
    if v == 0 and len(entries) > 2:
        break
    entries.append(v)
    off += 8
print(f"markers: {len(entries)} entries, first={entries[:3]}, last={entries[-3:]}")

names_end = m_start
names_len = entries[-1]
names_start = names_end - names_len
print(f"names: {names_start:#x}..{names_end:#x} ({names_len} bytes)")

def parse_names(start, end):
    p = start; count = 0
    while p < end:
        ln = data[p]
        if ln == 0:
            return count, p
        if ln & 0x80:
            ln = ((ln & 0x7f) | (data[p+1] << 7)) + 2
            p += 1
        p += 1 + ln
        count += 1
        if p > end: return count, p
    return count, p

# find exact start
best = None
for d in range(-512, 513):
    s = names_start + d
    if s < 0: continue
    c, pe = parse_names(s, names_end)
    if c > 100000:
        if pe == names_end:
            best = (s, c)
            break
        if best is None:
            best = (s, c)

s, c = best
print(f"\nnames_start={s:#x}, {c} symbols, parse ends at {pe:#x} (names_end {names_end:#x})")

# num_syms & relative_base: search u64 == c before s
for skip in range(0, 256, 4):
    np = s - 8 - skip
    if np < 8: break
    v = struct.unpack_from("<Q", data, np)[0]
    if v == c:
        rb = struct.unpack_from("<Q", data, np-8)[0]
        print(f"num_syms={c} @ {np:#x}, relative_base={rb:#x}")
        offs_pos = np - 8 - 4*c
        print(f"offsets @ {offs_pos:#x}")
        json.dump({"names_start": s, "names_end": names_end, "num_syms": c,
                   "num_syms_pos": np, "relative_base": rb, "offsets_pos": offs_pos,
                   "token_table": 0x2159ecc, "token_index": 0x215a2cc},
                  open(r"firmware\kallsyms_struct.json","w"))
        # PARSE ALL SYMBOLS NOW
        toks = []
        p = 0x2159ecc
        for i in range(256):
            e = data.find(b"\x00", p)
            toks.append(data[p:e])
            p = e + 1
        symbols = []
        pp = s
        for i in range(c):
            ln = data[pp]
            if ln & 0x80:
                ln = ((ln & 0x7f) | (data[pp+1] << 7)) + 2
                pp += 1
            nm = b"".join(toks[t] for t in data[pp+1:pp+1+ln])
            pp += 1 + ln
            off = struct.unpack_from("<i", data, offs_pos + 4*i)[0]
            symbols.append((rb + off, nm))
        print(f"\nparsed {len(symbols)} symbols; first 3:")
        for a, n in symbols[:3]: print(f"  {a:#x} {n.decode('latin-1')}")
        with open(r"firmware\kallsyms.txt","w") as f:
            for a, n in symbols:
                f.write(f"{a:016x} {n.decode('latin-1')}\n")
        print("SAVED kallsyms.txt")
        # target.h offsets
        symtab = {}
        for a, n in symbols:
            nm = n.decode('latin-1')
            parts = nm.split(' ', 1)
            symtab[parts[1] if len(parts)==2 else nm] = a
        text_base = symtab.get('_text', symbols[0][0])
        print(f"\n_text: {text_base:#x}")
        need = ['init_task','init_uts_ns','empty_zero_page','root_task_group',
                'selinux_state','security_hook_heads','kmalloc_caches',
                'anon_pipe_buf_ops','nfulnl_logger','sysctl_bootid',
                'ashmem_fops','ashmem_misc','ashmem_ioctl','compat_ashmem_ioctl',
                'ashmem_mmap','ashmem_open','ashmem_release','ashmem_show_fdinfo',
                'configfs_read_file','configfs_write_bin_file',
                'generic_file_splice_read','noop_llseek','remove_waiter',
                'kallsyms_lookup_name','_text','_stext','commit_creds',
                'prepare_kernel_cred','modprobe_path','loggers']
        print("\n=== target.h symbol offsets ===")
        for sy in need:
            if sy in symtab:
                print(f"#define {sy.upper()}_OFF 0x{symtab[sy]-text_base:08x}ULL")
            else:
                print(f"/* {sy}: NOT FOUND */")
        break
