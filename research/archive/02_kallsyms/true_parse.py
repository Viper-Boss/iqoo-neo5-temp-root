# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import struct, json
data = open(r"firmware\kernel_Image", "rb").read()

MARKERS0 = 0x21590cc
names_len = 1495175
names_start = MARKERS0 - names_len
names_end = MARKERS0
print(f"exact names_start: {names_start:#x} (0x21590cc - 1495175)")

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
        if p > end:
            return count, p
    return count, p

c, pe = parse_names(names_start, names_end)
print(f"parse: {c} symbols, ended at {pe:#x} (end={names_end:#x}, gap={names_end-pe})")

# try small adjustments for exact landing
for d in range(-8, 9):
    s = names_start + d
    if s < 0: continue
    c2, pe2 = parse_names(s, names_end)
    if pe2 == names_end and c2 > 100000:
        print(f"EXACT: start={s:#x} (d={d}): {c2} symbols")
        names_start = s; c = c2; pe = pe2
        break
    if abs(names_end - pe2) < 8 and c2 > 100000:
        print(f"near: start={s:#x} (d={d}): {c2} syms, gap={names_end-pe2}")

# structure before names_start
print("\n=== u64s before names_start ===")
for skip in range(8, 72, 8):
    np = names_start - skip
    v = struct.unpack_from("<Q", data, np)[0]
    print(f"  ns-{skip}: {v:#x} ({v})")
print("=== u32s ===")
for skip in range(4, 40, 4):
    np = names_start - skip
    v = struct.unpack_from("<I", data, np)[0]
    print(f"  ns-{skip}: {v:#x} ({v})")

# offsets table: if relative_base = u64 at names_start-8:
for skip_r, skip_n in ((8, 16), (16, 8), (12, 20), (20, 12)):
    rb = struct.unpack_from("<Q", data, names_start-skip_r)[0]
    ns_v = struct.unpack_from("<Q", data, names_start-skip_n)[0]
    print(f"try: rb(ns-{skip_r})={rb:#x}, num(ns-{skip_n})={ns_v}")
    if 0xffffff8000000000 <= rb < 0xffffffc000000000 and 100000 < ns_v < 120000:
        print("  ^^^ PLAUSIBLE STRUCTURE!")
        offs_pos = names_start - skip_n - 8 - 4*ns_v
        print(f"  offsets at {offs_pos:#x}")
        # verify: offsets increasing
        o0 = struct.unpack_from("<i", data, offs_pos)[0]
        o1 = struct.unpack_from("<i", data, offs_pos+4)[0]
        olast = struct.unpack_from("<i", data, offs_pos + 4*(ns_v-1))[0]
        print(f"  offsets[0]={o0} [1]={o1} [last]={olast}")
        if o0 < o1 < olast and olast < 0x4000000:
            print("  *** STRUCTURE VERIFIED ***")
            # PARSE ALL
            toks = []
            p = 0x2159ecc
            for i in range(256):
                e = data.find(b"\x00", p)
                toks.append(data[p:e]); p = e + 1
            symbols = []
            pp = names_start
            for i in range(ns_v):
                ln = data[pp]
                if ln & 0x80:
                    ln = ((ln & 0x7f) | (data[pp+1] << 7)) + 2
                    pp += 1
                nm = b"".join(toks[t] for t in data[pp+1:pp+1+ln])
                pp += 1 + ln
                off = struct.unpack_from("<i", data, offs_pos + 4*i)[0]
                symbols.append((rb + off, nm))
            print(f"\nparsed {len(symbols)} symbols")
            for a, n in symbols[:3]: print(f"  {a:#x} {n.decode('latin-1')}")
            for a, n in symbols[-2:]: print(f"  {a:#x} {n.decode('latin-1')}")
            with open(r"firmware\kallsyms.txt","w") as f:
                for a, n in symbols:
                    f.write(f"{a:016x} {n.decode('latin-1')}\n")
            json.dump({"names_start": names_start, "num_syms": ns_v, "relative_base": rb,
                       "offsets_pos": offs_pos, "token_table": 0x2159ecc,
                       "token_index": 0x215a2cc},
                      open(r"firmware\kallsyms_struct.json","w"))
            print("SAVED kallsyms.txt + struct")
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
            open(r"firmware\target_offsets.txt","w").write("\n".join(out))
            break
