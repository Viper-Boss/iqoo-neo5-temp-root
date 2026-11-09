# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import struct, json
data = open(r"firmware\kernel_Image", "rb").read()

names_start = 0x1febe46
count = 109581

# num_syms/relative_base search: scan u64s before names_start for the pair
found = False
for skip in range(0, 64, 4):
    np = names_start - 8 - skip
    v = struct.unpack_from("<Q", data, np)[0]
    if v == count or v == count + 1 or v == count + 2 or v == count + 3:
        rb = struct.unpack_from("<Q", data, np-8)[0]
        if 0xffffff8000000000 <= rb < 0xffffffc000000000:
            print(f"num_syms={v} @ {np:#x}, relative_base={rb:#x}")
            offs_pos = np - 8 - 4*count
            print(f"offsets table @ {offs_pos:#x}")
            found = True
            break
if not found:
    # fallback: relative_base found earlier at 0x1f804e4 = 0xffffff8008080000
    # offsets table would end at 0x1f804e4... let's scan for it
    print("searching relative_base near 0x1f804e4...")
    rb = 0xffffff8008080000
    rb_pos = 0x1f804e4
    # num_syms right after
    np = rb_pos + 8
    v = struct.unpack_from("<Q", data, np)[0]
    print(f"u64 after base: {v}")
    # if not count, scan for count nearby
    for skip in range(-64, 128, 4):
        vv = struct.unpack_from("<Q", data, rb_pos+8+skip)[0]
        if 100000 < vv < 120000:
            print(f"  candidate num_syms={vv} @ {rb_pos+8+skip:#x}")
            np = rb_pos+8+skip
            count = vv
    offs_pos = rb_pos - 4*count
    print(f"using base={rb:#x}, num_syms={count}, offsets @ {offs_pos:#x}")

# parse all symbols
toks = []
p = 0x2159ecc
for i in range(256):
    e = data.find(b"\x00", p)
    toks.append(data[p:e])
    p = e + 1

symbols = []
pp = names_start
n_ok = 0
for i in range(min(count, 200000)):
    if pp >= len(data): break
    ln = data[pp]
    if ln == 0: break
    if ln & 0x80:
        ln = ((ln & 0x7f) | (data[pp+1] << 7)) + 2
        pp += 1
    try:
        nm = b"".join(toks[t] for t in data[pp+1:pp+1+ln])
    except Exception:
        break
    pp += 1 + ln
    off = struct.unpack_from("<i", data, offs_pos + 4*i)[0]
    symbols.append((rb + off, nm))
    n_ok += 1

print(f"\nparsed {n_ok} symbols")
for a, n in symbols[:3]:
    print(f"  {a:#x} {n.decode('latin-1')}")
for a, n in symbols[-2:]:
    print(f"  {a:#x} {n.decode('latin-1')}")

with open(r"firmware\kallsyms.txt","w") as f:
    for a, n in symbols:
        f.write(f"{a:016x} {n.decode('latin-1')}\n")
print("saved kallsyms.txt")

json.dump({"names_start": names_start, "num_syms": count, "relative_base": rb,
           "offsets_pos": offs_pos, "token_table": 0x2159ecc, "token_index": 0x215a2cc},
          open(r"firmware\kallsyms_struct.json","w"))

# target.h offsets
symtab = {}
for a, n in symbols:
    nm = n.decode('latin-1')
    parts = nm.split(' ', 1)
    symtab[parts[1] if len(parts) == 2 else nm] = a

text_base = symtab.get('_text') or symtab.get('_stext') or symbols[0][0]
print(f"\n_text: {text_base:#x}")

need = ['init_task','init_uts_ns','empty_zero_page','root_task_group',
        'selinux_state','security_hook_heads','kmalloc_caches',
        'anon_pipe_buf_ops','nfulnl_logger','sysctl_bootid',
        'ashmem_fops','ashmem_misc','ashmem_ioctl','compat_ashmem_ioctl',
        'ashmem_mmap','ashmem_open','ashmem_release','ashmem_show_fdinfo',
        'configfs_read_file','configfs_write_bin_file',
        'generic_file_splice_read','noop_llseek','remove_waiter',
        'kallsyms_lookup_name','_text','_stext','commit_creds',
        'prepare_kernel_cred','modprobe_path','loggers','selinux_enforcing',
        'kmalloc_caches','_stext','init_task','panic','printk']
out = []
print("\n=== target.h offsets ===")
for sy in need:
    if sy in symtab:
        line = f"#define {sy.upper()}_OFF 0x{symtab[sy]-text_base:08x}ULL  /* {symtab[sy]:#x} */"
    else:
        line = f"/* {sy}: NOT FOUND */"
    print(line)
    out.append(line)
open(r"firmware\target_offsets.txt","w").write("\n".join(out))
