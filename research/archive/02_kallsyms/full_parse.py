# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import struct

data = open(r"firmware\kernel_Image", "rb").read()

# ==== Step 1: token_table exact boundaries ====
# digits run '0\0'..'9\0' at 0x2159fcd (token index 0x30 = 48)
digit_pos = 0x2159fcd
# walk back exactly 49 tokens to table start (so token[48]=='0')
p = digit_pos
for i in range(49):
    p = data.rfind(b"\x00", 0, p)
    assert p > 0
tt_start = p + 1
# token 48 = "0" is at digit_pos; check: data[tt_start:] first token after walk
# find token_index: after the table end. Table end: scan 256 tokens from tt_start
p2 = tt_start
tokens = []
for i in range(256):
    e = data.find(b"\x00", p2)
    if e == -1: break
    tokens.append(data[p2:e])
    p2 = e + 1
tt_end = p2
print(f"token_table: {tt_start:#x}-{tt_end:#x} ({tt_end-tt_start} bytes, {len(tokens)} tokens)")
# sanity: token 48 should be "0"
assert tokens[48] == b"0", f"token 48 = {tokens[48]!r}"
print("token 48 = '0' ✓")

# ==== Step 2: token_index ====
ti = 0x215a2cc  # verified 256/256
idx = struct.unpack("<256H", data[ti:ti+512])
token_index = idx
ti_pos = ti
print(f"token_index @{ti:#x} (hardcoded, verified)")

# ==== Step 3: names end & start ====
names_end = tt_start
# align down to 8 and strip zero padding
while names_end > 0 and data[names_end-1] == 0:
    names_end -= 1
print(f"names end: {names_end:#x}")

# find names start: forward-parse from candidates; parse must end exactly at names_end-1 (last entry len=0)
def parse_names(start, end):
    """parse [len][tokens] entries; returns (count, ok)"""
    p = start
    count = 0
    while p < end:
        ln = data[p]
        if ln == 0:
            # terminating entry
            return count, p == end - 1
        if ln & 0x80:
            ln = ((ln & 0x7f) | (data[p+1] << 7)) + 2
            p += 1
        p += 1 + ln
        count += 1
        if p > end:
            return count, False
    return count, False

# scan backward for start candidates - try BOTH 8-aligned and unaligned (every 4 and also every 1)
best = None
for step in (8, 4, 1):
    for guess_end_off in range(1, 400000, step):
        start = names_end - guess_end_off
        if start < 0: break
        # quick check: first byte plausible length, second byte = valid token index
        ln = data[start]
        if ln == 0 or ln > 60: continue
        ti0 = data[start+1]
        if ti0 >= 256: continue
        tok = tokens[ti0] if ti0 < len(tokens) else b""
        if not tok or tok[0:1].lower() not in b"tuvwdbrnagpmcsi":
            continue
        count, ok = parse_names(start, names_end)
        if ok and count > 10000:
            print(f"names start: {start:#x} ({count} symbols, step={step})")
            best = (start, count)
            break
    if best: break

if not best:
    raise SystemExit("names start not found")
names_start, num_syms = best

# ==== Step 4: num_syms u64 before names ====
# search backward within 256+8 bytes
needle = struct.pack("<Q", num_syms)
pos = data.rfind(needle, max(0, names_start-300), names_start)
print(f"num_syms ({num_syms}) encoded at: {pos:#x}" if pos >= 0 else "num_syms not found!")
num_syms_pos = pos

# ==== Step 5: offsets & relative_base ====
# layout: kallsyms_offsets (s32*num_syms) then kallsyms_relative_base (u64) then num_syms
# offsets table start = num_syms_pos - 8 - 4*num_syms (relative_base right before num_syms)
# actually: offsets, then relative_base(u64), then num_syms(u64), then names
# find relative_base: the u64 right before num_syms_pos (aligned 8)
rb_pos = num_syms_pos - 8
relative_base = struct.unpack_from("<Q", data, rb_pos)[0]
print(f"relative_base @ {rb_pos:#x}: {relative_base:#x}")

offsets_pos = rb_pos - 4 * num_syms
# align down to 4
offsets_pos -= offsets_pos % 4
print(f"offsets table @ {offsets_pos:#x} ({num_syms} x s32)")

# sanity check: offsets[0] should be small (first symbol near relative_base)
off0 = struct.unpack_from("<i", data, offsets_pos)[0]
print(f"offsets[0] = {off0} ({off0:#x})")

# ==== Step 6: parse symbols ====
# decode names
def decode_name(p):
    ln = data[p]
    if ln & 0x80:
        ln = ((ln & 0x7f) | (data[p+1] << 7)) + 2
        p += 1
    tokens_bytes = data[p+1:p+1+ln]
    name = b"".join(tokens[t] for t in tokens_bytes)
    return name, p + 1 + ln

symbols = []
p = names_start
for i in range(num_syms):
    name, p = decode_name(p)
    off = struct.unpack_from("<i", data, offsets_pos + 4*i)[0]
    addr = relative_base + off
    symbols.append((addr, name))

print(f"\nparsed {len(symbols)} symbols")
# the first few symbols
for a, n in symbols[:5]:
    print(f"  {a:#x} {n.decode('latin-1')}")
print("  ...")
for a, n in symbols[-3:]:
    print(f"  {a:#x} {n.decode('latin-1')}")

# save
with open(r"firmware\kallsyms.txt", "w") as f:
    for a, n in symbols:
        f.write(f"{a:016x} {n.decode('latin-1')}\n")
print("\nsaved kallsyms.txt")

# target.h symbol lookups!
need = ['init_task', 'init_uts_ns', 'empty_zero_page', 'root_task_group',
        'selinux_state', 'security_hook_heads', 'kmalloc_caches',
        'anon_pipe_buf_ops', 'nfulnl_logger', 'sysctl_bootid',
        'ashmem_fops', 'ashmem_misc', 'ashmem_ioctl', 'compat_ashmem_ioctl',
        'ashmem_mmap', 'ashmem_open', 'ashmem_release', 'ashmem_show_fdinfo',
        'configfs_read_file', 'configfs_write_bin_file',
        'generic_file_splice_read', 'noop_llseek', 'kallsyms_lookup_name',
        'remove_waiter', 'futex_requeue', 'kimage_voffset', '_text', '_stext',
        'commit_creds', 'prepare_kernel_cred', 'modprobe_path',
        'loggers', 'nf_log_set']
symtab = {}
for a, n in symbols:
    nm = n.decode('latin-1')
    # strip type char prefix (1 char) for kallsyms format 't name'
    parts = nm.split(' ', 1)
    if len(parts) == 2:
        symtab[parts[1]] = a
    else:
        symtab[nm] = a

# find _text = first symbol address
text_base = symtab.get('_text') or symtab.get('_stext') or symbols[0][0]
print(f"\n_text base: {text_base:#x}")
print("\n=== target.h offsets (sym - _text) ===")
for s in need:
    if s in symtab:
        print(f"#define {s.upper()}_OFF 0x{symtab[s]-text_base:08x}ULL  /* {symtab[s]:#x} */")
    else:
        print(f"/* {s}: NOT FOUND */")
