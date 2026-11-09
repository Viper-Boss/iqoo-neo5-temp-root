# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import struct

d = open(r"firmware\kernel_Image", "rb").read()

NAMES_S = 0x1feb9cc
NAMES_E = 0x215904e          # zero-length terminator position
MARKERS = 0x21590cc
TOK_TAB = 0x2159ecc
NUM_SYMS = 109687            # u32 @ 0x1feb8cc = 0x1AC77

# token table
toks = []
p = TOK_TAB
for i in range(256):
    e = d.find(b"\x00", p)
    toks.append(d[p:e]); p = e + 1

# ---------- 1. parse names ----------
pos = NAMES_S
names = []
positions = []
while pos < NAMES_E:
    ln = d[pos]
    if ln == 0:
        break
    positions.append(pos)
    names.append(b"".join(toks[t] for t in d[pos+1:pos+1+ln]))
    pos += 1 + ln

print(f"[1] names parsed: {len(names)} (expect {NUM_SYMS})")
print(f"    parse end: {pos:#x} (expect {NAMES_E:#x})")
assert len(names) == NUM_SYMS, "COUNT MISMATCH"
assert pos == NAMES_E, "END MISMATCH"

# ---------- 2. markers cross-check ----------
# markers[k] should equal positions[256k] - NAMES_S
ok8 = ok4 = 0
tot = 0
for k in range(0, 429):
    idx = 256 * k
    if idx >= len(positions):
        break
    expect = positions[idx] - NAMES_S
    tot += 1
    v8 = struct.unpack_from("<I", d, MARKERS + 8*k)[0]
    v4 = struct.unpack_from("<I", d, MARKERS + 4*k)[0]
    if v8 == expect: ok8 += 1
    if v4 == expect: ok4 += 1
print(f"[2] markers cross-check: {tot} markers tested")
print(f"    u32@8-stride matches: {ok8}/{tot}")
print(f"    u32@4-stride matches: {ok4}/{tot}")

# ---------- 3. offsets table: find correct start ----------
for cand in (0x1f805bc, 0x1f805cc):
    offs = [struct.unpack_from("<i", d, cand + 4*i)[0] for i in range(NUM_SYMS)]
    end = cand + 4*NUM_SYMS
    viol = sum(1 for i in range(NUM_SYMS-1) if offs[i] > offs[i+1])
    print(f"[3] start={cand:#x}: end={end:#x} first={offs[0]:#x} last={offs[-1]:#x} "
          f"monotonic-violations={viol} end-at-gap={'YES' if end==0x1feb7a8 else 'no'}")
    if viol == 0:
        chosen = cand
        chosen_offs = offs

print(f"    chosen offsets start: {chosen:#x}")

# ---------- 4. dump ----------
with open(r"firmware\kallsyms_fixed.txt", "w") as f:
    for o, n in zip(chosen_offs, names):
        f.write(f"{o:08x} {n.decode('latin-1')}\n")
print(f"[4] saved kallsyms_fixed.txt ({len(names)} symbols)")

# ---------- 5. probe critical symbols ----------
tab = {}
for o, n in zip(chosen_offs, names):
    s = n.decode('latin-1')
    tab[s[1:]] = (o, s[0])

probes = ['_text','_stext','_etext','__init_begin','_end',
          'init_task','commit_creds','prepare_kernel_cred','kernel_init',
          'init_uts_ns','empty_zero_page','root_task_group',
          'selinux_state','security_hook_heads','kmalloc_caches',
          'anon_pipe_buf_ops','nfulnl_logger','sysctl_bootid',
          'ashmem_fops','ashmem_misc','ashmem_ioctl','compat_ashmem_ioctl',
          'ashmem_mmap','ashmem_open','ashmem_release','ashmem_show_fdinfo',
          'configfs_read_file','configfs_write_bin_file',
          'generic_file_splice_read','noop_llseek','remove_waiter',
          'modprobe_path','loggers','panic','printk',
          'init_cred','init_nsproxy','init_fs','init_files',
          'kallsyms_lookup_name','start_kernel','schedule']
print("\n[5] probe results:")
missing = []
for s in probes:
    if s in tab:
        o, t = tab[s]
        print(f"    {s:28s} {t} 0x{o:08x}")
    else:
        print(f"    {s:28s} MISSING")
        missing.append(s)

print(f"\nfirst 8 symbols:")
for i in range(8):
    print(f"    [{i}] off={chosen_offs[i]:#x} {names[i].decode('latin-1')}")
print(f"last 3 symbols:")
for i in range(len(names)-3, len(names)):
    print(f"    [{i}] off={chosen_offs[i]:#x} {names[i].decode('latin-1')}")