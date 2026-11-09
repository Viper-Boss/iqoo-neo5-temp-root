# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import struct

d = open(r"firmware\kernel_Image", "rb").read()

OFFS_S = 0x1f805bc
OFFS_N = 109691
MARKERS = 0x21590cc          # markers[0] byte position; names must end here
TOK_TAB = 0x2159ecc

# token table
toks = []
p = TOK_TAB
for i in range(256):
    e = d.find(b"\x00", p)
    toks.append(d[p:e]); p = e + 1
print(f"tokens: {len(toks)} token[48]={toks[48]!r}")

def parse_plain(start, end, limit=200000):
    """4.19 upstream: [u8 len][len token indices], no 0x80 extension."""
    p = start
    n = 0
    names = []
    while p < end and n < limit:
        ln = d[p]
        if ln == 0:
            return names, p, "zero_len"
        if p + 1 + ln > end:
            return names, p, "overflow"
        names.append(b"".join(toks[t] for t in d[p+1:p+1+ln]))
        p += 1 + ln
        n += 1
    return names, p, "ok"

def parse_ext(start, end, limit=200000):
    """with 0x80 extended length (5.x style backport)."""
    p = start
    n = 0
    names = []
    while p < end and n < limit:
        ln = d[p]
        if ln == 0:
            return names, p, "zero_len"
        if ln & 0x80:
            ln = (ln & 0x7f) | (d[p+1] << 7)
            p += 1
        if p + 1 + ln > end:
            return names, p, "overflow"
        names.append(b"".join(toks[t] for t in d[p+1:p+1+ln]))
        p += 1 + ln
        n += 1
    return names, p, "ok"

print("\n=== brute-force names start ===")
hits = []
for parser, tag in ((parse_plain, "plain"), (parse_ext, "ext")):
    for delta in range(0, 0x600):
        S = 0x1feb7a8 + delta
        names, endp, why = parser(S, MARKERS, OFFS_N + 10)
        if len(names) == OFFS_N and endp == MARKERS:
            hits.append((tag, S, delta, len(names), endp))
            print(f"  HIT {tag}: start={S:#x} (0x1feb7a8+{delta:#x}) count={len(names)} end={endp:#x}")

if not hits:
    print("  no exact hit; nearest by count:")
    best = []
    for parser, tag in ((parse_plain, "plain"), (parse_ext, "ext")):
        for delta in range(0, 0x600):
            S = 0x1feb7a8 + delta
            names, endp, why = parser(S, MARKERS, OFFS_N + 10)
            if abs(len(names) - OFFS_N) < 60:
                best.append((abs(len(names)-OFFS_N), tag, S, len(names), endp, why))
    for b in sorted(best)[:12]:
        print(f"   diff={b[0]:3d} {b[1]:5s} start={b[2]:#x} count={b[3]} end={b[4]:#x} {b[5]}")

if hits:
    tag, S, delta, cnt, endp = hits[0]
    parser = parse_plain if tag == "plain" else parse_ext
    names, _, _ = parser(S, MARKERS, OFFS_N)
    print(f"\n=== using {tag} start={S:#x} ===")
    # sanity: first / last names
    print("  first 6:", [n.decode('latin-1') for n in names[:6]])
    print("  last  3:", [n.decode('latin-1') for n in names[-3:]])
    # pair and check monotonic offsets
    offs = [struct.unpack_from("<i", d, OFFS_S + 4*i)[0] for i in range(OFFS_N)]
    viol = sum(1 for i in range(OFFS_N-1) if offs[i] > offs[i+1])
    print(f"  offsets monotonic violations: {viol}")
    # write dump
    with open(r"firmware\kallsyms_fixed.txt", "w") as f:
        for o, n in zip(offs, names):
            f.write(f"{o:08x} {n.decode('latin-1')}\n")
    print("  saved kallsyms_fixed.txt")
    # key symbol probes
    tab = {}
    for o, n in zip(offs, names):
        s = n.decode('latin-1')
        if len(s) >= 2:
            tab[s[1:]] = o
    probes = ['_text','_stext','_etext','commit_creds','prepare_kernel_cred',
              'init_task','kernel_init','__arm64_sys_read','selinux_state',
              'kmalloc_caches','ashmem_fops','configfs_read_file','remove_waiter',
              'init_uts_ns','empty_zero_page','root_task_group','security_hook_heads',
              'anon_pipe_buf_ops','modprobe_path','generic_file_splice_read','noop_llseek',
              'panic','printk','init_cred','init_nsproxy','init_fs','init_files']
    print("\n  === probe ===")
    for s in probes:
        print(f"    {s:26s} {'0x%08x' % tab[s] if s in tab else 'MISSING'}")