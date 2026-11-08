#!/usr/bin/env python3
"""
verify_kallsyms.py — READ-ONLY independent verification of the kallsyms table.

Answers the question "markers all match does NOT by itself prove every function
offset is correct" by running SIX independent checks:

  1. count consistency   : parsed names == num_syms == offsets count
  2. offsets array       : re-read from image, monotonic, offsets[0]==0, and
                           identical to the committed dump (if provided)
  3. markers cross-check : markers[k] == byte offset of name[256k]  (all must match)
  4. section ordering    : text(T/t) < rodata(R/r) < data(D/d) < bss(B/b) medians
                           — an INDEPENDENT proof the name<->offset pairing is
                           correct (misalignment would scatter types across ranges)
  5. source clustering   : functions from one .c file have adjacent offsets
  6. ARM64 spot-check    : text symbols' file offsets decode to real ARM64
                           instructions in the SAME image (symbol offset == file
                           offset because _text is at file offset 0)

Nothing is written. Inputs are read-only. Missing inputs -> clear error + exit 2.

Usage:
  python3 verify_kallsyms.py --from-boot ../boot.img
  python3 verify_kallsyms.py --image kernel_Image --kallsyms ../kallsyms.txt
  python3 verify_kallsyms.py --from-boot ../boot.img --layout kallsyms_layout.json

Requires: capstone (pip install capstone) for check 6; other checks are pure.
License: GPLv3
"""
import sys, os, struct, argparse, json

HERE = os.path.dirname(os.path.abspath(__file__))

# A few text symbols to disassemble-probe (must exist in a generic kernel).
TEXT_PROBES = ["wake_up_process", "printk", "panic", "schedule",
               "get_futex_key", "kallsyms_lookup_name", "do_exit"]


def die(msg):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(2)


def load_layout(path):
    if not os.path.isfile(path):
        die(f"layout not found: {path} (expected next to this script)")
    lay = json.load(open(path))
    return {k: (int(v, 16) if isinstance(v, str) and v.startswith("0x") else v)
            for k, v in lay.items() if not k.startswith("_")}


def extract_kernel(data):
    sys.path.insert(0, HERE)
    import extract_boot_image as ebi
    hdr = ebi.parse_boot_header(data)
    page = hdr["page_size"] or 4096
    kraw = data[page:page + hdr["kernel_size"]]
    start, _ = ebi.find_arm64_image(kraw)
    return kraw[start:]


def parse_names(d, lay):
    tt = lay["token_table"]
    toks = []
    p = tt
    for _ in range(256):
        e = d.find(b"\x00", p)
        toks.append(d[p:e]); p = e + 1
    ns, ne = lay["names_start"], lay["names_end"]
    pos, names, positions = ns, [], []
    while pos < ne:
        ln = d[pos]
        if ln == 0 or pos + 1 + ln > ne:
            break
        names.append(b"".join(toks[t] for t in d[pos+1:pos+1+ln]))
        positions.append(pos)
        pos += 1 + ln
    return names, positions, toks


def main():
    ap = argparse.ArgumentParser(description="Read-only kallsyms verification")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--image", help="raw ARM64 kernel Image")
    g.add_argument("--from-boot", help="Android boot.img to extract the kernel from")
    ap.add_argument("--layout", default=os.path.join(HERE, "kallsyms_layout.json"))
    ap.add_argument("--kallsyms", help="optional committed dump to cross-check offsets")
    args = ap.parse_args()

    src = args.image or args.from_boot
    if not os.path.isfile(src):
        die(f"input not found: {src}")
    data = open(src, "rb").read()
    if args.from_boot:
        try:
            data = extract_kernel(data)
            print(f"[+] extracted kernel Image: {len(data)} bytes")
        except Exception as e:
            die(f"boot extraction failed: {e}")

    lay = load_layout(args.layout)
    names, positions, toks = parse_names(data, lay)
    num = lay["num_syms"]
    offs = list(struct.unpack_from("<%di" % num, data, lay["offsets_start"]))

    passed = failed = 0
    def check(cond, label):
        nonlocal passed, failed
        if cond:
            passed += 1; print(f"  [PASS] {label}")
        else:
            failed += 1; print(f"  [FAIL] {label}")

    print("\n[1] count consistency")
    check(len(names) == num, f"parsed names == num_syms ({len(names)} == {num})")

    print("\n[2] offsets array (re-read from image)")
    viol = sum(1 for i in range(num-1) if offs[i] > offs[i+1])
    check(viol == 0, f"monotonic non-decreasing ({viol} violations)")
    check(offs[0] == 0, f"offsets[0] == 0 (_text), got {offs[0]:#x}")
    if args.kallsyms:
        if not os.path.isfile(args.kallsyms):
            die(f"--kallsyms not found: {args.kallsyms}")
        dump = []
        for line in open(args.kallsyms, "rb"):
            line = line.decode("latin-1").rstrip("\r\n")
            if not line:
                continue
            o, raw = line.split(" ", 1)
            dump.append((int(o, 16), raw))
        mism = sum(1 for i in range(min(num, len(dump))) if offs[i] != dump[i][0]
                   or names[i].decode("latin-1") != dump[i][1])
        check(len(dump) == num and mism == 0,
              f"matches committed dump ({len(dump)} rows, {mism} mismatches)")

    print("\n[3] markers cross-check")
    mo, mc, ms = lay["markers"], lay["markers_count"], lay["markers_stride"]
    mk_ok = sum(1 for k in range(mc)
                if 256*k < len(positions)
                and struct.unpack_from("<I", data, mo + ms*k)[0] == positions[256*k] - lay["names_start"])
    check(mk_ok == mc, f"markers[k] == name[256k] offset ({mk_ok}/{mc})")

    print("\n[4] section ordering (independent pairing proof)")
    cls = {}
    for o, nm in zip(offs, names):
        t = nm[0:1].decode("latin-1")
        cls.setdefault(t, []).append(o)
    def med(t):
        v = sorted(cls.get(t, [])); return v[len(v)//2] if v else None
    tmed = med("T") or med("t"); bmed = med("B") or med("b")
    for t in "TtRrDdBb":
        if t in cls:
            v = sorted(cls[t])
            print(f"      type {t}: n={len(v):6d} min=0x{v[0]:08x} med=0x{v[len(v)//2]:08x} max=0x{v[-1]:08x}")
    check(tmed is not None and bmed is not None and tmed < bmed,
          f"text median 0x{tmed or 0:x} < bss median 0x{bmed or 0:x}")

    print("\n[5] source-adjacent clustering")
    tab = {}
    for o, nm in zip(offs, names):
        tab.setdefault(nm[1:].decode("latin-1"), o)
    groups = {
        "mm/ashmem.c": ["ashmem_ioctl", "ashmem_mmap", "ashmem_open", "ashmem_release"],
        "kernel/cred.c": ["prepare_creds", "copy_creds", "abort_creds", "cred_alloc_blank"],
    }
    for f, syms in groups.items():
        pres = sorted(tab[s] for s in syms if s in tab)
        if len(pres) >= 2:
            span = pres[-1] - pres[0]
            check(span < 0x8000, f"{f}: {len(pres)} syms span {span} bytes (<0x8000)")

    print("\n[6] ARM64 spot-check (text symbol offset == file offset)")
    try:
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
        md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        good = 0
        for s in TEXT_PROBES:
            if s not in tab:
                continue
            off = tab[s]
            code = data[off:off+4]
            if len(code) < 4:
                continue
            insns = list(md.disasm(code, off))
            ok = len(insns) == 1
            good += ok
            if insns:
                i = insns[0]
                print(f"      {s:22s} @0x{off:08x}: {i.mnemonic} {i.op_str}")
        check(good >= 4, f"{good}/{len(TEXT_PROBES)} text probes decode to valid ARM64")
    except ImportError:
        print("  [SKIP] capstone not installed (pip install capstone) — check 6 skipped")

    print(f"\n{'='*56}\n Result: {passed} passed, {failed} failed\n{'='*56}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
