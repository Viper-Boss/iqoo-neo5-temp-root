#!/usr/bin/env python3
"""
disasm_futex.py — Reproduce the futex static analysis from
analysis/futex_disassembly_report.md.

Disassembles the target kernel's get_futex_key / futex_wake / futex_init /
get_task_mm and scans every inlined hash_futex() seed site, so anyone can
re-verify the conclusions:
  - futex_key layout (mm@0, address@8, offset@16)
  - hash input order/length ([mm_lo,mm_hi,addr_lo,addr_hi], 4 u32, seed 0xdeadbeff)
  - hashsize = roundup_pow_of_two(256 * num_possible_cpus)
  - task_struct.mm offset

Symbol addresses are read from a kallsyms dump (no hard-coded offsets).
Requires: capstone (pip install capstone).

Usage:
  python3 disasm_futex.py --from-boot ../boot.img --kallsyms ../kallsyms.txt
  python3 disasm_futex.py --image kernel_Image --kallsyms ../kallsyms.txt --scan-hash
  python3 disasm_futex.py --from-boot ../boot.img --kallsyms ../kallsyms.txt --sym get_futex_key --len 0x3c0

License: GPLv3
"""
import sys, os, argparse

HERE = os.path.dirname(os.path.abspath(__file__))

# capstone is imported lazily inside main() so that --help works even when the
# optional disassembly dependency is not installed.
Cs = None
CS_ARCH_ARM64 = None
CS_MODE_LITTLE_ENDIAN = None


def import_capstone():
    """Import capstone, exiting with a clear message if it is missing."""
    global Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    try:
        from capstone import Cs as _Cs, CS_ARCH_ARM64 as _A, CS_MODE_LITTLE_ENDIAN as _M
    except ImportError:
        print("ERROR: the 'capstone' module is required for disassembly.", file=sys.stderr)
        print("       install it with:  pip install capstone", file=sys.stderr)
        print("       (see requirements.txt)", file=sys.stderr)
        sys.exit(2)
    Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN = _Cs, _A, _M


def load_kallsyms(path):
    if not os.path.isfile(path):
        print(f"ERROR: kallsyms dump not found: {path}", file=sys.stderr)
        sys.exit(2)
    tab = {}
    for line in open(path, "rb"):
        line = line.decode("latin-1").rstrip("\r\n")
        if not line or " " not in line:
            continue
        o, raw = line.split(" ", 1)
        name = raw[1:]            # strip the leading type char
        tab.setdefault(name, int(o, 16))
    return tab


def get_image(args):
    src = args.image or args.from_boot
    if not os.path.isfile(src):
        print(f"ERROR: image not found: {src}", file=sys.stderr)
        sys.exit(2)
    data = open(src, "rb").read()
    if args.from_boot:
        sys.path.insert(0, HERE)
        import extract_boot_image as ebi
        hdr = ebi.parse_boot_header(data)
        page = hdr["page_size"] or 4096
        kraw = data[page:page + hdr["kernel_size"]]
        start, _ = ebi.find_arm64_image(kraw)
        data = kraw[start:]
        print(f"[+] extracted kernel Image: {len(data)} bytes")
    return data


def main():
    ap = argparse.ArgumentParser(description="Disassemble target-kernel futex functions")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--image", help="raw ARM64 kernel Image")
    g.add_argument("--from-boot", help="Android boot.img to extract the kernel from")
    ap.add_argument("--kallsyms", default=os.path.join(HERE, "..", "kallsyms.txt"),
                    help="kallsyms dump for symbol addresses (default: ../kallsyms.txt)")
    ap.add_argument("--sym", help="disassemble a single symbol by name")
    ap.add_argument("--len", dest="length", default="0x80", help="bytes to disassemble (default 0x80)")
    ap.add_argument("--scan-hash", action="store_true",
                    help="scan the futex region for all inlined hash_futex seed sites (0xdeadbeff)")
    args = ap.parse_args()

    import_capstone()
    data = get_image(args)
    tab = load_kallsyms(args.kallsyms)
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True

    def disasm(start, length, label):
        print(f"\n=== {label} @ 0x{start:x} ===")
        if start + length > len(data):
            print("  (out of range)"); return
        for insn in md.disasm(data[start:start+length], start):
            print(f"  {insn.address:08x}: {insn.bytes.hex():<8} {insn.mnemonic:<8} {insn.op_str}")
            if insn.mnemonic == "ret":
                break

    if args.sym:
        if args.sym not in tab:
            print(f"ERROR: symbol '{args.sym}' not in kallsyms dump", file=sys.stderr)
            sys.exit(2)
        disasm(tab[args.sym], int(args.length, 0), args.sym)
        return

    # Default: reproduce the report's key evidence.
    for s, ln, note in [
        ("get_task_mm", 0x40, "confirms task_struct.mm offset (ldr [x0,#imm])"),
        ("get_futex_key", 0x60, "key stores: stp -> key+0=mm, key+8=address; str w,[key+0x10]=offset"),
        ("futex_init", 0x90, "hashsize = roundup_pow_of_two(256*cpus): lsl #8, clz, neg, lsl"),
    ]:
        if s in tab:
            print(f"\n##### {s}: {note}")
            disasm(tab[s], ln, s)
        else:
            print(f"\n##### {s}: NOT in kallsyms (skipped)")

    # futex_wake: show the inlined hash (seed + key loads)
    if "futex_wake" in tab:
        print("\n##### futex_wake: inlined hash_futex (seed 0xdeadbeff, loads key+0..+12)")
        disasm(tab["futex_wake"], 0xa0, "futex_wake")

    if args.scan_hash:
        print("\n##### scanning futex region for inlined hash_futex seed sites (0xdeadbeff)")
        lo = min(v for v in tab.values() if v > 0x100000)
        # bound the scan to the futex text region around do_futex..futex_init
        base = tab.get("do_futex", 0)
        region_start = base & ~0xfff
        region_end = region_start + 0x8000
        sites = []
        insns = list(md.disasm(data[region_start:region_end], region_start))
        for i, ins in enumerate(insns):
            if ins.mnemonic == "movk" and "0xdead" in ins.op_str and "lsl #16" in ins.op_str:
                reg = ins.op_str.split(",")[0].strip()
                for j in range(max(0, i-3), i):
                    if (insns[j].mnemonic == "mov" and insns[j].op_str.startswith(reg + ",")
                            and "0xbeff" in insns[j].op_str):
                        sites.append(ins.address); break
        print(f"  found {len(sites)} seed sites: " + " ".join(hex(a) for a in sites))
        print("  (each 0xdeadbeff = JHASH_INITVAL + (4<<2) => hash length 4 u32)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
