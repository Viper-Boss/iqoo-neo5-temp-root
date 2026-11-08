#!/usr/bin/env python3
"""
parse_kallsyms.py — Parse the kallsyms symbol table from a raw ARM64 kernel
Image using a verified layout, and RE-VERIFY it at runtime against the kernel's
own kallsyms_markers.

The structure offsets live in kallsyms_layout.json (default: next to this
script). They were discovered by the find_*/scan_* scripts for the
PD2055_A_9.10.3 image, but NOTHING is trusted blindly: this script re-derives
every symbol name and checks that all markers satisfy
    markers[k] == (byte offset of name[256*k]) - names_start
If any marker mismatches, it exits non-zero and writes nothing.

Inputs are read-only; the symbol dump is only written when -o is given, and the
script refuses to overwrite the input image.

Usage:
  python3 parse_kallsyms.py KERNEL_IMAGE [-o out.txt] [--layout kallsyms_layout.json]
  python3 parse_kallsyms.py ../boot.img --from-boot -o ../kallsyms.txt

License: GPLv3
"""
import sys, os, struct, argparse, json

HERE = os.path.dirname(os.path.abspath(__file__))


def load_layout(path):
    if not os.path.isfile(path):
        raise FileNotFoundError(f"layout file not found: {path}")
    lay = json.load(open(path))
    out = {}
    for k, v in lay.items():
        if k.startswith("_"):
            continue
        out[k] = int(v, 16) if isinstance(v, str) and v.startswith("0x") else v
    return out


def parse(d, lay):
    tt = lay["token_table"]
    toks = []
    p = tt
    for _ in range(256):
        e = d.find(b"\x00", p)
        if e < 0:
            raise ValueError("token table truncated")
        toks.append(d[p:e]); p = e + 1

    ns, ne = lay["names_start"], lay["names_end"]
    pos = ns
    names, positions = [], []
    while pos < ne:
        ln = d[pos]
        if ln == 0:
            break
        if pos + 1 + ln > ne:
            break
        names.append(b"".join(toks[t] for t in d[pos+1:pos+1+ln]))
        positions.append(pos)
        pos += 1 + ln

    num = lay["num_syms"]
    if len(names) != num:
        raise ValueError(f"name count {len(names)} != num_syms {num}")

    # marker cross-check
    mo, mc, ms = lay["markers"], lay["markers_count"], lay["markers_stride"]
    mk_ok = 0
    for k in range(mc):
        idx = 256 * k
        if idx >= len(positions):
            break
        if struct.unpack_from("<I", d, mo + ms*k)[0] == positions[idx] - ns:
            mk_ok += 1

    os_ = lay["offsets_start"]
    offs = list(struct.unpack_from("<%di" % num, d, os_))
    viol = sum(1 for i in range(num-1) if offs[i] > offs[i+1])

    return names, offs, mk_ok, mc, viol, pos


def main():
    ap = argparse.ArgumentParser(description="Parse + verify kallsyms from a kernel Image")
    ap.add_argument("image", help="raw ARM64 kernel Image, or boot.img with --from-boot")
    ap.add_argument("--from-boot", action="store_true",
                    help="treat IMAGE as an Android boot.img and extract the kernel first")
    ap.add_argument("--layout", default=os.path.join(HERE, "kallsyms_layout.json"),
                    help="kallsyms layout JSON (default: scripts/kallsyms_layout.json)")
    ap.add_argument("-o", "--output", help="write '<offset> <type><name>' dump here")
    args = ap.parse_args()

    if not os.path.isfile(args.image):
        print(f"ERROR: image not found: {args.image}", file=sys.stderr)
        return 2
    try:
        lay = load_layout(args.layout)
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    data = open(args.image, "rb").read()
    if args.from_boot:
        # reuse extract_boot_image logic
        sys.path.insert(0, HERE)
        try:
            import extract_boot_image as ebi
            hdr = ebi.parse_boot_header(data)
            page = hdr["page_size"] or 4096
            kraw = data[page:page + hdr["kernel_size"]]
            start, _ = ebi.find_arm64_image(kraw)
            data = kraw[start:]
            print(f"[+] extracted kernel Image from boot.img ({len(data)} bytes)")
        except Exception as e:
            print(f"ERROR: boot extraction failed: {e}", file=sys.stderr)
            return 2

    try:
        names, offs, mk_ok, mc, viol, endp = parse(data, lay)
    except (ValueError, struct.error) as e:
        print(f"ERROR: parse failed: {e}", file=sys.stderr)
        return 2

    print(f"[+] num_syms           : {len(names)}")
    print(f"[+] names parsed end   : 0x{endp:x} (layout names_end=0x{lay['names_end']:x})")
    print(f"[+] markers verified   : {mk_ok}/{mc}")
    print(f"[+] offsets monotonic  : {viol} violations")
    print(f"[+] offsets[0] / [-1]  : {offs[0]:#x} / {offs[-1]:#x}")

    if mk_ok != mc:
        print(f"ERROR: marker cross-check FAILED ({mk_ok}/{mc}) — layout does not "
              f"match this image; refusing to emit a possibly-wrong table.", file=sys.stderr)
        return 2
    if viol != 0:
        print(f"ERROR: offsets not monotonic ({viol} violations)", file=sys.stderr)
        return 2

    if args.output:
        if os.path.abspath(args.output) == os.path.abspath(args.image):
            print("ERROR: refusing to overwrite the input image", file=sys.stderr)
            return 2
        with open(args.output, "w") as f:
            for o, nm in zip(offs, names):
                f.write(f"{o:08x} {nm.decode('latin-1')}\n")
        print(f"[+] wrote {args.output} ({len(names)} symbols)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
