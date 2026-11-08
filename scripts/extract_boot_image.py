#!/usr/bin/env python3
"""
extract_boot_image.py — Parse an Android boot image (v0/v1/v2) and extract the
raw ARM64 kernel Image, handling vivo's proprietary pre-Image wrapper.

This is a clean, reproducible re-implementation. It takes the boot.img path as
a CLI argument (no hard-coded absolute paths) and writes the extracted kernel
Image to an output path (default: alongside the input, never overwriting the
input).

Method (no offset guessing):
  1. Parse the boot_img_hdr (magic, kernel_size, page_size, header_version).
  2. kernel_raw = data[page_size : page_size + kernel_size].
  3. Locate the ARM64 Image header by its magic "ARM\\x64" (u32 0x644d5241),
     which the arm64 boot protocol places at Image offset 0x38 (56).
  4. real Image start = magic_pos - 0x38. Everything before it inside
     kernel_raw is the vendor wrapper (vivo uses a small proprietary header).
  5. kernel_Image = kernel_raw[image_start:].

Usage:
    python3 extract_boot_image.py BOOT_IMG [-o OUTPUT] [--report]

Exit codes: 0 ok, 2 bad input/parse error.
License: GPLv3
"""
import sys, os, struct, argparse

ARM64_MAGIC = 0x644d5241  # "ARM\x64" little-endian, at Image offset 0x38


def parse_boot_header(data: bytes):
    if data[:8] != b"ANDROID!":
        raise ValueError(f"bad boot magic: {data[:8]!r} (expected b'ANDROID!')")
    (kernel_size, kernel_addr, ramdisk_size, ramdisk_addr,
     second_size, second_addr, tags_addr, page_size,
     header_version, os_version) = struct.unpack_from("<10I", data, 8)
    name = data[0x30:0x40].split(b"\0")[0].decode("latin-1")
    cmdline = data[0x40:0x240].split(b"\0")[0].decode("latin-1")
    hdr = {
        "kernel_size": kernel_size, "kernel_addr": kernel_addr,
        "ramdisk_size": ramdisk_size, "page_size": page_size,
        "header_version": header_version, "os_version": os_version,
        "name": name, "cmdline": cmdline,
    }
    if header_version >= 2:
        dtb_size, = struct.unpack_from("<I", data, 0x670)
        hdr["dtb_size"] = dtb_size
    return hdr


def find_arm64_image(kernel_raw: bytes):
    """Return (image_start, magic_pos) by scanning for the ARM64 header magic."""
    # The magic lives at Image offset 0x38; scan a bounded window for it.
    pos = kernel_raw.find(struct.pack("<I", ARM64_MAGIC))
    if pos < 0:
        raise ValueError("ARM64 Image magic 'ARM\\x64' not found in kernel blob")
    if pos < 0x38:
        raise ValueError(f"magic at {pos:#x} too early to be a real Image header")
    return pos - 0x38, pos


def main():
    ap = argparse.ArgumentParser(description="Extract ARM64 kernel Image from an Android boot.img")
    ap.add_argument("boot_img", help="path to boot.img")
    ap.add_argument("-o", "--output", help="output kernel Image path (default: <boot_img>.kernel)")
    ap.add_argument("--report", action="store_true", help="print a detailed header/verification report")
    args = ap.parse_args()

    if not os.path.isfile(args.boot_img):
        print(f"ERROR: input not found: {args.boot_img}", file=sys.stderr)
        return 2

    with open(args.boot_img, "rb") as f:
        data = f.read()

    try:
        hdr = parse_boot_header(data)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    page = hdr["page_size"] or 4096
    ksize = hdr["kernel_size"]
    if page + ksize > len(data):
        print(f"ERROR: kernel_size {ksize} exceeds file (page={page}, len={len(data)})", file=sys.stderr)
        return 2
    kernel_raw = data[page:page + ksize]

    try:
        image_start, magic_pos = find_arm64_image(kernel_raw)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    kernel_image = kernel_raw[image_start:]
    out = args.output or (args.boot_img + ".kernel")
    if os.path.abspath(out) == os.path.abspath(args.boot_img):
        print("ERROR: refusing to overwrite the input boot.img", file=sys.stderr)
        return 2
    with open(out, "wb") as f:
        f.write(kernel_image)

    # ARM64 Image header fields (at Image offset 0)
    code0, code1 = struct.unpack_from("<II", kernel_image, 0)
    text_offset, image_size, flags = struct.unpack_from("<QQQ", kernel_image, 8)

    print(f"[+] wrote {out} ({len(kernel_image)} bytes)")
    print(f"    boot magic       : ANDROID!")
    print(f"    header_version   : {hdr['header_version']}")
    print(f"    page_size        : {page}")
    print(f"    kernel_size      : {ksize}")
    print(f"    vendor wrapper   : {image_start} bytes before ARM64 Image (magic@{magic_pos:#x})")
    print(f"    ARM64 code0/1    : {code0:#010x} {code1:#010x}")
    print(f"    text_offset      : {text_offset:#x}  (0 => zeroed by vendor anti-RE)")
    print(f"    image_size field : {image_size:#x}")
    print(f"    flags field      : {flags:#x}")
    print(f"    name             : {hdr['name']!r}")
    if args.report:
        print(f"    cmdline          : {hdr['cmdline'][:120]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
