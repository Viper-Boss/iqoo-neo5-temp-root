#!/usr/bin/env python3
"""
check_docs.py — Verify that every relative link/path referenced by the
project's Markdown files exists.

This catches the most common documentation rot after a directory move.
It only reads files; it never modifies them.

Usage:
  python3 tests/check_docs.py
  python3 tests/check_docs.py --root .
License: GPLv3
"""
import sys, os, re, argparse

# [text](path)  or  [text](path#anchor); ignore http(s)://, mailto:, anchors.
LINK_RE = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
SKIP_DIRS = {".git", "node_modules", "__pycache__", "build", ".venv", "venv"}
# Placeholders that are not real paths.
IGNORE_PREFIX = ("http://", "https://", "mailto:", "#", "<")


def collect_md(root):
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if fn.lower().endswith(".md"):
                out.append(os.path.join(dirpath, fn))
    return out


def strip_anchor(target):
    # keep the path part before #fragment and drop ?query
    return target.split("#", 1)[0].split("?", 1)[0]


def main():
    ap = argparse.ArgumentParser(description="Check relative Markdown links exist")
    ap.add_argument("--root", default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    help="directory to scan (default: repo root)")
    args = ap.parse_args()
    root = os.path.abspath(args.root)

    md_files = collect_md(root)
    missing, checked = [], 0
    for md in md_files:
        try:
            text = open(md, "r", encoding="utf-8", errors="ignore").read()
        except OSError:
            continue
        base = os.path.dirname(md)
        for m in LINK_RE.finditer(text):
            target = m.group(1).strip()
            if target.startswith(IGNORE_PREFIX) or not target:
                continue
            path = strip_anchor(target)
            if not path:
                continue
            # URLs with scheme we already skipped; handle absolute /path (skip)
            if path.startswith("/"):
                continue
            resolved = os.path.normpath(os.path.join(base, path))
            checked += 1
            if not os.path.exists(resolved):
                line = text.count("\n", 0, m.start()) + 1
                missing.append((os.path.relpath(md, root), line, target))

    print(f"[*] {len(md_files)} markdown files, {checked} relative links checked")
    if missing:
        print(f"\n[!] {len(missing)} broken relative link(s):")
        for rel, line, target in missing:
            print(f"    {rel}:{line} -> {target}")
        return 1
    print("[+] all relative markdown links resolve")
    return 0


if __name__ == "__main__":
    sys.exit(main())
