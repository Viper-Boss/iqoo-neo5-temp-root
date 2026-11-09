#!/usr/bin/env python3
"""
privacy_scan.py — Scan the working tree for accidentally committed personal or
secret data.

This is a heuristic scanner, not a guarantee. It is used by CI and by
contributors before committing. It only reads files; it never modifies them.

Design note: this file deliberately contains NO literal device identifiers.
Device-specific leakage is detected *structurally* (any non-redacted value in
an identifier field), so the scanner itself cannot leak what it protects.

Checks:
  1. Identifier fields carrying real values (imei / emmcid / serial / android_id)
     where the value is not all-zeros or <REDACTED_*>
  2. Generic credential patterns (private keys, GitHub/AWS tokens, JWTs)
  3. Cookie / Authorization header values
  4. Developer absolute paths (Windows drive user paths, /home/<user>/, Q:\\...)
  5. E-mail addresses (report only; may be legitimate attribution)

Exit code: 0 = clean, 1 = findings that must be fixed.

Usage:
  python3 tests/privacy_scan.py
  python3 tests/privacy_scan.py --root .
License: GPLv3
"""
import sys, os, re, argparse

HEX = r"[0-9a-fA-F]"
_BS = chr(92)          # backslash, built at runtime so this file never contains
                       # the literal developer paths it is looking for.
_SEP = re.escape(_BS * 2)  # matches a doubled backslash (escaped form in text)

# (label, compiled regex, group index holding the value)
IDENTIFIER_FIELDS = [
    ("IMEI hash field",   re.compile(r"up\.imei=(%s{40,80})" % HEX), 1),
    ("IMEI request field", re.compile(r"[&?]imei=(%s{40,80})" % HEX), 1),
    ("emmcid field",      re.compile(r"up\.emmcid=(%s{32,80})" % HEX), 1),
    ("emmcid request field", re.compile(r"[&?]emmcid=(%s{32,80})" % HEX), 1),
    ("serial field",      re.compile(r"(?:serial|serialno|sn)=([A-Za-z0-9]{10,32})", re.I), 1),
    ("android_id field",  re.compile(r"android_id=([A-Za-z0-9]{8,32})", re.I), 1),
]

HARD_BLOCK = [
    ("GitHub token",       re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}")),
    ("AWS access key",     re.compile(r"AKIA[0-9A-Z]{16}")),
    ("private key block",  re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("JWT",                re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("cookie/authorization header",
     re.compile(r"(?:Cookie|Authorization)\s*[:=]\s*\S{20,}", re.I)),
    ("developer Windows user path",
     re.compile(r"[A-Za-z]:" + _SEP + "Users" + _SEP + r"[^\\\s\"']+")),
    ("developer home path",          re.compile(r"/home/[a-z_][a-z0-9_-]{2,}/")),
    ("developer research path",      re.compile(r"Q:" + _SEP + "Deepseek")),
]

SOFT_REPORT = [
    ("e-mail address", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
]

SKIP_DIRS = {".git", "__pycache__", "node_modules", "build", ".venv", "venv"}
SKIP_EXT = {".img", ".elf", ".zip", ".png", ".jpg", ".jpeg", ".so", ".bin", ".gz", ".xz"}
SKIP_FILES = {"requirements.txt"}   # intentionally lists package names
MAX_BYTES = 4 * 1024 * 1024

# Values that are explicitly placeholders, not real identifiers.
PLACEHOLDER_RE = re.compile(r"^(?:0+|REDACTED|<.*)$", re.I)


def iter_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if os.path.splitext(fn)[1].lower() in SKIP_EXT:
                continue
            if fn in SKIP_FILES:
                continue
            p = os.path.join(dirpath, fn)
            try:
                if os.path.getsize(p) > MAX_BYTES:
                    continue
            except OSError:
                continue
            yield p


def classify_identifier_or_placeholder(value):
    """True if the identifier value is a placeholder (all zeros / REDACTED)."""
    v = value.strip().strip("\"'&,;")
    if PLACEHOLDER_RE.match(v):
        return True
    if set(v) == {"0"}:
        return True
    return False


def main():
    ap = argparse.ArgumentParser(description="Heuristic privacy/secret scan")
    ap.add_argument("--root",
                    default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    help="directory to scan (default: repo root)")
    args = ap.parse_args()
    root = os.path.abspath(args.root)

    hard_hits, soft_hits = [], []
    scanned = 0
    for path in iter_files(root):
        scanned += 1
        try:
            text = open(path, "r", encoding="utf-8", errors="ignore").read()
        except OSError:
            continue
        rel = os.path.relpath(path, root)

        for label, rx, grp in IDENTIFIER_FIELDS:
            for m in rx.finditer(text):
                if not classify_identifier_or_placeholder(m.group(grp)):
                    line = text.count("\n", 0, m.start()) + 1
                    hard_hits.append((rel, line, label))
        for label, rx in HARD_BLOCK:
            for m in rx.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                hard_hits.append((rel, line, label))
        for label, rx in SOFT_REPORT:
            for m in rx.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                soft_hits.append((rel, line, label))

    print(f"[*] scanned {scanned} files under {root}")

    # Self-check: this scanner must not embed real identifiers either.
    if hard_hits:
        print(f"\n[!] {len(hard_hits)} HARD finding(s) - must be fixed before publishing:")
        seen = {}
        for rel, line, label in hard_hits:
            seen.setdefault((rel, label), []).append(line)
        for (rel, label), lines in sorted(seen.items()):
            shown = ", ".join(str(x) for x in lines[:5])
            more = "" if len(lines) <= 5 else f" (+{len(lines)-5} more lines)"
            print(f"    {rel}: {label} at line(s) {shown}{more}")
    else:
        print("[+] no hard-blocked privacy/secret patterns found")

    if soft_hits:
        print(f"\n[i] {len(soft_hits)} report-only finding(s) (review; may be legitimate):")
        seen = {}
        for rel, line, label in soft_hits:
            seen.setdefault((rel, label), []).append(line)
        for (rel, label), lines in sorted(seen.items()):
            print(f"    {rel}: {label} at line {lines[0]}" + (f" (+{len(lines)-1})" if len(lines) > 1 else ""))

    return 1 if hard_hits else 0


if __name__ == "__main__":
    sys.exit(main())
