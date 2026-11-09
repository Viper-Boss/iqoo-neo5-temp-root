# NOTE(privacy): device identifiers (IMEI hash / emmcid) that were embedded in
# this historical script have been REDACTED (<REDACTED_*> placeholders). The
# script is kept as a methodology record; re-running it requires re-supplying
# your own device's known-plaintext anchors. See SECURITY.md.
import sys

conf = open(r'samples/recovery/last_server_cJSON.conf','r',encoding='utf-8').read().strip()
param = open(r'samples/request_param.txt','r').read().strip()

def bitsof(b):
    return [(b >> i) & 1 for i in range(7, -1, -1)]

def anchor_candidates(cipher, plain_word):
    """Try plain_word at every byte offset. Returns list of (offset, {symbol: set(values)})."""
    results = []
    W = len(plain_word)
    nbits = 8 * W
    for B in range(0, len(cipher)*6//8 - W + 1):
        # bit range [8B, 8B+nbits)
        lo_bit = 8 * B
        hi_bit = 8 * B + nbits - 1
        c0 = lo_bit // 6
        c1 = hi_bit // 6
        if c1 >= len(cipher): break
        # constraints per char
        cons = {}  # char index -> {bitpos_in_value: bit}
        ok = True
        for j, b in enumerate(plain_word):
            for k, bit in enumerate(bitsof(b)):
                gpos = 8*B + 8*j + k
                ci = gpos // 6
                bpos = gpos % 6  # bit position in 6-bit value, MSB-first (vb[0]=MSB)
                ch = cipher[ci]
                cons.setdefault(ci, {})
                if cons[ci].get(bpos) is not None and cons[ci][bpos] != bit:
                    ok = False; break
                cons[ci][bpos] = bit
            if not ok: break
        if not ok: continue
        # build value sets
        symsets = {}
        for ci, bits in cons.items():
            ch = cipher[ci]
            vals = set()
            for v in range(64):
                vb = [(v >> i) & 1 for i in range(5, -1, -1)]
                match = True
                for bpos, bit in bits.items():
                    if vb[bpos] != bit: match = False; break
                if match: vals.add(v)
            if not vals: ok = False; break
            # merge if symbol repeats
            if ch in symsets:
                inter = symsets[ch] & vals
                if not inter: ok = False; break
                symsets[ch] = inter
            else:
                symsets[ch] = vals
        if ok and symsets:
            results.append((B, symsets, c0, c1))
    return results

def merge_anchor(m, inv, symsets):
    """Merge anchor into current map. Returns True on success."""
    for ch, vals in symsets.items():
        if len(vals) != 1:
            return False  # only accept fully determined
        v = next(iter(vals))
        if ch in m:
            if m[ch] != v: return False
        else:
            if v in inv: return False
            m[ch] = v; inv[v] = ch
    return True

words_param = [b'PD2055', b'PD2055D_A_9.10.3', b'PD2055_A_9.10.3', b'PD2055MA',
               b'<REDACTED_IMEI_HASH>',
               b'model=', b'imei=', b'hwVer', b'swVer', b'CN-ZH', b'zh_CN', b'WIFI', b'1.0.3']
words_conf = [b'https://', b'http://', b'PD2055', b'.zip', b'vivo', b'sysupgrade', b'sysupdxdl',
              b'upgrade', b'/oem/files/', b'.com.cn', b'{"', b'size', b'md5', b'name', b'url',
              b'sign', b'time', b'ver']

print('=== anchor scan on PARAM ===')
param_anchors = []
for w in words_param:
    res = anchor_candidates(param, w)
    fully = [(B, ss) for B, ss, c0, c1 in res if all(len(v)==1 for v in ss.values())]
    print(f'{w[:20]!r}: {len(res)} possible offsets, {len(fully)} fully-determined')
    for B, ss in fully[:4]:
        print(f'   B={B}: {dict((k,next(iter(v))) for k,v in ss.items())}')
    param_anchors.extend((w, B, ss) for B, ss in fully)

print('\n=== anchor scan on CONF ===')
conf_anchors = []
for w in words_conf:
    res = anchor_candidates(conf, w)
    fully = [(B, ss) for B, ss, c0, c1 in res if all(len(v)==1 for v in ss.values())]
    print(f'{w[:20]!r}: {len(res)} possible offsets, {len(fully)} fully-determined')
    conf_anchors.extend((w, B, ss) for B, ss in fully)

# try to merge anchors greedily (most symbols first)
all_anchors = sorted(param_anchors + conf_anchors, key=lambda x: -len(x[2]))
m, inv = {}, {}
merged = []
for w, B, ss in all_anchors:
    mm = dict(m); ii = dict(inv)
    if merge_anchor(mm, ii, ss):
        m, inv = mm, ii
        merged.append((w, B, len(ss)))
print(f'\nmerged {len(merged)} anchors, {len(m)} symbols determined:')
print(m)
