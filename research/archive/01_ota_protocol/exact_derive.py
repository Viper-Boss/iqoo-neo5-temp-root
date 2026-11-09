# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import json

conf = open(r'br\recovery\last_server_cJSON.conf','r',encoding='utf-8').read().strip()
param = open(r'br\request_param.txt','r').read().strip()

m = json.load(open(r'br\alphabet_final.json'))

TRUE_HASH = b'<REDACTED_IMEI_HASH>'

def exact_derive(cipher, plain, byte_off):
    """Derive exact symbol values from known plaintext at byte offset.
    Returns {char: value} for chars fully covered."""
    nbits = len(plain) * 8
    lo = 8 * byte_off
    hi = lo + nbits  # exclusive
    out = {}
    for ci in range(lo // 6, (hi - 1) // 6 + 1):
        if ci >= len(cipher): break
        ch = cipher[ci]
        # bits of this char: global positions 6*ci .. 6*ci+6
        bits = []
        known = True
        for k in range(6):
            gpos = 6 * ci + k
            if lo <= gpos < hi:
                # bit index within plain
                bi = gpos - lo
                byte_i = bi // 8
                bit_i = 7 - (bi % 8)
                bits.append((plain[byte_i] >> bit_i) & 1)
            else:
                bits.append(None)
                known = False
        if known:
            v = 0
            for b in bits: v = (v << 1) | b
            if ch in out and out[ch] != v:
                return None  # conflict
            out[ch] = v
    return out

def find_hash_offset(cipher, plain, m):
    """Find the byte offset where plain occurs, using current map to score."""
    best = None
    for B in range(0, len(cipher)*6//8 - len(plain) + 1):
        # check consistency: decode region with current map, count matches
        match = 0
        ok = True
        derived = exact_derive(cipher, plain, B)
        if derived is None: continue
        # candidate must not conflict with locked/known map
        bad = 0
        for ch, v in derived.items():
            if ch in m and m[ch] != v:
                bad += 1
        if bad > 6: continue  # allow few wrong prior values
        if best is None or bad < best[1]:
            best = (B, bad, derived)
    return best

total_fixed = {}
for s, name in ((param,'param'),(conf,'conf')):
    res = find_hash_offset(s, TRUE_HASH, m)
    if res:
        B, bad, derived = res
        print(f'{name}: hash at B={B} (prior-map mismatches: {bad}), derived {len(derived)} exact symbols')
        for ch, v in derived.items():
            if ch in total_fixed and total_fixed[ch] != v:
                print(f'  CONFLICT {ch}: {total_fixed[ch]} vs {v}')
            total_fixed[ch] = v

# Also exact-derive from other known strings at their locked offsets
KNOWN = [
    (param, b'PD2055D_A_9.10.3'), (conf, b'PD2055D_A_9.10.3'),
    (param, b'PD2055MA'), (conf, b'PD2055MA'),
]
# find offsets by trying all and requiring high consistency with total_fixed
for s, plain in KNOWN:
    best = None
    for B in range(0, len(s)*6//8 - len(plain) + 1):
        d = exact_derive(s, plain, B)
        if d is None: continue
        bad = sum(1 for ch, v in d.items() if ch in total_fixed and total_fixed[ch] != v)
        if best is None or bad < best[1]:
            best = (B, bad, d)
    if best and best[1] <= 2:
        B, bad, d = best
        print(f'{plain[:16]!r}: B={B} bad={bad} +{len(d)} syms')
        for ch, v in d.items():
            if ch in total_fixed and total_fixed[ch] != v:
                print(f'  conflict {ch}')
            else:
                total_fixed[ch] = v

print(f'\ntotal exact-fixed: {len(total_fixed)} symbols')

# merge into map: fixed values override
m2 = dict(m)
for ch, v in total_fixed.items():
    m2[ch] = v
# fix bijection: ensure distinct
inv = {}
for ch, v in sorted(m2.items()):
    if v in inv:
        print(f'dup value {v}: {inv[v]} and {ch}')
    inv[v] = ch

def decode(m, s):
    try:
        vals = [m[ch] for ch in s]
    except KeyError:
        return None
    out = []
    for g in range(0, len(vals)-3, 4):
        v0,v1,v2,v3 = vals[g:g+4]
        out.append((v0<<2)|(v1>>4)); out.append(((v1&15)<<4)|(v2>>2)); out.append(((v2&3)<<4)|v3)
    r = len(vals)%4
    if r == 2: out.append((vals[-2]<<2)|(vals[-1]>>4))
    elif r == 3:
        out.append((vals[-3]<<2)|(vals[-2]>>4)); out.append(((vals[-2]&15)<<4)|(vals[-1]>>2))
    return bytes(out)

pt = decode(m2, conf); ptp = decode(m2, param)
print('\n===== CONF =====')
print(pt.decode('utf-8', errors='replace'))
print('\n===== PARAM =====')
print(ptp.decode('utf-8', errors='replace'))
open(r'br\conf_exact.txt','wb').write(pt)
open(r'br\param_exact.txt','wb').write(ptp)
json.dump(m2, open(r'br\alphabet_exact.json','w'))
