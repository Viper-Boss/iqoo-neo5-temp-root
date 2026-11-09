# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import json, random, re

conf = open(r'br\recovery\last_server_cJSON.conf','r',encoding='utf-8').read().strip()
param = open(r'br\request_param.txt','r').read().strip()
syms = sorted(set(conf) | set(param))

TRUE_HASH = b'<REDACTED_IMEI_HASH>'

def exact_derive(cipher, plain, byte_off):
    nbits = len(plain) * 8
    lo, hi = 8*byte_off, 8*byte_off + nbits
    out = {}
    for ci in range(lo // 6, (hi - 1) // 6 + 1):
        if ci >= len(cipher): break
        ch = cipher[ci]
        bits, known = [], True
        for k in range(6):
            gpos = 6*ci + k
            if lo <= gpos < hi:
                bi = gpos - lo
                bits.append((plain[bi // 8] >> (7 - bi % 8)) & 1)
            else:
                bits.append(None); known = False
        if known:
            v = 0
            for b in bits: v = (v << 1) | b
            if ch in out and out[ch] != v: return None
            out[ch] = v
    return out

# anchors: (string, plaintext, byte_offset)
anchors = []
for s, name, B in ((param,'param',119),(conf,'conf',341)):
    d = exact_derive(s, TRUE_HASH, B)
    assert d, f'anchor failed on {name}'
    anchors.append((name, B, d))
    print(f'{name} hash@{B}: {len(d)} exact symbols')

# also PD2055MA at B=22(param) B=242(conf) as found
for s, name, B in ((param,'param',22),(conf,'conf',242)):
    d = exact_derive(s, b'PD2055MA', B)
    if d: anchors.append((name, B, d)); print(f'{name} PD2055MA@{B}: {len(d)} syms')

locked = {}
ok = True
for name, B, d in anchors:
    for ch, v in d.items():
        if ch in locked and locked[ch] != v:
            print(f'LOCK CONFLICT {ch}'); ok = False
        if v in [x for c,x in locked.items() if c != ch]:
            # value taken by another symbol: longer anchor wins — just report
            print(f'value conflict: {ch} and {[c for c,x in locked.items() if x==x and x==v]}')
        locked[ch] = v
print('locked:', len(locked))

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

# sanity: hash region must decode exactly now
pt_check = decode(locked, conf[341*8//6 - 2: 341*8//6 + 86])
print('hash check decode:', pt_check)

STRONG = set(b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789=')
GOOD = STRONG | set(b'{}":,./&?_-+()\n ')
WORDS = [b'PD2055', b'http', b'vivo', b'.zip', b'size', b'md5', b'name', b'model', b'upgrade', b'url', b'files']

def score(m):
    pt = decode(m, conf); ptp = decode(m, param)
    if pt is None or ptp is None: return -1e9
    sc = 0
    for t in (pt, ptp):
        for b in t:
            if b in STRONG: sc += 2
            elif b in GOOD: sc += 1
            else: sc -= 4
        for wd in WORDS: sc += t.count(wd) * 100
        sc += sum(len(mm) for mm in re.findall(rb'[0-9a-f]{12,}', t)) * 4
    # exact hash bonus
    if pt is not None and TRUE_HASH in pt: sc += 5000
    if ptp is not None and TRUE_HASH in ptp: sc += 5000
    return sc

unlocked = [s for s in syms if s not in locked]
locked_vals = set(locked.values())
free_vals = [v for v in range(64) if v not in locked_vals]

random.seed(2024)
best = None
for trial in range(100):
    m = dict(locked)
    fv = list(free_vals); random.shuffle(fv)
    if len(fv) < len(unlocked):
        # some unlocked symbols share values with... impossible (bijection). skip
        continue
    for s, v in zip(unlocked, fv):
        m[s] = v
    cur = score(m)
    for it in range(10000):
        if random.random() < 0.6:
            s1, s2 = random.sample(unlocked, 2)
            v1, v2 = m[s1], m[s2]
            m[s1], m[s2] = v2, v1
            ns = score(m)
            if ns > cur: cur = ns
            else: m[s1], m[s2] = v1, v2
        else:
            s1 = random.choice(unlocked)
            # swap with a locked symbol? NO. reassign to an unused value? all free vals used.
            # swap with random other symbol incl locked-adjacent: swap s1 with any OTHER unlocked
            s2 = random.choice(unlocked)
            if s2 == s1: continue
            v1, v2 = m[s1], m[s2]
            m[s1], m[s2] = v2, v1
            ns = score(m)
            if ns > cur: cur = ns
            else: m[s1], m[s2] = v1, v2
    if best is None or cur > best[0]:
        best = (cur, dict(m))
        print(f'trial {trial}: {cur}')

sc, m = best
pt = decode(m, conf); ptp = decode(m, param)
print('\n=== FINAL (score', sc, ') ===')
print('\n--- CONF ---')
print(pt.decode('utf-8', errors='replace'))
print('\n--- PARAM ---')
print(ptp.decode('utf-8', errors='replace'))
open(r'br\conf_exact.txt','wb').write(pt)
open(r'br\param_exact.txt','wb').write(ptp)
json.dump(m, open(r'br\alphabet_exact.json','w'))
