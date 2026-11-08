import json, random, re

conf = open(r'Q:\Deepseek\_neo5\br\recovery\last_server_cJSON.conf','r',encoding='utf-8').read().strip()
param = open(r'Q:\Deepseek\_neo5\br\request_param.txt','r').read().strip()
syms = sorted(set(conf) | set(param))

def bitsof(b):
    return [(b >> i) & 1 for i in range(7, -1, -1)]

def anchor_candidates(cipher, plain_word):
    results = []
    W = len(plain_word)
    for B in range(0, len(cipher)*6//8 - W + 1):
        lo_bit, hi_bit = 8*B, 8*B + 8*W - 1
        c1 = hi_bit // 6
        if c1 >= len(cipher): break
        cons = {}
        ok = True
        for j, b in enumerate(plain_word):
            for k, bit in enumerate(bitsof(b)):
                gpos = 8*B + 8*j + k
                ci = gpos // 6
                bpos = gpos % 6
                ch = cipher[ci]
                cons.setdefault(ci, {})
                if cons[ci].get(bpos) is not None and cons[ci][bpos] != bit:
                    ok = False; break
                cons[ci][bpos] = bit
            if not ok: break
        if not ok: continue
        symsets = {}
        for ci, bits in cons.items():
            ch = cipher[ci]
            vals = set()
            for v in range(64):
                vb = [(v >> i) & 1 for i in range(5, -1, -1)]
                if all(vb[bp] == bit for bp, bit in bits.items()):
                    vals.add(v)
            if not vals: ok = False; break
            if ch in symsets:
                symsets[ch] &= vals
                if not symsets[ch]: ok = False; break
            else:
                symsets[ch] = vals
        if ok and symsets:
            results.append((B, symsets))
    return results

# STRONG anchors: only accept if EXACTLY ONE offset works in that string
strong_words = [b'<REDACTED_IMEI_HASH>',
                b'PD2055D_A_9.10.3', b'PD2055_A_9.10.3', b'PD2055MA',
                b'PD2055D_A_9.10.3.W10', b'9.10.3', b'1.0.3', b'CN-ZH', b'zh_CN',
                b'model', b'imei', b'hwVer', b'swVer', b'fullVer', b'version']

locked = {}
for w in strong_words:
    for s, sname in ((param,'param'),(conf,'conf')):
        res = anchor_candidates(s, w)
        full = [(B, ss) for B, ss in res if all(len(v)==1 for v in ss.values())]
        if len(full) == 1:
            B, ss = full[0]
            # merge with lock-check
            conflict = False
            for ch, vals in ss.items():
                v = next(iter(vals))
                if ch in locked and locked[ch] != v:
                    conflict = True
                    break
            if not conflict:
                for ch, vals in ss.items():
                    v = next(iter(vals))
                    # bijection check on locked values
                    if v in set(locked.values()) and ch not in locked:
                        # find who has it
                        other = [c for c, vv in locked.items() if vv == v]
                        # longer word wins: if current word longer, replace
                        pass
                    locked[ch] = v
                print(f'LOCK {sname}: {w[:24]!r} @B={B} (+{len(ss)} syms)')

print(f'\nlocked {len(locked)} symbols')

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

STRONG = set(b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789=')
GOOD = STRONG | set(b'{}":,./&?_-+()\n ')
WORDS = [b'PD2055', b'http', b'vivo', b'.zip', b'size', b'md5', b'name', b'model', b'upgrade', b'url']

def score(m):
    pt = decode(m, conf); ptp = decode(m, param)
    if pt is None or ptp is None: return -1e9
    sc = 0
    for t in (pt, ptp):
        for b in t:
            if b in STRONG: sc += 2
            elif b in GOOD: sc += 1
            else: sc -= 4
        for wd in WORDS: sc += t.count(wd) * 80
        sc += sum(len(mm) for mm in re.findall(rb'[0-9a-f]{10,}', t)) * 3
    return sc

unlocked = [s for s in syms if s not in locked]
best = None
random.seed(99)
for trial in range(80):
    m = dict(locked)
    used = set(m.values())
    ok = True
    for s in unlocked:
        cand = [v for v in range(64) if v not in used]
        if not cand: ok = False; break
        v = random.choice(cand); m[s] = v; used.add(v)
    if not ok: continue
    cur = score(m)
    for it in range(8000):
        s1 = random.choice(unlocked)
        # swap with any symbol (incl locked? no - swap with unlocked OR with an unused value)
        if random.random() < 0.5 and unlocked:
            s2 = random.choice(unlocked)
            v1, v2 = m[s1], m[s2]
            m[s1], m[s2] = v2, v1
        else:
            # reassign s1 to a currently-unused value
            used_now = set(m.values())
            free = [v for v in range(64) if v not in used_now]
            if not free: continue
            v1 = m[s1]; v2 = random.choice(free)
            m[s1] = v2
        ns = score(m)
        if ns > cur: cur = ns
        else:
            m[s1] = v1
            if 's2' in dir():
                m[s2] = v1 if m.get(s1) == v2 else v1
                m[s1], m[s2] = v2, v1 if False else (v1 if random.random()<0 else v1)
            # restore properly
            m[s1] = v1
            try: m[s2] = v2
            except Exception: pass
    if best is None or cur > best[0]:
        best = (cur, dict(m))
        print(f'trial {trial}: {cur}')

sc, m = best
pt = decode(m, conf); ptp = decode(m, param)
print('\n=== FINAL ===')
print('\n--- CONF ---')
print(pt.decode('utf-8', errors='replace'))
print('\n--- PARAM ---')
print(ptp.decode('utf-8', errors='replace'))
open(r'Q:\Deepseek\_neo5\br\conf_final.txt','wb').write(pt)
open(r'Q:\Deepseek\_neo5\br\param_final.txt','wb').write(ptp)
json.dump(m, open(r'Q:\Deepseek\_neo5\br\alphabet_final.json','w'))
