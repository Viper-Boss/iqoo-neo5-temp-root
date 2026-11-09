# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import sys
from collections import defaultdict

conf = open(r'br\recovery\last_server_cJSON.conf','r',encoding='utf-8').read().strip()
param = open(r'br\request_param.txt','r').read().strip()

def ok_byte(b):
    return 0x20 <= b <= 0x7e or b in (10,13,9)

# seed: derived from '{"data":"' chain (byte-by-byte verification)
seed = {'A':30,'D':50,'J':11,'2':52,'L':24,'5':23,'P':19,'u':49,'M':8,'y':35,'Y':34}
# note: these came from assuming '{"data":"X' — J->11 came from '{"d' (v2=11, v3=52)
# Actually chain: b0='{' b1='"' b2='d' b3='a' b4='t' b5='a' b6='"' b7=':' b8='"'
# A=30 D=50 | J=11(v2) 2=52(v3) | L=24(v4) 5=23(v5) | P=19(v6) u=49(v7) | M=8(v8) y=35(v9) | Y=34(v11) v10=40 -> symbol at pos10 = conf[10]='h' -> 40
seed['h'] = 40
# v12 (conf[12]='6') unknown, v13 (conf[13]='l') unknown

def bits_of(s, m):
    out = []
    for ch in s:
        v = m.get(ch)
        if v is None: return None
        out.append(v)
    return out

def decode_bytes(vals):
    out = []
    for i in range(0, len(vals)-3, 4):
        v0,v1,v2,v3 = vals[i:i+4]
        out.append((v0<<2)|(v1>>4))
        out.append(((v1&15)<<4)|(v2>>2))
        out.append(((v2&3)<<4)|v3)
    r = len(vals) % 4
    if r == 2:
        v0,v1 = vals[-2:]
        out.append((v0<<2)|(v1>>4))
    elif r == 3:
        v0,v1,v2 = vals[-3:]
        out.append((v0<<2)|(v1>>4))
        out.append(((v1&15)<<4)|(v2>>2))
    return out

# verify seed on known prefix
vals = bits_of(conf[:16], seed)
if vals is None or None in vals:
    print('seed incomplete on first 16')
else:
    bs = decode_bytes(vals)
    print('seed prefix decode:', bytes(bs))

# full constraint solver: DFS with propagation
# symbols
syms = sorted(set(conf) | set(param))
val_domain = {s: set(range(64)) for s in syms}
for s in seed:
    if s in val_domain: val_domain[s] = {seed[s]}

groups = []
for s, name in ((conf,'c'),(param,'p')):
    for i in range(0, len(s)-3, 4):
        groups.append((s[i:i+4], name, i))

# ASCII constraint per byte:
# b0 = (v0<<2)|(v1>>4) printable
# b1 = ((v1&15)<<4)|(v2>>2) printable
# b2 = ((v2&3)<<4)|v3 printable
# For unknown symbols, prune: value v for symbol s must not violate any constraint where s appears.

def prune_once(domains, group_list):
    changed = False
    for g, name, off in group_list:
        sy = [g[0],g[1],g[2],g[3]]
        # for each byte constraint, compute possible value combos
        # b0: v0 in dom0, v1 in dom1 -> b0 printable
        # prune v0: exists v1 s.t. printable?
        for pos in range(4):
            s = sy[pos]
            if len(domains[s]) <= 1: continue
            newdom = set()
            for v in domains[s]:
                ok = False
                # test with all combos of other symbols (bounded: if others big, sample)
                others = [list(domains[o]) if o != s else [v] for o in sy]
                # cap combos
                total = 1
                for l in others: total *= len(l)
                if total > 200000:
                    # too big: only check local constraint participation
                    ok = True  # can't prune, skip
                else:
                    for v0 in others[0]:
                        for v1 in others[1]:
                            for v2 in others[2]:
                                for v3 in others[3]:
                                    b0 = (v0<<2)|(v1>>4)
                                    b1 = ((v1&15)<<4)|(v2>>2)
                                    b2 = ((v2&3)<<4)|v3
                                    if ok_byte(b0) and ok_byte(b1) and ok_byte(b2):
                                        ok = True; break
                                if ok: break
                            if ok: break
                        if ok: break
                if ok: newdom.add(v)
            if newdom != domains[s]:
                domains[s] = newdom
                changed = True
                if not newdom:
                    return changed, False  # wipeout
    return changed, True

print('pruning...')
ok = True
for it in range(30):
    changed, ok = prune_once(val_domain, groups)
    if not ok:
        print('WIPEOUT at iter', it); sys.exit(1)
    if not changed: break
print('pruned domains:')
for s in syms:
    d = val_domain[s]
    print(f"  '{s}': {sorted(d)}", '<<seed' if len(d)==1 else '')

# after pruning: count search space
import math
total = 1
for s in syms:
    total *= len(val_domain[s])
print('search space ~ 2^%.1f' % math.log2(total) if total else 'EMPTY')

# now greedy DFS over remaining ambiguity using frequency prior + English scoring
def decode_with(domains_map, s):
    vals = []
    for ch in s:
        v = domains_map.get(ch)
        if v is None: return None
        vals.append(v)
    return bytes(decode_bytes(vals))

GOOD = set(b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}[]":,./&=?_-+() \n')
WORDS = [b'http',b'vivo',b'.zip',b'PD2055',b'url',b'size',b'md5',b'name',b'ver',b'model',b'time',b'sign']

import random
best = None
for trial in range(300):
    m = dict(seed)
    used = set(seed.values())
    # random consistent completion
    order = sorted([s for s in syms if s not in seed], key=lambda s: len(val_domain[s]))
    success = True
    for s in order:
        cand = [v for v in val_domain[s] if v not in used]
        if not cand: success = False; break
        v = random.choice(cand)
        m[s] = v; used.add(v)
    if not success: continue
    pt = decode_with(m, conf)
    ptp = decode_with(m, param)
    sc = 0
    if pt:
        sc += sum(1 for b in pt if b in GOOD)
        for w in WORDS: sc += pt.count(w)*50
    if ptp:
        sc += sum(1 for b in ptp if b in GOOD)
        for w in WORDS: sc += ptp.count(w)*50
    # hill climb: swap pairs
    improved = True
    while improved:
        improved = False
        s1, s2 = random.sample(list(m.keys()), 2)
        v1, v2 = m[s1], m[s2]
        if v2 not in val_domain[s1] or v1 not in val_domain[s2]: continue
        m[s1], m[s2] = v2, v1
        pt = decode_with(m, conf); ptp = decode_with(m, param)
        nsc = 0
        if pt:
            nsc += sum(1 for b in pt if b in GOOD)
            for w in WORDS: nsc += pt.count(w)*50
        if ptp:
            nsc += sum(1 for b in ptp if b in GOOD)
            for w in WORDS: nsc += ptp.count(w)*50
        if nsc > sc: sc = nsc; improved = True
        else: m[s1], m[s2] = v1, v2
    if best is None or sc > best[0]:
        best = (sc, dict(m))
        print(f'trial {trial}: score {sc}')

sc, m = best
pt = decode_with(m, conf)
ptp = decode_with(m, param)
print('\n=== BEST', sc, '===')
print('conf:', pt[:300])
print('param:', (ptp or b'')[:300])
open(r'br\conf_plaintext.txt','wb').write(pt)
if ptp: open(r'br\param_plaintext.txt','wb').write(ptp)
