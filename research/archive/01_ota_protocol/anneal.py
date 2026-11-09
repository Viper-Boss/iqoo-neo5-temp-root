# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import random, math

conf = open(r'br\recovery\last_server_cJSON.conf','r',encoding='utf-8').read().strip()
param = open(r'br\request_param.txt','r').read().strip()

# collect class constraints
syms = sorted(set(conf) | set(param))
cls = {s: set() for s in syms}
for s in (conf + param):
    pass
for i, ch in enumerate(conf):
    cls[ch].add(i % 4)
for i, ch in enumerate(param):
    cls[ch].add(i % 4)

# allowed value ranges per class combos
def allowed(s):
    c = cls[s]
    lo, hi = 0, 63
    if 0 in c: hi = min(hi, 31)
    if 1 in c: hi = min(hi, 55)
    if 2 in c: hi = min(hi, 61)
    return lo, hi

domains = {s: list(range(allowed(s)[0], allowed(s)[1]+1)) for s in syms}
for s in syms:
    if not domains[s]:
        print('EMPTY DOMAIN', s); raise SystemExit

# bit decode helper: values of chars -> bytes
def decode(s, m):
    bits = []
    for ch in s:
        v = m.get(ch)
        if v is None: return None
        bits.extend([(v>>5)&1,(v>>4)&1,(v>>3)&1,(v>>2)&1,(v>>1)&1,v&1])
    out = bytearray()
    for i in range(0, len(bits)-7, 8):
        b = 0
        for j in range(8): b = (b<<1) | bits[i+j]
        out.append(b)
    return bytes(out)

GOOD_CHARS = set(b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}[]":,./&=?_-+()\n\r\t ')
WORDS = [b'http', b'vivo', b'.zip', b'PD2055', b'url', b'json', b'size', b'md5', b'name', b'path',
         b'ver', b'model', b'imei', b'hwVer', b'swVer', b'fullVer', b'CN-ZH', b'WIFI', b'sign', b'time']

def score(m):
    pt = decode(conf, m)
    if pt is None: return -1e9, None
    sc = 0
    for b in pt:
        if b in GOOD_CHARS: sc += 1
        elif 0x20 <= b <= 0x7e: sc += 0.3
        else: sc -= 2
    for w in WORDS:
        sc += pt.count(w) * 30
    ptp = decode(param, m)
    if ptp is not None:
        for b in ptp:
            if b in GOOD_CHARS: sc += 1
        for w in WORDS:
            sc += ptp.count(w) * 30
    return sc, (pt, ptp)

# init: greedy assignment by frequency matching
freq = {}
for ch in conf: freq[ch] = freq.get(ch, 0) + 1
for ch in param: freq[ch] = freq.get(ch, 0) + 1

best_global = None
random.seed(1337)
for restart in range(12):
    # random bijection respecting domains
    while True:
        m = {}
        vals = list(range(64)); random.shuffle(vals)
        ok = True
        for s in sorted(syms, key=lambda y: -len(domains[y])):
            avail = [v for v in vals if domains[s][0] <= v <= domains[s][-1]]
            if not avail:
                ok = False; break
            v = random.choice(avail)
            m[s] = v
            vals.remove(v)
        if ok: break
    cur, _ = score(m)
    improved = True
    it = 0
    while improved and it < 4000:
        improved = False
        it += 1
        s1, s2 = random.sample(syms, 2)
        v1, v2 = m[s1], m[s2]
        # swap allowed?
        if not (domains[s1][0] <= v2 <= domains[s1][-1] and domains[s2][0] <= v1 <= domains[s2][-1]):
            continue
        m[s1], m[s2] = v2, v1
        new, _ = score(m)
        if new > cur:
            cur = new; improved = True
        else:
            m[s1], m[s2] = v1, v2
    print(f'restart {restart}: best {cur:.0f}')
    if best_global is None or cur > best_global[0]:
        sc, (pt, ptp) = score(m)
        best_global = (cur, dict(m), pt, ptp)

cur, m, pt, ptp = best_global
print('\n=== BEST SCORE', cur, '===')
print('--- conf plaintext ---')
print(pt[:400].decode('utf-8', errors='replace'))
if ptp:
    print('\n--- param plaintext ---')
    print(ptp[:300].decode('utf-8', errors='replace'))
open(r'br\conf_plaintext.txt','wb').write(pt)
if ptp: open(r'br\param_plaintext.txt','wb').write(ptp)
