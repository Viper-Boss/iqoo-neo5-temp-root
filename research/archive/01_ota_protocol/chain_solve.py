# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import itertools, random

conf = open(r'br\recovery\last_server_cJSON.conf','r',encoding='utf-8').read().strip()
param = open(r'br\request_param.txt','r').read().strip()

def decode(m, s):
    try:
        vals = [m[ch] for ch in s]
    except KeyError:
        return None
    out = []
    for i in range(0, len(vals)-3, 4):
        v0,v1,v2,v3 = vals[i:i+4]
        out.append((v0<<2)|(v1>>4)); out.append(((v1&15)<<4)|(v2>>2)); out.append(((v2&3)<<4)|v3)
    r = len(vals) % 4
    if r == 2:
        out.append((vals[-2]<<2)|(vals[-1]>>4))
    elif r == 3:
        out.append((vals[-3]<<2)|(vals[-2]>>4)); out.append(((vals[-2]&15)<<4)|(vals[-1]>>2))
    return bytes(out)

# Given a byte-position p in the plaintext and an assumed byte value b,
# determine constraints on symbol values.
# bytes p, p+1, p+2 come from chars at 4p/3 (aligned only when p%3==0 for clean math)
# We'll work with whole groups: group g (chars 4g..4g+3) = bytes 3g..3g+2.

# Chain solver: assume plaintext prefix, group by group.
# For group g: symbols s0..s3 = conf[4g..4g+3]; bytes b0,b1,b2 = pt[3g..3g+2]
# v(s0) = b0>>2 ; v(s1) top4 = (b0&3)<<... derive:
#   v0: b0>>2 (bits), low2 of v0 unknown from b0 alone? NO: b0 = (v0<<2)|(v1>>4) fully determines:
#     v0 = b0 >> 2  (6 bits: top 6 of b0... wait b0 is 8 bits: v0 = b0>>2 uses top 6 bits... but b0<0x80 so v0<32) — v0 = b0>>2 exactly? b0>>2 gives 6 bits yes → v0 = b0>>2. THEN v1>>4 = b0 & 3.
#   v1 = (b1>>4) | ((b0&3)<<4)  → v1 determined fully by b0,b1!
#   v2 = (b2>>6) | ((b1&15)<<2) → determined by b1,b2
#   v3 = b2 & 63 → determined
# GREAT: knowing 3 plaintext bytes fully determines the 4 symbol values!

def group_values(b0, b1, b2):
    v0 = b0 >> 2
    v1 = ((b0 & 3) << 4) | (b1 >> 4)
    v2 = ((b1 & 15) << 2) | (b2 >> 6)
    v3 = b2 & 63
    return [v0, v1, v2, v3]

# verify with self-consistency: encode known text
import base64
def selfcheck():
    STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    pt = b'{"message":"ok"}123'
    b64 = base64.urlsafe_b64encode(pt).decode()
    for g4 in range(0, len(b64)-3, 4):
        gi = g4 // 4
        b = pt[gi*3:gi*3+3]
        if len(b) < 3: break
        vs = group_values(b[0], b[1], b[2])
        assert ''.join(STD[v] for v in vs) == b64[g4:g4+4], (g4, vs, b64[g4:g4+4])
    print('group_values self-check OK')
selfcheck()

# Now: derive symbol values from assumed plaintext prefixes.
# Try candidate JSON prefixes for the conf.
candidates = [
    '{"data"', '{"message"', '{"md5"', '{"param"', '{"code"', '{"err"', '{"msg"',
    '{"url"', '{"size"', '{"name"', '{"time"', '{"ver"', '{"sign"', '{"path"',
    '{"data":{', '{"d', '{"m', '{"p', '{"c', '{"e', '{"u', '{"s', '{"n', '{"t', '{"v',
]

def try_prefix(pt_prefix):
    """pt_prefix: bytes. Derive symbol values group by group; return map or None on conflict."""
    m = {}
    inv = {}
    n = len(pt_prefix)
    for g in range(0, (n - n%3)//1):
        gidx = g // 3  # group index
        if gidx*4+4 > len(conf): break
        if (gidx+1)*3 > n: break
        b0, b1, b2 = pt_prefix[gidx*3], pt_prefix[gidx*3+1], pt_prefix[gidx*3+2]
        vs = group_values(b0, b1, b2)
        chars = conf[gidx*4:gidx*4+4]
        for ch, v in zip(chars, vs):
            if ch in m:
                if m[ch] != v: return None
            else:
                if v in inv: return None  # bijection
                m[ch] = v; inv[v] = ch
    return m

results = []
for cand in candidates:
    m = try_prefix(cand.encode())
    if m:
        results.append((cand, m))
        print(f'PREFIX OK: {cand!r} -> {len(m)} symbols: {m}')

# For each surviving prefix, hill-climb the rest
GOOD = set(b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}[]":,./&=?_-+() \n')
WORDS = [b'http',b'vivo',b'.zip',b'PD2055',b'url',b'size',b'md5',b'name',b'time',b'sign',b'model',b'upgrade']

def score(m):
    pt = decode(m, conf); ptp = decode(m, param)
    sc = 0
    if pt:
        sc += sum(1 for b in pt if b in GOOD)*2
        sc -= sum(1 for b in pt if b not in GOOD)*3
        for w in WORDS: sc += pt.count(w)*100
    if ptp:
        sc += sum(1 for b in ptp if b in GOOD)*2
        sc -= sum(1 for b in ptp if b not in GOOD)*3
        for w in WORDS: sc += ptp.count(w)*100
    return sc

best_global = None
for cand, m0 in results:
    print(f'\n--- hill climb from {cand!r} (start score {score(m0)}) ---')
    syms = sorted(set(conf) | set(param))
    random.seed(7)
    for trial in range(20):
        m = dict(m0)
        used = set(m.values())
        rest = [s for s in syms if s not in m]
        ok = True
        for s in sorted(rest, key=lambda x: random.random()):
            cand_v = [v for v in range(64) if v not in used]
            if not cand_v: ok = False; break
            v = random.choice(cand_v)
            m[s] = v; used.add(v)
        if not ok: continue
        cur = score(m)
        for it in range(3000):
            s1, s2 = random.sample(list(m.keys()), 2)
            v1, v2 = m[s1], m[s2]
            m[s1], m[s2] = v2, v1
            ns = score(m)
            if ns > cur: cur = ns
            else: m[s1], m[s2] = v1, v2
        if best_global is None or cur > best_global[0]:
            best_global = (cur, dict(m), cand)
            print(f'  new best {cur} (from {cand!r})')

if best_global:
    sc, m, cand = best_global
    print('\n=== BEST', sc, 'from', cand, '===')
    pt = decode(m, conf); ptp = decode(m, param)
    print('CONF :', pt[:250])
    print('PARAM:', (ptp or b'')[:250])
    open(r'br\conf_plaintext.txt','wb').write(pt)
    if ptp: open(r'br\param_plaintext.txt','wb').write(ptp)
else:
    print('no prefix survived')
