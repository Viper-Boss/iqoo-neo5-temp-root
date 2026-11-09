# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import random

m0 = {'4':52,'l':55,'W':13,'N':3,'H':36,'C':53,'6':25,'M':19,'c':28,'D':50,'T':12,
      'Z':24,'d':32,'1':57,'y':6,'E':8,'m':56,'9':51,'k':20,'2':38,'h':21,'z':34,
      '5':22,'_':17,'P':49,'r':5,'-':4,'e':35,'0':54,'K':16,'x':27,'g':61,'f':48,
      'U':29,'R':23,'8':9,'X':44}

conf = open(r'br\recovery\last_server_cJSON.conf','r',encoding='utf-8').read().strip()
param = open(r'br\request_param.txt','r').read().strip()
syms = sorted(set(conf) | set(param))

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

import re
GOOD = set(b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}":,./&=?_-+()\n')
STRONG = set(b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789=')
WORDS = [b'PD2055', b'http', b'vivo', b'.zip', b'size', b'md5', b'name', b'model',
         b'upgrade', b'files', b'time', b'sign', b'url', b'ver', b'CN', b'zh']

def score(m):
    pt = decode(m, conf); ptp = decode(m, param)
    if pt is None or ptp is None: return -1e9
    sc = 0
    for pt_s, w in ((pt, 1.0), (ptp, 1.0)):
        for b in pt_s:
            if b in STRONG: sc += 2
            elif b in GOOD: sc += 1
            else: sc -= 3
        for wd in WORDS: sc += pt_s.count(wd) * 60
        # hex-run bonus: long runs of hex chars (hashes!)
        sc += sum(len(mm) for mm in re.findall(rb'[0-9a-f]{8,}', pt_s)) * 2
    return sc

best = None
random.seed(1234)
for trial in range(60):
    m = dict(m0)
    used = set(m.values())
    rest = [s for s in syms if s not in m]
    random.shuffle(rest)
    ok = True
    for s in rest:
        cand = [v for v in range(64) if v not in used]
        if not cand: ok = False; break
        v = random.choice(cand); m[s] = v; used.add(v)
    if not ok: continue
    cur = score(m)
    for it in range(6000):
        s1, s2 = random.sample(list(m.keys()), 2)
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
print('\n=== FINAL SCORE', sc, '===')
print('\n--- CONF plaintext ---')
print(pt.decode('utf-8', errors='replace'))
print('\n--- PARAM plaintext ---')
print(ptp.decode('utf-8', errors='replace'))
open(r'br\conf_plaintext.txt','wb').write(pt)
open(r'br\param_plaintext.txt','wb').write(ptp)
import json
json.dump(m, open(r'br\alphabet.json','w'))
