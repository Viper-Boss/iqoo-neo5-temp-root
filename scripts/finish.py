import json, random

conf = open(r'Q:\Deepseek\_neo5\br\recovery\last_server_cJSON.conf','r',encoding='utf-8').read().strip()
param = open(r'Q:\Deepseek\_neo5\br\request_param.txt','r').read().strip()
m0 = json.load(open(r'Q:\Deepseek\_neo5\br\alphabet_victory.json'))
TRUE_HASH = b'<REDACTED_IMEI_HASH>'
syms = sorted(set(conf) | set(param))

def decode(m, s):
    vals = [m.get(ch) for ch in s]
    out = []
    for g in range(0, len(vals)-3, 4):
        v = vals[g:g+4]
        if None in v:
            out.extend([None]*3); continue
        out.append((v[0]<<2)|(v[1]>>4))
        out.append(((v[1]&15)<<4)|(v[2]>>2))
        out.append(((v[2]&3)<<6)|v[3])
    r = len(vals)%4
    if r == 2:
        v = vals[-2:]
        out.append((v[0]<<2)|(v[1]>>4) if None not in v else None)
    elif r == 3:
        v = vals[-3:]
        if None not in v:
            out.append((v[0]<<2)|(v[1]>>4)); out.append(((v[1]&15)<<4)|(v[2]>>2))
    return [b for b in out if b is not None]

def bytes_of(m, s):
    return bytes(decode(m, s))

import string
ALNUM = set((string.ascii_letters + string.digits).encode())

def score(m):
    pt = bytes_of(m, conf); ptp = bytes_of(m, param)
    sc = 0
    # hash integrity (hard)
    if TRUE_HASH not in pt or TRUE_HASH not in ptp:
        return -1e9
    # whole-text quality
    for t in (pt, ptp):
        for b in t:
            if b in ALNUM: sc += 2
            elif b in b'{}":,./&?_-+%()= \n@': sc += 1
            else: sc -= 30
    # known words
    for wd in (b'fileName', b'fileLength', b'api2.do', b'http', b'vivo', b'.com.cn',
               b'PD2055', b'md5', b'imei', b'version', b'model', b'hardware',
               b'up.model', b'check', b'full', b'false', b'Support', b'NULL', b'custom'):
        sc += pt.count(wd) * 200 + ptp.count(wd) * 200
    # fileName region: after 'fileName=%40' until '&' must be all alnum
    try:
        i0 = pt.find(b'fileName=%40')
        if i0 > 0:
            i1 = pt.find(b'&', i0)
            region = pt[i0+11:i1]
            good = sum(1 for b in region if b in ALNUM)
            sc += good * 50 - (len(region)-good) * 400
            # filename should be substantial
            if len(region) > 60: sc += 500
    except Exception:
        pass
    return sc

random.seed(777)
best = (score(m0), dict(m0))
print('start:', best[0])
for trial in range(40):
    m = dict(best[1])
    cur = score(m)
    for it in range(30000):
        s1, s2 = random.sample(syms, 2)
        v1, v2 = m[s1], m[s2]
        m[s1], m[s2] = v2, v1
        ns = score(m)
        if ns > cur: cur = ns
        else: m[s1], m[s2] = v1, v2
    if cur > best[0]:
        best = (cur, dict(m))
        print(f'trial {trial}: {cur}')

sc, m = best
pt = bytes_of(m, conf)
print('\n=== FINAL ===')
print(pt.decode('utf-8', errors='replace'))
i0 = pt.find(b'fileName=%40')
i1 = pt.find(b'&', i0) if i0 > 0 else -1
print('\n>>> FILENAME:', pt[i0+11:i1].decode('latin-1'))
print('>>> FULL URL:', pt[pt.find(b'http'):i1].decode('latin-1'))
open(r'Q:\Deepseek\_neo5\br\conf_done.txt','wb').write(pt)
json.dump(m, open(r'Q:\Deepseek\_neo5\br\alphabet_done.json','w'))
