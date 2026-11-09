# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import json, random, re

conf = open(r'br\recovery\last_server_cJSON.conf','r',encoding='utf-8').read().strip()
param = open(r'br\request_param.txt','r').read().strip()
m0 = json.load(open(r'br\alphabet_url3.json'))
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

# lock: verify hash still matches
def bytes_of(m, s):
    return bytes(decode(m, s))

assert TRUE_HASH in bytes_of(m0, conf), 'hash check failed'
assert TRUE_HASH in bytes_of(m0, param), 'hash check failed 2'
print('hash anchors verified in current map')

STRONG = set(b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789=')
GOOD = STRONG | set(b'{}":,./&?_-+%()\n @')
WORDS = [b'PD2055', b'http', b'vivo', b'.zip', b'size', b'md5', b'fileName', b'model',
         b'upgrade', b'fileLength', b'imei', b'fileName=', b'api2.do', b'.do', b'version',
         b'length', b'Length', b'Sha', b'sha', b'check']

def score(m):
    pt = bytes_of(m, conf); ptp = bytes_of(m, param)
    sc = 0
    for t in (pt, ptp):
        for b in t:
            if b in STRONG: sc += 3
            elif b in GOOD: sc += 1
            else: sc -= 8
        for wd in WORDS: sc += t.count(wd) * 150
        sc += sum(len(mm) for mm in re.findall(rb'[0-9a-zA-Z]{12,}', t)) * 2
    if TRUE_HASH in pt: sc += 8000
    if TRUE_HASH in ptp: sc += 8000
    return sc

# hill climb: swap any pair of symbols (keep hash-valid via score's big bonus)
random.seed(4242)
best = (score(m0), dict(m0))
print('start score:', best[0])
for trial in range(25):
    m = dict(best[1])
    cur = score(m)
    for it in range(20000):
        s1, s2 = random.sample(syms, 2)
        v1, v2 = m[s1], m[s2]
        m[s1], m[s2] = v2, v1
        ns = score(m)
        if ns > cur:
            cur = ns
        else:
            m[s1], m[s2] = v1, v2
    if cur > best[0]:
        best = (cur, dict(m))
        print(f'trial {trial}: {cur}')

sc, m = best
pt = bytes_of(m, conf); ptp = bytes_of(m, param)
print('\n=== FINAL (score', sc, ') ===')
print('\n--- CONF ---')
print(pt.decode('utf-8', errors='replace'))
print('\n--- PARAM ---')
print(ptp.decode('utf-8', errors='replace'))
open(r'br\conf_victory.txt','wb').write(pt)
open(r'br\param_victory.txt','wb').write(ptp)
json.dump(m, open(r'br\alphabet_victory.json','w'))
