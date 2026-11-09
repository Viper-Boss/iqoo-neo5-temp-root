# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import json, random, string

conf = open(r'br\recovery\last_server_cJSON.conf','r',encoding='utf-8').read().strip()
param = open(r'br\request_param.txt','r').read().strip()
m0 = json.load(open(r'br\alphabet_victory.json'))
TRUE_HASH = b'<REDACTED_IMEI_HASH>'
syms = sorted(set(conf) | set(param))
ALNUM = set((string.ascii_letters + string.digits).encode())

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

def score(m):
    pt = bytes_of(m, conf); ptp = bytes_of(m, param)
    if TRUE_HASH not in pt or TRUE_HASH not in ptp:
        return -1e9
    sc = 0
    # region constraints using RELIABLE anchors: 'fileLength' is readable
    i_fl = pt.find(b'fileLength=7039074100')
    i_url = pt.find(b'sysupgrade.vivo.com.cn')
    if i_url > 0 and i_fl > i_url:
        # name region: after the '?' (fileName=...) up to fileLength
        i_q = pt.find(b'?', i_url)
        if i_q > 0:
            region = pt[i_q+1:i_fl]
            # after fileName=%40 or similar: find '%' or start after '='
            ie = region.rfind(b'=')
            core = region[ie+1:] if ie >= 0 else region
            good = sum(1 for b in core if b in ALNUM or b == 0x3d)
            sc += good * 100 - (len(core)-good) * 500
            # '=' allowed, '/' allowed before the name
            prefix = region[:ie+1] if ie >= 0 else b''
            pgood = sum(1 for b in prefix if b in ALNUM or b in b'./?=&%%_')
            sc += pgood * 20 - (len(prefix)-pgood) * 200
    # overall text quality
    for t in (pt, ptp):
        for b in t:
            if b in ALNUM: sc += 2
            elif b in b'{}":,./&?_-+%()= \n@': sc += 1
            else: sc -= 40
    for wd in (b'fileLength', b'fileName', b'http', b'vivo.com.cn', b'PD2055',
               b'md5', b'imei', b'version', b'hardware', b'model', b'api2.do',
               b'full', b'false', b'Support', b'NULL'):
        sc += (pt.count(wd) + ptp.count(wd)) * 300
    return sc

random.seed(31337)
best = (score(m0), dict(m0))
print('start:', best[0])
for trial in range(60):
    m = dict(best[1])
    cur = score(m)
    for it in range(40000):
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
i_url = pt.find(b'sysupgrade.vivo.com.cn')
i_fl = pt.find(b'fileLength=7039074100')
print('\n>>> URL+NAME region:')
print(pt[max(0,i_url-10):i_fl].decode('latin-1'))
open(r'br\conf_done.txt','wb').write(pt)
json.dump(m, open(r'br\alphabet_done.json','w'))
