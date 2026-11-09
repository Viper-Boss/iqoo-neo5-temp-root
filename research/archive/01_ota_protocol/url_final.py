# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import json

conf = open(r'br\recovery\last_server_cJSON.conf','r',encoding='utf-8').read().strip()
param = open(r'br\request_param.txt','r').read().strip()
m_exact = json.load(open(r'br\alphabet_exact.json'))

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

trusted = {}
for d in (exact_derive(param, TRUE_HASH, 119),
          exact_derive(conf, TRUE_HASH, 341),
          exact_derive(param, b'PD2055MA', 22),
          exact_derive(conf, b'PD2055MA', 242)):
    for ch, v in d.items():
        if ch in trusted and trusted[ch] != v:
            print('TRUSTED CONFLICT', ch)
        trusted[ch] = v
print('trusted symbols:', len(trusted))

hosts = ['sysupgrade', 'sysupdxdl', 'sysupgdxdl', 'sysupdrade', 'upgrade', 'sysupdate', 'sysdown']
schemes = ['http://', 'https://']
tlds = ['.vivo.com.cn', '.vivo.com', '.bbk.com']
results = []
for scheme in schemes:
    for host in hosts:
        for tld in tlds:
            url = scheme + host + tld
            for B in range(40, 70):
                d = exact_derive(conf, url.encode(), B)
                if d is None or len(d) < 4: continue
                known = sum(1 for ch in d if ch in trusted)
                agree = sum(1 for ch, v in d.items() if trusted.get(ch) == v)
                if known >= 3:
                    results.append((agree/max(1,known), agree, known, B, url, d))
results.sort(reverse=True)
print('\ntop URL candidates:')
for ratio, agree, known, B, url, d in results[:8]:
    print(f'  {url!r} B={B} agree={agree}/{known} ({ratio:.2f})')

ratio, agree, known, B, url, d = results[0]
print(f'\nAPPLYING {url!r} @ B={B}')
m2 = dict(m_exact)
for ch, v in d.items():
    m2[ch] = v

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

pt = decode(m2, conf)
print('\nCONF:')
print(pt.decode('utf-8', errors='replace'))
json.dump(m2, open(r'br\alphabet_url3.json','w'))
