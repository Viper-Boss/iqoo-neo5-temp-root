# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import json

conf = open(r'br\recovery\last_server_cJSON.conf','r',encoding='utf-8').read().strip()
param = open(r'br\request_param.txt','r').read().strip()
m = json.load(open(r'br\alphabet_url.json'))

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

# score anchors by agreement with current (mostly correct) map
def find_anchor(cipher, plain, search_lo, search_hi):
    results = []
    for B in range(search_lo, search_hi):
        d = exact_derive(cipher, plain, B)
        if d is None or len(d) < 3: continue
        agree = sum(1 for ch,v in d.items() if m.get(ch) == v)
        known = sum(1 for ch,v in d.items() if m.get(ch) is not None)
        results.append((agree/max(1,known), agree, known, B, d))
    results.sort(reverse=True)
    return results

# 1. http URL at B=53
cands = [
    (b'http://sysupgrade.vivo.com.cn', 48, 60),
    (b'https://sysupgrade.vivo.com.cn', 48, 60),
]
best = None
for plain, lo, hi in cands:
    for ratio, agree, known, B, d in find_anchor(conf, plain, lo, hi)[:3]:
        print(f'{plain[:30]!r} B={B} agree={agree}/{known} ratio={ratio:.2f}')
        if best is None or ratio > best[0]:
            best = (ratio, plain, B, d)

ratio, plain, B, d = best
print(f'\nApplying: {plain!r} @B={B}')
for ch, v in d.items(): m[ch] = v

pt = decode(m, conf)
url_region = pt[50:130]
print('URL region now:', url_region)
print()
print(pt.decode('utf-8', errors='replace'))
json.dump(m, open(r'br\alphabet_url2.json','w'))
open(r'br\conf_url2.txt','wb').write(pt)
