# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import json

conf = open(r'br\recovery\last_server_cJSON.conf','r',encoding='utf-8').read().strip()
param = open(r'br\request_param.txt','r').read().strip()
m = json.load(open(r'br\alphabet_exact.json'))

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

pt = decode(m, conf)
# find "9xt0" (http) position in the decoded text
pos = pt.find(b'9xt0')
print('http-position in decoded conf:', pos)

# candidate URL plaintexts
url_candidates = [
    b'http://sysupgrade.vivo.com.cn',
    b'http://sysupgrade.vivo.com.cn/',
    b'https://sysupgrade.vivo.com.cn',
    b'http://sysupdxdl.vivo.com.cn',
    b'sysupgrade.vivo.com.cn',
    b'upgrade/oem/files',
    b'/upgrade/oem/files/',
    b'.zip',
]
best_anchor = None
for cand in url_candidates:
    for B in range(max(0,pos-10), pos+30):
        d = exact_derive(conf, cand, B)
        if d is None: continue
        # check consistency with current map: count conflicts (some current values are wrong!)
        agree = sum(1 for ch,v in d.items() if m.get(ch) == v)
        disagree = sum(1 for ch,v in d.items() if m.get(ch) is not None and m.get(ch) != v)
        if best_anchor is None or len(d) > len(best_anchor[1]):
            best_anchor = (cand, d, B)
            print(f'{cand!r} @B={B}: {len(d)} syms, agree={agree} disagree={disagree}')

# apply the strongest URL anchor
if best_anchor:
    cand, d, B = best_anchor
    print(f'\napplying anchor {cand!r} @B={B}')
    for ch, v in d.items():
        m[ch] = v
    # verify bijection, fix dups by keeping anchor values
    inv = {}
    for ch in sorted(m.keys()):
        v = m[ch]
        if v in inv:
            # remove the other symbol's value (mark for hill fix later) - just report now
            print(f'dup: {ch} and {inv[v]} both = {v}')
        else:
            inv[v] = ch

pt = decode(m, conf)
print('\n=== UPDATED CONF ===')
print(pt.decode('utf-8', errors='replace'))
open(r'br\conf_url.txt','wb').write(pt)
json.dump(m, open(r'br\alphabet_url.json','w'))
