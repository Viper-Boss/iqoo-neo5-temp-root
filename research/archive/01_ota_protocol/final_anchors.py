# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import json

conf = open(r'br\recovery\last_server_cJSON.conf','r',encoding='utf-8').read().strip()
m = json.load(open(r'br\alphabet_repaired.json'))

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
    vals = [m.get(ch) for ch in s]
    out = []
    for g in range(0, len(vals)-3, 4):
        v = vals[g:g+4]
        out.append((v[0]<<2)|(v[1]>>4)); out.append(((v[1]&15)<<4)|(v[2]>>2)); out.append(((v[2]&3)<<6)|v[3])
    r = len(vals)%4
    if r == 2: out.append((vals[-2]<<2)|(vals[-1]>>4))
    elif r == 3:
        out.append((vals[-3]<<2)|(vals[-2]>>4)); out.append(((vals[-2]&15)<<4)|(vals[-1]>>2))
    return bytes(out)

# find URL offset from current decode
pt = decode(m, conf)
i_url = pt.find(b'sysupgrade')
print('sysupgrade at byte', i_url)
# URL = "http://" + 10 chars before sysupgrade... "http://" is 7 chars + "://" hmm: "http://" = 7, then "sysupgrade" — so http starts at i_url - 7
b_http = i_url - 7
print('http starts at byte', b_http)

anchors = [
    (b'http://sysupgrade.vivo.com.cn', b_http),
    (b'fileLength', 1),          # '{"fileLength'
    (b'":' , None),
]
# apply the http URL anchor
for plain, B in [(b'http://sysupgrade.vivo.com.cn', b_http)]:
    d = exact_derive(conf, plain, B)
    if d:
        print(f'URL anchor: {len(d)} symbols')
        for ch, v in d.items():
            if ch in m and m[ch] != v:
                print(f'  fix {ch!r}: {m[ch]} -> {v}')
            m[ch] = v
    else:
        print('URL anchor failed')

# more anchors on known-good text
pt2 = decode(m, conf)
print('\n--- decode after URL anchor ---')
print(pt2.decode('latin-1'))

# apply fileLength anchor (bytes 1-11: "fileLength" after '{')
d = exact_derive(conf, b'{"fileLength"', 0)
if d:
    print(f'\nfileLength anchor: {len(d)} symbols')
    for ch, v in d.items():
        if ch in m and m[ch] != v:
            print(f'  fix {ch!r}: {m[ch]} -> {v}')
        m[ch] = v

# version field: '"version":"9.10.3","url":"'
i_ver = pt2.find(b'version')
if i_ver > 0:
    # the text before version is '","' — anchor '"version"' at i_ver-1
    d = exact_derive(conf, b'"version":"9.10.3","url":"', i_ver-1)
    if d:
        print(f'version anchor: {len(d)} symbols')
        for ch, v in d.items():
            if ch in m and m[ch] != v:
                print(f'  fix {ch!r}: {m[ch]} -> {v}')
            m[ch] = v

# up.model / up.hardware / postStyle=false / fileType=full
pt3 = decode(m, conf)
for pat in [b'&up.model=PD2055&', b'&up.hardware=PD2055MA&', b'&fileLength=7039074100&',
            b'&imei=7495e721', b'fileType=full', b'httpsSupport=0']:
    i = pt3.find(pat)
    if i > 0:
        d = exact_derive(conf, pat, i)
        if d:
            n_fix = sum(1 for ch, v in d.items() if m.get(ch) != v)
            print(f'anchor {pat[:20]!r} @ {i}: {len(d)} syms, {n_fix} fixes')
            for ch, v in d.items():
                if ch in m and m[ch] != v:
                    print(f'  fix {ch!r}: {m[ch]} -> {v}')
                m[ch] = v

pt4 = decode(m, conf)
print('\n=== FINAL CONF ===')
print(pt4.decode('latin-1'))
open(r'br\conf_final2.txt','wb').write(pt4)
json.dump(m, open(r'br\alphabet_final2.json','w'))

# extract URL
i_h = pt4.find(b'http')
i_amp = pt4.find(b'&fileLength', i_h)
if i_h >= 0 and i_amp > i_h:
    url = pt4[i_h:i_amp].decode('latin-1')
    print('\n>>> DOWNLOAD URL:')
    print(url)
    open(r'br\DOWNLOAD_URL.txt','w').write(url)
