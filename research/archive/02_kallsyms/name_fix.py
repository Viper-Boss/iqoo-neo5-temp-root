# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import json

conf = open(r'br\recovery\last_server_cJSON.conf','r',encoding='utf-8').read().strip()
param = open(r'br\request_param.txt','r').read().strip()
m = json.load(open(r'br\alphabet_final2.json'))

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

def encode(m, plaintext):
    inv = {v: ch for ch, v in m.items()}
    bits = []
    for b in plaintext:
        bits.extend([(b>>7)&1,(b>>6)&1,(b>>5)&1,(b>>4)&1,(b>>3)&1,(b>>2)&1,(b>>1)&1,b&1])
    while len(bits) % 6: bits.append(0)
    out = []
    for i in range(0, len(bits), 6):
        v = 0
        for k in range(6): v = (v<<1) | bits[i+k]
        out.append(inv.get(v, '?'))
    return ''.join(out)

# current decode
pt = decode(m, conf)
print('current:')
print(pt.decode('latin-1'))

# Repair via oracle on the CONF: guess the full plaintext with unknown name region
# Structure: {"fileLength":"7039074100","version":"9.10.3","url":"http://sysupgrade.vivo.com.cn/dapi2.do?fileName=%40<NAME>&...
# name region bytes: find them
i_name_start = pt.find(b'%40') + 3
i_name_end = pt.find(b'&fileLength', i_name_start)
print(f'\nname region: bytes {i_name_start}..{i_name_end} ({i_name_end-i_name_start} chars)')
name = pt[i_name_start:i_name_end]
print('name:', name.decode('latin-1'))

# name chars that are non-alnum are wrong
import string
ALNUM = set((string.ascii_letters + string.digits + '=').encode())
bad_positions = [(i_name_start+i, b) for i, b in enumerate(name) if b not in ALNUM]
print('bad name chars:', [(p, chr(b)) for p, b in bad_positions])

# repair loop on conf using the known structure
guess = bytearray(pt)  # start from current decode (mostly right)
# fix the known-wrong chars in structure:
fixes = [(1, ord('f'))]
# '{"fileLength"' — byte 1 should be 'f'? it IS 'f'... the "fileLejgth" issue: find and fix
# Let's directly repair via re-encode oracle on everything EXCEPT the name region
# mark name region unknown
unknown = set(range(i_name_start, i_name_end))
# also the 'j' in fileLejgth and the '>' — try fixing via known text
known_txt = b'{"fileLength"'
for i, b in enumerate(known_txt):
    guess[i] = b
known_txt2 = b'","version":"9.10.3","url":"http://sysupgrade.vivo.com.cn/dapi2.do?fileName=%40'
i_url_start = 41  # '{"fileLength":"7039074100"' is 25 chars + ',"version"...' hmm compute
# find where '"version"' starts
iv = pt.find(b'version')
# the ',' before version at iv-2... let's anchor from '"version'
start = iv - 1
for i, b in enumerate(known_txt2):
    if start + i < len(guess) and start+i not in unknown:
        guess[start+i] = b

# tail: '&fileLength=7039074100&up.model=PD2055&up.version=PD2055_N_PD2055MA_9.10.3&up.tail=&up.hardware=PD2055MA&postStyle=false&httpsSupport=0&fileType=full&up.imei='
tail_start = pt.find(b'&fileLength', i_name_end)
tail = (b'&fileLength=7039074100&up.model=PD2055&up.version=PD2055_N_PD2055MA_9.10.3'
        b'&up.tail=&up.hardware=PD2055MA&postStyle=false&httpsSupport=0&fileType=full&up.imei=')
for i, b in enumerate(tail):
    if tail_start + i < len(guess):
        guess[tail_start+i] = b
# hash region is correct
TRUE_HASH = b'<REDACTED_IMEI_HASH>'
ih = pt.find(TRUE_HASH)
for i, b in enumerate(TRUE_HASH):
    guess[ih+i] = b
# after hash: '&up.emmcid=' + hash + '","checkString":""}'
tail2_start = ih + 64
tail2 = b'&up.emmcid=' + b'<REDACTED_EMMCID>' + b'","checkString":""}'
h2 = pt.find(b'<REDACTED_HEX>')
for i, b in enumerate(b'&up.emmcid='):
    guess[h2-11+i] = b
for i, b in enumerate(b'<REDACTED_EMMCID>'):
    guess[h2+i] = b
for i, b in enumerate(b'","checkString":""}'):
    guess[h2+64+i] = b

# repair loop: re-encode guess, find diffs at known positions, swap symbols
changed = True
rounds = 0
while changed and rounds < 60:
    rounds += 1
    changed = False
    enc = encode(m, bytes(guess))
    diffs = []
    for i in range(min(len(enc), len(conf))):
        if enc[i] != conf[i]:
            b_lo = (6*i)//8; b_hi = (6*i+5)//8
            if not any(p in unknown for p in range(b_lo, b_hi+1)):
                diffs.append((i, conf[i], enc[i]))
    for i, a, b in diffs[:2]:
        va, vb = m.get(a), m.get(b)
        if va is None or vb is None or va == vb: continue
        m[a], m[b] = vb, va
        changed = True
        print(f'swap {a!r}({va}) <-> {b!r}({vb})')

pt2 = decode(m, conf)
print('\n=== REPAIRED ===')
print(pt2.decode('latin-1'))
name2 = pt2[pt2.find(b'%40')+3:pt2.find(b'&fileLength', pt2.find(b'%40'))]
print('\nname:', name2.decode('latin-1'))
bad = [b for b in name2 if b not in ALNUM]
print('non-alnum in name:', bad)
json.dump(m, open(r'br\alphabet_final3.json','w'))
open(r'br\conf_final3.txt','wb').write(pt2)

# URL
i_h = pt2.find(b'http')
i_amp = pt2.find(b'&fileLength', i_h)
url = pt2[i_h:i_amp].decode('latin-1')
print('\n>>> URL:', url)
open(r'br\DOWNLOAD_URL.txt','w').write(url)
