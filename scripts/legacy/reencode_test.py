import json

conf = open(r'samples/recovery/last_server_cJSON.conf','r',encoding='utf-8').read().strip()
param = open(r'samples/request_param.txt','r').read().strip()
m = json.load(open(r'samples/alphabet_cpsat.json'))  # latest
# also load victory map for comparison
mv = json.load(open(r'samples/alphabet_victory.json'))

def decode(m, s):
    vals = [m.get(ch) for ch in s]
    out = []
    for g in range(0, len(vals)-3, 4):
        v = vals[g:g+4]
        if None in v: return None
        out.append((v[0]<<2)|(v[1]>>4)); out.append(((v[1]&15)<<4)|(v[2]>>2)); out.append(((v[2]&3)<<6)|v[3])
    r = len(vals)%4
    if r == 2: out.append((vals[-2]<<2)|(vals[-1]>>4))
    elif r == 3:
        out.append((vals[-3]<<2)|(vals[-2]>>4)); out.append(((vals[-2]&15)<<4)|(vals[-1]>>2))
    return bytes(out)

STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

def encode(m, plaintext):
    """encode bytes -> substituted base64 string using inverse map"""
    inv = {}
    for ch, v in m.items():
        inv[v] = ch
    bits = []
    for b in plaintext:
        bits.extend([(b>>7)&1,(b>>6)&1,(b>>5)&1,(b>>4)&1,(b>>3)&1,(b>>2)&1,(b>>1)&1,b&1])
    # pad to multiple of 6
    while len(bits) % 6: bits.append(0)
    out = []
    for i in range(0, len(bits), 6):
        v = 0
        for k in range(6): v = (v<<1) | bits[i+k]
        out.append(inv.get(v, '?'))
    return ''.join(out)

# decode param, re-encode, compare
pt = decode(m, param)
print('param plaintext (current map):')
print(pt.decode('utf-8', errors='replace'))
re = encode(m, pt)
print('\nre-encode == original?', re == param)
if re != param:
    diffs = [(i, param[i], re[i]) for i in range(min(len(re), len(param))) if param[i] != re[i]]
    print(f'{len(diffs)} position differences:')
    for i, a, b in diffs[:40]:
        print(f'  pos {i}: orig={a} reenc={b}  (context: {param[max(0,i-5):i+6]})')
