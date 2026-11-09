# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import json

param = open(r'br\request_param.txt','r').read().strip()
m = json.load(open(r'br\alphabet_cpsat.json'))

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

# corrected plaintext guess (from field knowledge)
guess = (b'model=PD2055&hardware=PD2055MA&version=PD2055_N_PD2055MA_9.10.3'
         b'&oem=PD2055D_CN-ZH_FULL_SC_NULL'
         b'&sdkVersion=34&sc=='
         b'&imei=<REDACTED_IMEI_HASH>'
         b'&emmcid=<REDACTED_EMMCID>'
         b'&oemVersion=N&custom=N&gn=0'
         b'&oemProjects=PD2055+PD2055B+PD2055C,PD2055D+PD2055E+PD2055F,PD2055G'
         b'&vgcCu=NULL&hasVgc=0&countryRegion=CN/ZH&vgcSwVer=null&pver=1'
         b'&jvq_type=0&servType=0&se?Version=&?ps?e?s?=&fbe?re?s?=')

cur = decode(m, param)
print('current decode len:', len(cur))
print('guess len:', len(guess))
# align: print current decode for manual diff
print('\ncurrent:')
print(cur.decode('latin-1'))
print('\nguess:')
print(guess.decode('latin-1'))

enc = encode(m, guess[:len(cur)] if len(guess) > len(cur) else guess)
print('\nre-encoded guess == param?', enc == param)
if enc != param:
    # find first diff
    for i in range(min(len(enc), len(param))):
        if enc[i] != param[i]:
            print(f'first diff at char {i}: orig={param[i]} enc={enc[i]}')
            print('orig ctx:', param[max(0,i-10):i+10])
            print('enc  ctx:', enc[max(0,i-10):i+10])
            break
