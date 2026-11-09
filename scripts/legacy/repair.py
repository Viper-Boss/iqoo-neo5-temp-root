# NOTE(privacy): device identifiers (IMEI hash / emmcid) that were embedded in
# this historical script have been REDACTED (<REDACTED_*> placeholders). The
# script is kept as a methodology record; re-running it requires re-supplying
# your own device's known-plaintext anchors. See SECURITY.md.
import json

param = open(r'samples/request_param.txt','r').read().strip()
m = json.load(open(r'samples/alphabet_cpsat.json'))

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

# plaintext guess with '?' as unknown markers
guess = bytearray(b'model=PD2055&hardware=PD2055MA&version=PD2055_N_PD2055MA_9.10.3'
         b'&oem=PD2055D_CN-ZH_FULL_SC_NULL'
         b'&sdkVersion=34&?c=='
         b'&imei=<REDACTED_IMEI_HASH>'
         b'&emmcid=<REDACTED_EMMCID>'
         b'&?emVersion=N&custom=N&gn=0'
         b'&oemProjects=PD2055+PD2055B+PD2055C,PD2055D+PD2055E+PD2055F,PD2055G'
         b'&vgcCu=NULL&hasVgc=0&countryRegion=CN/ZH&vgcSwVer=null&pver=1'
         b'&jvq_type=0&servType=0&se?Version=&?ps?e?si?=&fbe?re?si?=')
while len(guess) < 454:
    guess.append(0x3f)
unknown_positions = {i for i, b in enumerate(bytes(guess)) if b == 0x3f}

# iterative repair
changed = True
rounds = 0
swaps_done = set()
while changed and rounds < 100:
    rounds += 1
    changed = False
    enc = encode(m, bytes(guess[:454]))
    # find diffs where plaintext is known
    diffs = []
    for i in range(min(len(enc), len(param))):
        if enc[i] != param[i]:
            # which plaintext bytes does char i depend on?
            # char i covers bits [6i, 6i+6) -> bytes 6i//8 .. (6i+5)//8
            b_lo = (6*i) // 8
            b_hi = (6*i+5) // 8
            if all(p not in unknown_positions for p in range(b_lo, b_hi+1)):
                diffs.append((i, param[i], enc[i]))
    if not diffs:
        print('no fixable diffs remain')
        break
    # fix the first few diffs (swap symbol values)
    for i, orig_ch, enc_ch in diffs[:3]:
        pair = (orig_ch, enc_ch)
        if pair in swaps_done:
            continue
        # swap values of the two symbols
        va, vb = m.get(orig_ch), m.get(enc_ch)
        if va is None or vb is None:
            continue
        m[orig_ch], m[enc_ch] = vb, va
        swaps_done.add(pair)
        changed = True
        print(f'round {rounds}: swap {orig_ch!r}({va}) <-> {enc_ch!r}({vb}) at char {i}')

# final state
enc = encode(m, bytes(guess[:454]))
matching = sum(1 for i in range(min(len(enc), len(param))) if enc[i] == param[i])
print(f'\nfinal: {matching}/{len(param)} chars match ({matching/len(param)*100:.1f}%)')

pt = decode(m, param)
print('\n=== PARAM decoded (repaired) ===')
print(pt.decode('latin-1'))
json.dump(m, open(r'samples/alphabet_repaired.json','w'))

conf = open(r'samples/recovery/last_server_cJSON.conf','r',encoding='utf-8').read().strip()
ptc = decode(m, conf)
print('\n=== CONF decoded (repaired) ===')
print(ptc.decode('latin-1'))
open(r'samples/conf_repaired.txt','wb').write(ptc)


