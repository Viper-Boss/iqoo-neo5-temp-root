# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import json

# hill-climb map (mostly correct, some symbols wrong)
m_hc = json.load(open(r'br\alphabet.json'))

conf = open(r'br\recovery\last_server_cJSON.conf','r',encoding='utf-8').read().strip()
param = open(r'br\request_param.txt','r').read().strip()

# --- rerun anchor derivation (correct bit order) ---
def bitsof(b):
    return [(b >> i) & 1 for i in range(7, -1, -1)]

def anchor_candidates(cipher, plain_word):
    results = []
    W = len(plain_word)
    for B in range(0, len(cipher)*6//8 - W + 1):
        lo_bit = 8 * B
        hi_bit = 8 * B + 8 * W - 1
        c0, c1 = lo_bit // 6, hi_bit // 6
        if c1 >= len(cipher): break
        cons = {}
        ok = True
        for j, b in enumerate(plain_word):
            for k, bit in enumerate(bitsof(b)):
                gpos = 8*B + 8*j + k
                ci = gpos // 6
                bpos = gpos % 6
                ch = cipher[ci]
                cons.setdefault(ci, {})
                if cons[ci].get(bpos) is not None and cons[ci][bpos] != bit:
                    ok = False; break
                cons[ci][bpos] = bit
            if not ok: break
        if not ok: continue
        symsets = {}
        for ci, bits in cons.items():
            ch = cipher[ci]
            vals = set()
            for v in range(64):
                vb = [(v >> i) & 1 for i in range(5, -1, -1)]
                if all(vb[bp] == bit for bp, bit in bits.items()):
                    vals.add(v)
            if not vals: ok = False; break
            if ch in symsets:
                symsets[ch] &= vals
                if not symsets[ch]: ok = False; break
            else:
                symsets[ch] = vals
        if ok and all(len(v) == 1 for v in symsets.values()):
            results.append((B, {k: next(iter(v)) for k, v in symsets.items()}))
    return results

# known plaintexts (high confidence)
words_param = [(b'PD2055D_A_9.10.3', param), (b'PD2055_A_9.10.3', param),
               (b'<REDACTED_IMEI_HASH>', param),
               (b'PD2055MA', param), (b'1.0.3', param), (b'CN-ZH', param),
               (b'PD2055D_A_9.10.3', conf), (b'PD2055_A_9.10.3', conf),
               (b'<REDACTED_IMEI_HASH>', conf),
               (b'PD2055MA', conf), (b'http', conf), (b'.zip', conf), (b'vivo', conf),
               (b'size', conf), (b'md5', conf), (b'name', conf), (b'url', conf),
               (b'time', conf), (b'model', param), (b'imei', param), (b'hwVer', param)]

# collect votes: symbol -> {value: weight}
votes = {}
for w, s in words_param:
    for B, derived in anchor_candidates(s, w):
        weight = len(w)  # longer word = stronger
        for ch, v in derived.items():
            votes.setdefault(ch, {}).setdefault(v, 0)
            votes[ch][v] += weight

# reconcile with hill-climb map: hill climb gets weight too
for ch, v in m_hc.items():
    if ch in votes:
        votes[ch].setdefault(v, 0)
        votes[ch][v] += 150  # strong but not absolute

final = {}
conflicts = []
for ch, vd in votes.items():
    best_v = max(vd.items(), key=lambda kv: kv[1])
    second = sorted(vd.values(), reverse=True)
    if len(second) > 1 and second[0] == second[1]:
        conflicts.append(ch)
    final[ch] = best_v[0]

print('conflicts (ties):', conflicts)
print('final map size:', len(final))

def decode(m, s):
    try:
        vals = [m[ch] for ch in s]
    except KeyError as e:
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

pt = decode(final, conf)
ptp = decode(final, param)
print('\n===== FULL CONF PLAINTEXT =====')
print(pt.decode('utf-8', errors='replace') if pt else 'INCOMPLETE MAP')
print('\n===== FULL PARAM PLAINTEXT =====')
print(ptp.decode('utf-8', errors='replace') if ptp else 'INCOMPLETE MAP')
if pt: open(r'br\conf_final.txt','wb').write(pt)
if ptp: open(r'br\param_final.txt','wb').write(ptp)
json.dump(final, open(r'br\alphabet_final.json','w'))
