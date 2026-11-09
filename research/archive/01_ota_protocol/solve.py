# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import sys
from collections import defaultdict

conf = open(r'br\recovery\last_server_cJSON.conf','r',encoding='utf-8').read().strip()
param = open(r'br\request_param.txt','r').read().strip()

ALL = sorted(set(conf) | set(param))
# standard base64 value -> char (url-safe variant since strings contain - _)
STD_URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
# printable target for plaintext bytes
def ok_byte(b):
    return 0x20 <= b <= 0x7e or b in (10, 13, 9)

# anchor: plaintext[0] = '{' = 0x7b
ANCHOR0 = 0x7b

def decode_group(vals):
    """4 six-bit values -> 3 bytes"""
    v0,v1,v2,v3 = vals
    b0 = (v0<<2) | (v1>>4)
    b1 = ((v1&0xf)<<4) | (v2>>2)
    b2 = ((v2&3)<<4) | v3
    return b0,b1,b2

def decode_tail2(vals):
    v0,v1 = vals
    b0 = (v0<<2) | (v1>>4)
    return b0, ((v1&0xf)<<4)

# build groups from conf
groups = []
for i in range(0, len(conf)-3, 4):
    groups.append(conf[i:i+4])
tail = conf[len(conf)//4*4:]
print(f'conf groups: {len(groups)}, tail: "{tail}"')

symbol_values = {}   # symbol -> value (0..63)
# start anchor: first byte must be '{'
# conf[0..3] -> bytes0-2. byte0 = (v0<<2)|(v1>>4) = 0x7b

# DFS over groups
solutions = []
def dfs(gi):
    if len(solutions) > 2000:
        return
    if gi >= len(groups):
        # handle tail
        if len(tail) == 2:
            v0 = symbol_values.get(tail[0])
            v1 = symbol_values.get(tail[1])
            if v0 is not None and v1 is not None:
                b0 = (v0<<2)|(v1>>4)
                if ok_byte(b0):
                    solutions.append(dict(symbol_values))
        elif len(tail) == 0:
            solutions.append(dict(symbol_values))
        return
    g = groups[gi]
    syms = [s for s in g]
    # unknown symbols in this group
    unknown = [s for s in dict.fromkeys(g) if s not in symbol_values]
    if not unknown:
        vals = [symbol_values[s] for s in g]
        b = decode_group(vals)
        if gi == 0:
            if b[0] != ANCHOR0 or not all(ok_byte(x) for x in b):
                return
        else:
            if not all(ok_byte(x) for x in b):
                return
        dfs(gi+1)
        return
    # enumerate values for unknown symbols
    def try_assign(ui, val_map):
        if ui == len(unknown):
            # check group
            vals = [val_map.get(s, symbol_values.get(s)) for s in g]
            if any(v is None for v in vals):
                return
            b = decode_group(vals)
            if gi == 0:
                if b[0] != ANCHOR0 or not all(ok_byte(x) for x in b):
                    return
            else:
                if not all(ok_byte(x) for x in b):
                    return
            # commit
            old = {}
            for s,v in val_map.items():
                old[s] = symbol_values.get(s)
                symbol_values[s] = v
            dfs(gi+1)
            for s,v in old.items():
                if v is None: del symbol_values[s]
                else: symbol_values[s] = v
            return
        s = unknown[ui]
        for v in range(64):
            if v in val_map.values():
                continue
            val_map[s] = v
            try_assign(ui+1, val_map)
            del val_map[s]
    try_assign(0, {})

print('searching...')
dfs(0)
print('solutions found:', len(solutions))

# score solutions by plaintext quality
def apply(sol, s):
    bits = ''
    for ch in s:
        v = sol.get(ch)
        if v is None: return None
        bits += format(v, '06b')
    out = bytearray()
    for i in range(0, len(bits)-7, 8):
        out.append(int(bits[i:i+8], 2))
    return bytes(out)

common_words = [b'http', b'vivo', b'.zip', b'PD2055', b'url', b'json', b'size', b'md5', b'name', b'path', b'ver']
def score(pt):
    s = 0
    for w in common_words:
        s += pt.count(w) * 10
    # letters ratio
    letters = sum(1 for b in pt if 0x41 <= b <= 0x7a)
    s += letters
    return s

scored = []
for sol in solutions[:2000]:
    pt = apply(sol, conf)
    if pt is None: continue
    scored.append((score(pt), sol, pt))
scored.sort(key=lambda x: -x[0])
for sc, sol, pt in scored[:3]:
    print(f'\n=== score {sc} ===')
    print('plaintext head:', pt[:160])
    # show alphabet mapping
    inv = {v:k for k,v in sol.items()}
    print('alphabet(64):', ''.join(inv.get(i,'?') for i in range(64)))

if scored:
    best = scored[0]
    open(r'br\conf_plaintext.txt','wb').write(best[2])
    ptp = apply(best[1], param)
    if ptp:
        open(r'br\param_plaintext.txt','wb').write(ptp)
        print('\nparam plaintext head:', ptp[:200])
