# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import random, sys
from collections import Counter

# self-test: build a substituted-base64 of a known plaintext and test the pruner
plaintext = '{"message":"ok","retcode":0,"url":"https://sysupdxdl.vivo.com.cn/upgrade/oem/files/test.zip","size":123456,"md5":"abc"}'
import base64
STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
b64 = base64.urlsafe_b64encode(plaintext.encode()).decode().rstrip('=')
print('b64 len:', len(b64))

# random permutation
perm = list(range(64)); random.seed(42); random.shuffle(perm)
mapping = {STD[i]: STD[perm[i]] for i in range(64)}  # value i -> symbol
# build ciphertext: each b64 char has value v=STD.index(ch) -> substituted symbol STD[perm[v]]
cipher = ''.join(STD[perm[STD.index(ch)]] for ch in b64)
print('cipher head:', cipher[:60])

# value domain of a cipher symbol s = position of s in STD... no wait:
# substitution: cipher symbol c represents the VALUE v where STD[v] == original char.
# original char = STD[v]; cipher char = STD[perm[v]].
# So for cipher symbol c: v such that STD[perm[v]] == c → v = perm_inverse[STD.index(c)]
truth = {c: perm.index for c in STD}  # unused

def ok_byte(b):
    return 0x20 <= b <= 0x7e or b in (10,13,9)

syms = sorted(set(cipher))
val_domain = {s: set(range(64)) for s in syms}
groups = [cipher[i:i+4] for i in range(0, len(cipher)-3, 4)]

def prune_once(domains, group_list):
    changed = False
    for g in group_list:
        sy = list(g)
        for pos in range(4):
            s = sy[pos]
            if len(domains[s]) <= 1: continue
            others = [list(domains[o]) if o != s else None for o in sy]
            newdom = set()
            for v in domains[s]:
                ok = False
                lists = []
                total = 1
                for idx, o in enumerate(sy):
                    if idx == pos: lists.append([v])
                    else: lists.append(list(domains[o])); total *= len(lists[-1])
                if total > 100000:
                    ok = True
                else:
                    for v0 in lists[0]:
                        for v1 in lists[1]:
                            for v2 in lists[2]:
                                for v3 in lists[3]:
                                    b0 = (v0<<2)|(v1>>4)
                                    b1 = ((v1&15)<<4)|(v2>>2)
                                    b2 = ((v2&3)<<4)|v3
                                    if ok_byte(b0) and ok_byte(b1) and ok_byte(b2):
                                        ok = True; break
                                if ok: break
                            if ok: break
                        if ok: break
                if ok: newdom.add(v)
            if newdom != domains[s]:
                if not newdom: return changed, False
                domains[s] = newdom
                changed = True
    return changed, True

for it in range(20):
    changed, ok = prune_once(val_domain, groups)
    if not ok:
        print('WIPEOUT at iter', it); sys.exit(1)
    if not changed: break

sizes = Counter(len(val_domain[s]) for s in syms)
print('domain size histogram:', dict(sizes))
import math
total = 1
for s in syms: total *= max(1,len(val_domain[s]))
print('search space ~ 2^%.1f' % math.log2(total))

# can the true solution be recovered by hill climb?
truth_map = {}
for c in STD:
    # cipher symbol c appears when original value v = ... find v: STD[perm[v]] == c
    v = [i for i in range(64) if STD[perm[i]] == c][0]
    truth_map[c] = v
# check truth satisfies domains
bad = [s for s in syms if truth_map[s] not in val_domain[s]]
print('truth violations:', bad)

def decode(m, s):
    vals = [m[ch] for ch in s]
    out = []
    for i in range(0, len(vals)-3, 4):
        v0,v1,v2,v3 = vals[i:i+4]
        out.append((v0<<2)|(v1>>4)); out.append(((v1&15)<<4)|(v2>>2)); out.append(((v2&3)<<4)|v3)
    r = len(vals) % 4
    if r == 2:
        out.append((vals[-2]<<2)|(vals[-1]>>4))
    elif r == 3:
        out.append((vals[-3]<<2)|(vals[-2]>>4)); out.append(((vals[-2]&15)<<4)|(vals[-1]>>2))
    return bytes(out)

print('truth decode check:', decode(truth_map, cipher)[:50])
