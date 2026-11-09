# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import collections, string

def analyze(name, s):
    print(f'===== {name}: {len(s)} chars =====')
    # alphabet check
    alphabet = sorted(set(s))
    print('distinct symbols:', len(alphabet), ''.join(alphabet))
    # residue classes
    classes = {r: collections.Counter(s[i] for i in range(len(s)) if i % 4 == r) for r in range(4)}
    for r in range(4):
        print(f'pos%4=={r}: {len(classes[r])} distinct; top: {classes[r].most_common(8)}')
    # constraints: for base64-of-ASCII: class0 -> values<=31, class1 <=55, class2 <= 61?, class3 any
    s0 = set(classes[0].keys()); s3 = set(classes[3].keys())
    only0 = s0 - s3  # if a symbol appears ONLY in class 0 (and 1,2), it must have value <= 31
    print('symbols never at pos%4==3:', len(only0), ''.join(sorted(only0)))
    # char frequency overall
    freq = collections.Counter(s)
    print('top 12 overall:', freq.most_common(12))
    print('bottom 6:', freq.most_common()[-6:])
    print()

conf = open(r'br\recovery\last_server_cJSON.conf','r',encoding='utf-8').read().strip()
param = open(r'br\request_param.txt','r').read().strip()
analyze('RESPONSE conf', conf)
analyze('REQUEST param', param)

# Do the two share the same substitution? Compare alphabets and frequency profiles
sc = collections.Counter(conf); sp = collections.Counter(param)
common = set(sc) & set(sp)
print('shared symbols:', len(common), 'conf-only:', ''.join(sorted(set(sc)-set(sp))), 'param-only:', ''.join(sorted(set(sp)-set(sc))))
# rank correlation quick look: top-5 of each
print('conf top5 :', [c for c,_ in sc.most_common(5)])
print('param top5:', [c for c,_ in sp.most_common(5)])
