# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import re
from collections import Counter

conf = open(r'br\recovery\last_server_cJSON.conf','r',encoding='utf-8').read().strip()
param = open(r'br\request_param.txt','r').read().strip()

def repeat_distances(s, name, minlen=6):
    print(f'===== {name} =====')
    # find all repeated substrings of length >= minlen
    seen = {}
    reps = Counter()
    for L in range(minlen, 20):
        pos = {}
        for i in range(len(s)-L+1):
            sub = s[i:i+L]
            pos.setdefault(sub, []).append(i)
        for sub, ps in pos.items():
            if len(ps) >= 2:
                reps[sub] = ps
    # merge: keep maximal repeats
    maximal = {}
    for sub, ps in reps.items():
        # check if extending kills it
        if any(sub != k and sub in k for k in reps):
            continue
        maximal[sub] = ps
    for sub, ps in sorted(maximal.items(), key=lambda x: -len(x[0]))[:12]:
        dists = [ps[i+1]-ps[i] for i in range(len(ps)-1)]
        mod4 = [d % 4 for d in dists]
        mod3 = [d % 3 for d in dists]
        print(f'"{sub}" x{len(ps)} at {ps[:6]} dists={dists[:6]} mod4={mod4[:6]} mod3={mod3[:6]}')

repeat_distances(conf, 'CONF')
repeat_distances(param, 'PARAM')

# Also: 1:1 mapping hypothesis — most frequent symbols
print('\nfreq conf:', Counter(conf).most_common(10))
print('freq param:', Counter(param).most_common(10))
