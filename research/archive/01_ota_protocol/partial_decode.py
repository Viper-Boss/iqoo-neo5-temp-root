# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import random

conf = open(r'br\recovery\last_server_cJSON.conf','r',encoding='utf-8').read().strip()
param = open(r'br\request_param.txt','r').read().strip()

m = {'4':11,'l':59,'W':44,'N':48,'H':9,'C':43,'6':38,'M':50,'c':14,'D':19,'T':12,
     'Z':6,'d':1,'1':39,'y':24,'E':4,'m':7,'9':51,'k':10,'2':25,'h':42,'z':17,'5':26,
     '_':34,'P':35,'r':40,'-':8,'e':49,'0':27,'K':2,'x':54,'g':47,'f':3,'U':46,'R':58,
     '8':36,'X':13}

def decode(m, s):
    out = []
    i = 0
    vals = []
    for ch in s:
        v = m.get(ch)
        vals.append(v)
    # process in 4-groups; unknown values marked None -> decode as '?'
    res = []
    for g in range(0, len(vals)-3, 4):
        v0,v1,v2,v3 = vals[g:g+4]
        if None in (v0,v1,v2,v3):
            res.extend([None]*3)
            continue
        res.append((v0<<2)|(v1>>4))
        res.append(((v1&15)<<4)|(v2>>2))
        res.append(((v2&3)<<4)|v3)
    r = len(vals)%4
    if r == 2:
        v0,v1 = vals[-2:]
        res.append((v0<<2)|(v1>>4) if None not in (v0,v1) else None)
    elif r == 3:
        v0,v1,v2 = vals[-3:]
        if None not in (v0,v1,v2):
            res.append((v0<<2)|(v1>>4)); res.append(((v1&15)<<4)|(v2>>2))
        else:
            res.extend([None,None])
    return bytes((b if b is not None else 0x3f) for b in res), res

pt, raw = decode(m, param)
print('=== PARAM partial decode ===')
print(pt.decode('ascii', errors='replace'))
print()
ptc, rawc = decode(m, conf)
print('=== CONF partial decode ===')
print(ptc.decode('ascii', errors='replace'))
