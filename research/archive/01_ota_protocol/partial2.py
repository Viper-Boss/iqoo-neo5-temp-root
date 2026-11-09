# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import sys
m = {'4':52,'l':55,'W':13,'N':3,'H':36,'C':53,'6':25,'M':19,'c':28,'D':50,'T':12,
     'Z':24,'d':32,'1':57,'y':6,'E':8,'m':56,'9':51,'k':20,'2':38,'h':21,'z':34,
     '5':22,'_':17,'P':49,'r':5,'-':4,'e':35,'0':54,'K':16,'x':27,'g':61,'f':48,
     'U':29,'R':23,'8':9,'X':44}

conf = open(r'br\recovery\last_server_cJSON.conf','r',encoding='utf-8').read().strip()
param = open(r'br\request_param.txt','r').read().strip()

def decode_partial(m, s):
    vals = [m.get(ch) for ch in s]
    out = []
    for g in range(0, len(vals)-3, 4):
        v = vals[g:g+4]
        if None in v:
            out.extend([None]*3); continue
        out.append((v[0]<<2)|(v[1]>>4))
        out.append(((v[1]&15)<<4)|(v[2]>>2))
        out.append(((v[2]&3)<<4)|v[3])
    r = len(vals)%4
    if r == 2:
        v = vals[-2:]
        out.append((v[0]<<2)|(v[1]>>4) if None not in v else None)
    elif r == 3:
        v = vals[-3:]
        if None not in v:
            out.append((v[0]<<2)|(v[1]>>4)); out.append(((v[1]&15)<<4)|(v[2]>>2))
        else:
            out.extend([None,None])
    return out

for name, s in (('PARAM', param), ('CONF', conf)):
    raw = decode_partial(m, s)
    txt = ''.join(chr(b) if b is not None and 0x20 <= b <= 0x7e else ('?' if b is None else '#') for b in raw)
    print(f'=== {name} ===')
    print(txt)
    print()
