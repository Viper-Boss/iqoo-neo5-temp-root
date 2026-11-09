# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import json

conf = open(r'br\recovery\last_server_cJSON.conf','r',encoding='utf-8').read().strip()
param = open(r'br\request_param.txt','r').read().strip()
m = json.load(open(r'br\alphabet_url3.json'))
TRUE_HASH = b'<REDACTED_IMEI_HASH>'

def decode(m, s):
    vals = [m.get(ch) for ch in s]
    out = []
    for g in range(0, len(vals)-3, 4):
        v = vals[g:g+4]
        if None in v:
            out.extend([None]*3); continue
        out.append((v[0]<<2)|(v[1]>>4))
        out.append(((v[1]&15)<<4)|(v[2]>>2))
        out.append(((v[2]&3)<<6)|v[3])   # <<< FIXED: <<6
    r = len(vals)%4
    if r == 2:
        v = vals[-2:]
        out.append((v[0]<<2)|(v[1]>>4) if None not in v else None)
    elif r == 3:
        v = vals[-3:]
        if None not in v:
            out.append((v[0]<<2)|(v[1]>>4)); out.append(((v[1]&15)<<4)|(v[2]>>2))
    return out

raw = decode(m, conf)
txt = ''.join(chr(b) if b is not None and 0x20 <= b <= 0x7e else ('?' if b is None else '#') for b in raw)
print('===== CONF (fixed decode) =====')
print(txt)
print()
print('hash region match:', bytes(raw[341:405]) == TRUE_HASH)

rawp = decode(m, param)
txtp = ''.join(chr(b) if b is not None and 0x20 <= b <= 0x7e else ('?' if b is None else '#') for b in rawp)
print('\n===== PARAM (fixed decode) =====')
print(txtp)
print()
print('param hash match:', bytes(rawp[119:183]) == TRUE_HASH)
