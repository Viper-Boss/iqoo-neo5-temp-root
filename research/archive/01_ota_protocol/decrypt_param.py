# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import base64, sys
sys.path.insert(0, r'vivoota')
from vivo_ota_tracker import AES_KEY_KV1, AES_KEY_KV2, AES_IV
from Crypto.Cipher import AES

param = open(r'br\request_param.txt','r').read().strip()
print('param len:', len(param))
C = base64.urlsafe_b64decode(param + '='*((4-len(param)%4)%4))
print('decoded:', len(C), 'bytes')
print('head hex:', C[:32].hex())
hl = int.from_bytes(C[:2],'big')
print('headerLen field:', hl)
print('bytes[10:12] ver:', C[10:12].hex())
print('bytes[12] tokenLen:', C[12])
# show possible token if V1
tl = C[12]
if 0 < tl < 64:
    try:
        print('token guess:', C[13:13+tl].decode('utf-8',errors='replace'))
    except Exception:
        pass

def try_aes(data, label):
    if len(data) % 16 != 0:
        print(f'{label}: len {len(data)} not 16-aligned (mod {len(data)%16})')
        # try truncating / with header offset adjustments
        return None
    out = None
    for name, key in (('KV1',AES_KEY_KV1),('KV2',AES_KEY_KV2)):
        d = AES.new(key, AES.MODE_CBC, AES_IV).decrypt(data)
        good = sum(1 for b in d if 32 <= b < 127 or b in (10,13,9))
        print(f'{label} {name}: printable {good/len(d):.2f} head: {d[:48]}')
        if good/len(d) > 0.9:
            out = (name, d)
    return out

# envelope variants
for skip in (hl, 16, 0, 44, 45, 46, 47, 48, 49, 50, 51):
    body = C[skip:]
    if len(body) >= 16 and len(body) % 16 == 0:
        print(f'--- skip {skip}: body {len(body)} bytes (16-aligned!) ---')
        try_aes(body, f'skip{skip}')
    else:
        # check nearby
        pass

# find all 16-aligned windows
print('\n=== aligned windows search ===')
for skip in range(0, 64):
    body = C[skip:]
    if len(body) % 16 == 0 and len(body) > 16:
        for name, key in (('KV1',AES_KEY_KV1),('KV2',AES_KEY_KV2)):
            d = AES.new(key, AES.MODE_CBC, AES_IV).decrypt(body)
            good = sum(1 for b in d if 32 <= b < 127 or b in (10,13,9))
            if good/len(d) > 0.9:
                print(f'HIT skip={skip} {name}: {d[:200]}')
