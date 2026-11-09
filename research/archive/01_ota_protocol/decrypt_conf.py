# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import sys, base64, zlib
sys.path.insert(0, r'vivoota')
from vivo_ota_tracker import (aes_decrypt, aes_encrypt, base64_url_decode,
                               AES_KEY_KV1, AES_KEY_KV2, AES_IV)

conf = open(r'br\recovery\last_server_cJSON.conf','r',encoding='utf-8').read().strip()
print('conf len:', len(conf))

full = base64_url_decode(conf)
print('decoded:', len(full), 'bytes')
print('head hex:', full[:24].hex())
hl = int.from_bytes(full[:2], 'big')
print('headerLen:', hl)

body = full[hl:]
print('body len:', len(body), 'mod16:', len(body) % 16)

for kv, key in ((1, AES_KEY_KV1), (2, AES_KEY_KV2)):
    try:
        from Crypto.Cipher import AES as _A
        from Crypto.Util.Padding import unpad
        c = _A.new(key, _A.MODE_CBC, AES_IV)
        d = c.decrypt(body)
        print(f'--- KV{kv} raw decrypt head: {d[:48].hex()}')
        try:
            up = unpad(d, 16)
            s = up.decode('utf-8', errors='replace')
            print(f'=== KV{kv} DECRYPTED ({len(up)} bytes) ===')
            print(s)
        except Exception as e:
            print(f'KV{kv} unpad fail: {e}; raw text guess:', d[:64])
    except Exception as e:
        print(f'KV{kv} fail: {e}')

# also try whole-package decrypt (skip 0)
print('\n=== try full package (skip=0) ===')
for kv, key in ((1, AES_KEY_KV1), (2, AES_KEY_KV2)):
    from Crypto.Cipher import AES as _A
    c = _A.new(key, _A.MODE_CBC, AES_IV)
    d = c.decrypt(full)
    try:
        from Crypto.Util.Padding import unpad
        up = unpad(d, 16)
        print(f'KV{kv}: {up[:200]}')
    except Exception:
        printable = sum(1 for b in d[:200] if 32 <= b < 127)
        print(f'KV{kv}: unpad fail, printable ratio {printable/200:.2f}')
