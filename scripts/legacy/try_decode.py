import base64, binascii, sys

conf = open(r'samples/recovery/last_server_cJSON.conf','r',encoding='utf-8').read().strip()
print('conf len:', len(conf))

# hypothesis 1: strip '-' and '_' then standard base64
s1 = conf.replace('-','').replace('_','')
print('stripped len:', len(s1), 'mod4:', len(s1)%4)
def try_dec(label, s):
    for pad in range(4):
        sp = s + '='*pad
        try:
            b = base64.b64decode(sp, validate=False)
        except Exception:
            continue
        if len(b) >= 12:
            hl = int.from_bytes(b[0:2],'big')
            ver = int.from_bytes(b[10:12],'big')
            print(f'{label} pad={pad}: {len(b)} bytes, headerLen={hl}, version@10={ver}')
            if ver in (1,3):
                print('  >>> VALID ENVELOPE VERSION! <<<')
                print('  head hex:', b[:24].hex())
            return b
    return None

b1 = try_dec('stripped', s1)

# hypothesis 2: base64url as-is
b2 = None
try:
    b2 = base64.urlsafe_b64decode(conf + '='*((4-len(conf)%4)%4))
    print('urlsafe:', len(b2), 'bytes, head:', b2[:24].hex())
    hl = int.from_bytes(b2[0:2],'big'); ver = int.from_bytes(b2[10:12],'big')
    print('  headerLen=', hl, 'version=', ver)
except Exception as e:
    print('urlsafe fail:', e)

# hypothesis 3: treat - and _ as + and / (standard b64) — same as urlsafe decode with translate
s3 = conf.replace('-','+').replace('_','/')
b3 = try_dec('translated', s3)
