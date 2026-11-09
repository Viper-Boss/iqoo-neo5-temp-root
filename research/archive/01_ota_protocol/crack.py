# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import base64, itertools, string
from urllib.parse import unquote

conf = open(r'br\recovery\last_server_cJSON.conf','r',encoding='utf-8').read().strip()
C = base64.urlsafe_b64decode(conf + '='*((4-len(conf)%4)%4))
print('cipher bytes:', len(C))

def printable_ratio(b):
    if not b: return 0
    good = sum(1 for x in b if 32 <= x < 127 or x in (10,13,9))
    return good/len(b)

# ---------- 1. known-plaintext XOR crack (repeating key) ----------
knowns = [b'https://', b'PD2055', b'vivo-survival_1.0-UpdateFull_package.zip',
          b'sysupgrade.vivo.com.cn', b'{"retcode"', b'.zip', b'vivo', b'"url"',
          b'size', b'md5', b'fds.vivo', b'http://']
print('\n=== repeating-key XOR known-plaintext crack ===')
found = []
for S in knowns:
    for i in range(0, len(C)-len(S)+1):
        keyfrag = bytes(a ^ b for a,b in zip(C[i:i+len(S)], S))
        # try key lengths that divide the fragment position consistently: test KL = 1..len(keyfrag)
        for KL in range(1, 33):
            if len(keyfrag) < KL and i % KL != 0:  # need full coverage only if aligned
                pass
            # build full key by repeating fragment at phase (i % KL)
            key = bytearray(KL)
            ok = True
            for j in range(len(keyfrag)):
                pos_in_key = (i + j) % KL
                if key[pos_in_key] != 0 and key[pos_in_key] != keyfrag[j]:
                    ok = False; break
                key[pos_in_key] = keyfrag[j]
            if not ok or all(k==0 for k in key):
                continue
            # decrypt with this partial key (unknown positions = 0 -> garbage there, ok)
            D = bytes(C[j] ^ key[j % KL] for j in range(len(C)))
            r = printable_ratio(D)
            if r > 0.85:
                found.append((r, S, i, KL, bytes(key), D[:120]))
for r,S,i,KL,key,head in sorted(found, reverse=True)[:6]:
    print(f'ratio={r:.2f} plain={S[:20]} pos={i} keylen={KL} key={key.hex()}')
    print('  head:', head)

# ---------- 2. position-based keystreams ----------
print('\n=== position-based keystream tests ===')
tests = {
  'xor i': lambda i: i & 0xff,
  'xor (i*7)': lambda i: (i*7) & 0xff,
  'xor 0x5a+i': lambda i: (0x5a + i) & 0xff,
  'xor 0xa5^i': lambda i: (0xa5 ^ i) & 0xff,
  'sub i': None,
}
for name, f in tests.items():
    if f is None: continue
    D = bytes(C[j] ^ f(j) for j in range(len(C)))
    r = printable_ratio(D)
    if r > 0.8:
        print(f'{name}: ratio {r:.2f} head: {D[:80]}')
    else:
        print(f'{name}: ratio {r:.2f}')

# ---------- 3. string-level transforms ----------
print('\n=== string-level transforms ===')
B64STD = string.ascii_uppercase + string.ascii_lowercase + string.digits + '+/'
B64URL = string.ascii_uppercase + string.ascii_lowercase + string.digits + '-_'
def shift_str(s, k):
    tbl = B64URL
    out = []
    for ch in s:
        if ch in tbl:
            out.append(tbl[(tbl.index(ch)+k) % 64])
        else:
            out.append(ch)
    return ''.join(out)
for k in range(1, 64):
    s2 = shift_str(conf, k)
    try:
        b = base64.urlsafe_b64decode(s2 + '='*((4-len(s2)%4)%4))
        r = printable_ratio(b)
        if r > 0.85:
            print(f'shift {k}: ratio {r:.2f} head: {b[:100]}')
    except Exception:
        pass
# reversed string
rev = conf[::-1]
try:
    b = base64.urlsafe_b64decode(rev + '='*((4-len(rev)%4)%4))
    print('reversed-string decode ratio:', printable_ratio(b), b[:60])
except Exception as e:
    print('reversed fail:', e)
# reversed bytes
rb = C[::-1]
print('reversed-bytes ratio:', printable_ratio(rb), rb[:60])
