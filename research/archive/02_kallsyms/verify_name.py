# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import json, string

conf = open(r'br\recovery\last_server_cJSON.conf','r',encoding='utf-8').read().strip()
m = json.load(open(r'br\alphabet_final2.json'))
pt = open(r'br\conf_final2.txt','rb').read()

ALNUM = set((string.ascii_letters + string.digits).encode())

# known-correct byte ranges (verified via anchors/hash):
TRUE_HASH = b'<REDACTED_IMEI_HASH>'
verified_ranges = []
# full hash
ih = pt.find(TRUE_HASH)
verified_ranges.append((ih, ih+64))
# URL prefix
iu = pt.find(b'http://sysupgrade.vivo.com.cn')
verified_ranges.append((iu, iu+28))
# structure
for pat in (b'{"fileLength":"7039074100"', b'","version":"9.10.3","url":"',
            b'&fileLength=7039074100&up.model=PD2055&up.version=PD2055_N_PD2055MA_9.10.3',
            b'&up.tail=&up.hardware=PD2055MA&postStyle=false&httpsSupport=0&fileType=full&up.imei=',
            b'&up.emmcid=', b'","checkString":""}',
            b'<REDACTED_EMMCID>'):
    i = pt.find(pat)
    if i >= 0: verified_ranges.append((i, i+len(pat)))

def in_verified(byte_pos):
    return any(a <= byte_pos < b for a, b in verified_ranges)

# name region
i_name_start = pt.find(b'%40') + 3
i_name_end = pt.find(b'&fileLength', i_name_start)
print(f'name bytes: {i_name_start}..{i_name_end}')

# for each byte in name: which symbols contribute, are they verified?
unverified_syms = set()
for byte_pos in range(i_name_start, i_name_end):
    if in_verified(byte_pos): continue
    bit0 = 8*byte_pos
    for gpos in range(bit0, bit0+8):
        ci = gpos // 6
        sym = conf[ci]
        # does this symbol appear in a verified region?
        appears_verified = False
        for a, b in verified_ranges:
            for p in range(a, b):
                for gp in range(8*p, 8*p+8):
                    c2 = gp // 6
                    if conf[c2] == sym:
                        appears_verified = True
                        break
                if appears_verified: break
            if appears_verified: break
        if not appears_verified:
            unverified_syms.add(sym)

print('unverified symbols in name region:', sorted(unverified_syms))
print('their current values:', {s: m.get(s) for s in sorted(unverified_syms)})

# which bytes are affected by unverified symbols?
affected_bytes = set()
for byte_pos in range(i_name_start, i_name_end):
    bit0 = 8*byte_pos
    for gpos in range(bit0, bit0+8):
        ci = gpos // 6
        if conf[ci] in unverified_syms:
            affected_bytes.add(byte_pos)
print('affected name bytes:', sorted(affected_bytes))
name = pt[i_name_start:i_name_end]
for b in sorted(affected_bytes):
    print(f'  byte {b}: current={chr(name[b-i_name_start])}')

# generate candidate URLs: for the affected bytes, try alnum alternatives
# simple approach: for the '{' byte try x/y/z; also check '=' handling
# The name with URL-decoding: '%40'->@ handled at server; keep as-is
variants = []
base_name = list(name.decode('latin-1'))
# byte 125 ('{') - try x, y, z and other alnums
pos = 125 - i_name_start
for c in string.ascii_letters + string.digits:
    v = base_name.copy()
    v[pos] = c
    variants.append(''.join(v))
print(f'\ngenerated {len(variants)} variants for the broken char')
import json as j
j.dump(variants, open(r'br\name_variants.json','w'))
