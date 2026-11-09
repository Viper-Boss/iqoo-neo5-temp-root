# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import json, string

base_url = open(r'br\DOWNLOAD_URL.txt').read().strip()
pt = open(r'br\conf_final2.txt','rb').read()
i_name_start = pt.find(b'%40') + 3
name = pt[i_name_start:i_name_end].decode('latin-1') if (i_name_end := pt.find(b'&fileLength', i_name_start)) else None

# byte 125 is '{' — position in name = 125 - 104
pos125 = 125 - i_name_start
print('name:', name)
print('char at 125-position:', name[pos125])

# generate variants: replace char at pos125 with every alnum
variants = []
for c in string.ascii_letters + string.digits:
    v = name[:pos125] + c + name[pos125+1:]
    variants.append(v)

# also compute smart constraint: what values of I/V give valid bytes at both 119/125
conf = open(r'Q:\Deepseek\neo5\\br\\recovery\\last_server_cJSON.conf'.replace('neo5\\\\br','br'),'r',encoding='utf-8').read().strip()
m = json.load(open(r'Q:\Deepseek\br\alphabet_final2.json'.replace('br\\','neo5\\br\\')))
# find I and V positions in conf
pos_I = [i for i, ch in enumerate(conf) if ch == 'I']
pos_V = [i for i, ch in enumerate(conf) if ch == 'V']
print('I at chars:', pos_I)
print('V at chars:', pos_V)

# bits: byte 119 (bits 952-960), byte 125 (bits 1000-1008)
# determine which bits of these bytes come from I/V
for byte_pos, label in ((119, 'byte119'), (125, 'byte125')):
    bit0 = 8*byte_pos
    contrib = []
    for gpos in range(bit0, bit0+8):
        ci = gpos//6
        ch = conf[ci]
        bpos_in_val = gpos % 6
        contrib.append((ch, bpos_in_val, gpos-bit0))
    print(f'{label} bit contributions: {contrib}')

json.dump(variants, open(r'Q:\Deepseek\neo5\br\name_variants.json'.replace('neo5\\br','_neo5\\br'),'w'))
print(f'{len(variants)} variants saved')
