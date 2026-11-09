# HISTORICAL ARCHIVE — 研究过程原始脚本，未按当前工程标准整理。
# 可能包含已被推翻的方法/错误假设；隐私标识已脱敏，本地绝对路径已移除。
# 权威可复现工具见 scripts/ 与 tools/。详见 research/archive/README.md
import json, time
import urllib.request, urllib.error

variants = json.load(open(r"br\name_variants.json"))
base_url = "http://sysupgrade.vivo.com.cn/dapi2.do?fileName=%40"

results = []
for i, name in enumerate(variants):
    url = base_url + name
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "Wget/1.20"})
    try:
        resp = urllib.request.urlopen(req, timeout=20)
        results.append((name, resp.status, dict(resp.headers)))
        print(f"[{i}] {name[-10:]}: {resp.status} CL={resp.headers.get('Content-Length')}")
    except urllib.error.HTTPError as e:
        if e.code != 404:
            print(f"[{i}] {name[-10:]}: HTTP {e.code} {e.headers.get('Location','')}")
            results.append((name, e.code, dict(e.headers)))
        if i % 10 == 0:
            print(f"[{i}] 404 ({name[pos] if (pos:=21) else ''})")
    except Exception as e:
        print(f"[{i}] ERR: {e}")
    time.sleep(0.2)

print("\nNON-404 RESULTS:")
for name, code, hdrs in results:
    print(f"  {name} -> {code} {hdrs.get('Content-Length')} {hdrs.get('Location','')}")
