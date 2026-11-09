# 失败尝试记录 / Failed Attempts

> **本文件记录所有失败实验、错误假设与已证伪的结论**，供后人避免重蹈覆辙。
> 每条均标注状态：`HISTORICAL`（历史事实） / `INCORRECT`（已被证伪） / `SUPERSEDED`（已被取代）。
> 保留在此是为了透明，**不是**推荐做法。

---

## F1: futex 哈希第一次错误判断 —「只哈希 2 个 u32，不含 mm」

- **状态**: `INCORRECT`（已证伪）
- **时间**: 2026-11-09 03:24（初稿）
- **错误结论**: 内核 `hash_futex()` 只用 `sizeof(key->both.word)/4 = 2` 个 u32，不含 mm 指针。
- **错误根因**: 误读了 `sizeof(key->both.word)` 为 8 字节（=2 u32），把它当成了完整哈希长度；
  实际上内核的哈希长度表达式是 `(sizeof(word)+sizeof(ptr))/4 = 4` 个 u32。
- **正确结论**（见 F4）: 哈希长度 = 4 u32，且**包含 mm**。

## F2: futex 哈希第二次错误判断 —「从 key+8 哈希，仍不含 mm」

- **状态**: `INCORRECT`（已证伪）
- **时间**: 2026-11-09 04:17（commit e34852b）
- **错误结论**: 内核从 `&key->both.word`（被误认为是 key+8）哈希 4 个 u32 = `[addr, offset, padding]`，不含 mm。
- **错误根因**: 单元测试的**参考结构体 `kernel_futex_key_t` 也抄反了**（ptr@0, word@8），
  与错误的 exploit typedef 犯了同一个错 → "错代码验证错代码"假通过。
  这正是"不要用错误参考实现验证错误代码"这一教训的实证。
- **教训**: 参考实现必须独立转录/独立推导，不能从被测代码复制。

## F3: futex 哈希第三次判断 —「对照上游 v4.19 → address@0/[addr,mm]」

- **状态**: `SUPERSEDED`（对上游正确、对目标设备错误）
- **时间**: 2026-11-09 04:30（commit 43460fa，fix/futex-key-layout 分支，已并 master）
- **错误结论**: 把用户态 typedef "修正"成上游 v4.19 布局 `address@0/mm@8`。
- **错误根因**: **上游源码 ≠ 设备内核**。上游 v4.19 确实用 address@0/mm@8（判断本身没错），
  但 vivo 4.19.152-perf+ **保留了旧 mainline 布局 mm@0/address@8**。以上游为参照的"修复"
  对这个设备反而引入错误。
- **教训**: 移植必须反汇编**设备实际内核**，不能仅对照上游源码。

## F4: 最终正确结论（反汇编 vivo 固件）

- **状态**: `✅ CORRECT`（当前采用）
- **时间**: 2026-11-09 04:48
- **结论**: vivo = **mm@0 / address@8 / offset@16**，哈希 = `jhash2([mm,addr], offset)` 从 key+0 读 4 u32。
- **证据**: `analysis/reports/futex_disassembly_report.md`（get_futex_key + get_task_mm + 12 处种子）。
- **原始 K40 exploit 的 typedef（mm@0）本就与 vivo 匹配**，F3 才是错的。

---

## F5: kallsyms 初版解析 — 109,641 符号（错位 50 条）

- **状态**: `HISTORICAL`（已被 109,687 版取代）
- **错误现象**: 解析出 109,641 个符号，`init_task`/`commit_creds`/`_text` 等"缺失"。
- **错误根因**: names_start 偏晚 50 条，导致名字与偏移错位配对（第 i 个名字对应第 i+50 个偏移）。
- **发现方法**: 检查 num_syms（u32 @ 0x1feb900 = 0x1AC77 = 109,687）与 offsets 表尾部，
  再用 markers 交叉验证暴力搜索正确 names_start。
- **深层教训**: "解析出 N 个名字" ≠ "配对正确"。必须用 markers + 段序分层等独立校验。

## F6: boot.img 提取「52 字节 vendor 头」误判

- **状态**: `INCORRECT`（已证伪）
- **错误**: 早期认为 kernel blob 前有 52 字节 vivo 头，并据此 `kernel_raw[52:]`。
- **真相**: ARM64 magic 在标准位置 0x38，**vendor wrapper = 0 字节**；
  头字段 `text_offset=0x80000/image_size/flags` **完好未清零**。
- **影响**: 旧镜像比正确镜像小 52 字节，所有文件偏移错位；符号偏移（kallsyms 值）不受影响。
- **修正**: `scripts/extract_boot_image.py` 正确提取 `kernel_raw[0:]`。

## F7: MM_STRUCT_SZ 0x340 与 slab order 重置

- **状态**: `HISTORICAL`（已修复）
- **错误**: `MM_STRUCT_SZ=0x340`（K40 默认值）→ 候选步长错误；`mm_slab_order` 重试时重置为 0。
- **真相**: PD2055 设备 `mm_struct` objsize=**960 (0x3C0)**、34 obj/slab、8 pages → **order 3**。
- **证据**: `analysis/evidence/slabinfo_PD2055.txt`（`/proc/slabinfo` 实测）。
- **修复**: target.h 改 0x3C0；util.c 保持 MM_ORDER(3)。

## F8: base64 第三字节 `<<4` bug

- **状态**: `HISTORICAL`（已修复）
- **错误**: vivo OTA 解码第三字节用 `(v2&3)<<4`。
- **真相**: 标准 base64 是 `(v2&3)<<6`。`<<4` 让每第三个字节解密错误，结果"几乎对但不对"。
- **耗时**: ~3 小时排查。**这是本项目最隐蔽的单一 bug。**

## F9: 设备端「碰撞成功但 mm 定位失败」（尚未复测）

- **状态**: `HISTORICAL`（根因已定位，设备端未复测）
- **现象**: `found 3 collisions`（阶段 1 成功）→ `KernelSnitch mm_struct leak failed`（阶段 2 失败），12 次重试全败。
- **根因分析**（事后）: F7 的两个参数错误（MM_STRUCT_SZ、slab order）+ 当时的 futex 布局判断混乱。
- **当前状态**: 参数已修复、哈希已反汇编确认正确，但**未在真机重测**。**不宣称已解决。**

---

## 教训汇总

1. **上游源码 ≠ 设备内核**：每次移植必须反汇编设备固件确认，不能默认等价。
2. **参考实现必须独立推导**：单元测试的参照物不能从被测代码复制，否则"错验错"假通过。
3. **"数量对了" ≠ "配对对了"**：kallsyms 之类必须用 markers/段序等独立交叉验证。
4. **最隐蔽的 bug 是"几乎对"**：`<<4` vs `<<6`，结果每第 3 字节错一个，极难发现。
5. **保留失败过程**：本文件即为此目的。后人不至于把历史错误再当正确实现。

---

相关：`CHANGELOG.md`、`RESEARCH_TIMELINE.md`、`KNOWN_LIMITATIONS.md`、`docs/06_futex_hash_research.md`、`docs/04_kallsyms_recovery.md`。