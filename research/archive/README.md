# research/archive/ — 历史研究脚本与数据归档

> **状态标注：HISTORICAL / PARTIALLY SUPERSEDED**
>
> 本目录保存研究过程中的**原始脚本与中间数据**，按任务要求"不随意删除旧工具"而归档。
> 它们记录了真实的探索路径（包括错误假设与失败尝试），但：
>
> 1. **不保证可运行**——多数脚本是一次性探索代码，输入文件可能未随仓库分发；
> 2. **部分结论已被推翻**——尤其是 kallsyms 早期解析（109,641 错位版本）与
>    futex 布局的前两次错误判断，详见根目录 `FAILED_ATTEMPTS.md`；
> 3. **隐私标识已脱敏**——所有 IMEI 哈希 / emmcid / 序列号替换为 `<REDACTED_*>`
>    占位符，开发者本地绝对路径已移除；
> 4. **权威可复现工具在 `scripts/` 与 `tools/`**——复现研究请从那里开始，
>    本目录仅供理解研究过程与二次考古。

## 目录结构

```
01_ota_protocol/   vivo OTA 协议(jvq 1.0.3)破解全过程脚本（28 个）
02_kallsyms/       kallsyms 定位/解析/修复的迭代脚本（38 个）
03_disassembly/    ARM64 反汇编取证脚本（capstone，9 个）
04_misc/           其他辅助
data/              中间数据：字母表演化(12版)、解密样本(19份,已脱敏)、
                   62变体清单、下载URL、旧结构元数据
PROGRESS_research_log.md  实时进度日志快照（含后来被推翻的结论，原样保留）
```

## 01_ota_protocol — 破解方法论演化顺序（推荐阅读顺序）

| 阶段 | 脚本 | 内容 |
|------|------|------|
| 1. 结构分析 | `try_decode.py`, `partial_decode.py`, `partial2.py` | 发现重复子串间距 ≡0 (mod 4) → 判定 base64 类编码 |
| 2. 已知明文 | `anchor_attack.py`*, `final_anchors.py`, `exact_derive.py` | 用 IMEI 哈希/版本串锚定符号值（*权威版在 scripts/legacy/）|
| 3. 约束求解 | `cpsat_solve.py`*, `chain_solve.py`, `solve.py`, `solve2.py` | OR-Tools CP-SAT 求双射约束 |
| 4. 爬山优化 | `anneal.py`, `crack.py`, `final_crack.py`, `final2.py`*, `final3.py`, `final4.py` | 剩余未知符号爬山 |
| 5. Oracle 验证 | `oracle_test.py`, `repeat_test.py`, `selftest.py`, `reencode_test.py`* | encode(decode(x))==x 全量验证 |
| 6. 关键 bug 修复 | `fixed_decode.py` | **`<<6` 而非 `<<4`**（第三字节公式）|
| 7. URL 变体爆破 | `gen_variants.py`, `try_variants.py`, `url_anchor.py`, `url_anchor2.py`, `url_final.py` | fileName 中未知字符的 62 变体 HEAD 探测（'k' 命中 HTTP 200）|
| 8. 收尾 | `victory.py`, `finish.py`*, `finish2.py`, `repair.py`*, `reconcile.py`, `clean_final.py`, `decrypt_conf.py`, `decrypt_param.py` | 最终字母表导出与全文解密 |

带 * 的脚本在 `scripts/legacy/` 有同名版本（本目录是原始快照）。

## 02_kallsyms — 解析迭代史（含错误版本，用于吸取教训）

| 阶段 | 脚本 | 状态 |
|------|------|------|
| 结构定位 | `find_base.py`, `find_markers.py`, `find_ti.py`, `find_tt.py`, `final_structure.py`, `final_structure2.py`, `scan_kernel.py`, `scan_offsets.py` | 定位 token 表/索引/markers |
| **错误解析** | `parse419.py`, `align_final.py`, `lookup_syms.py`, `full_parse.py`, `parse_all.py`, `parse_final.py`, `true_parse.py`, `my_kallsyms.py` | **SUPERSEDED/INCORRECT**：names 起点错位 50 条 → 109,641 符号、名字-偏移错配、init_task/commit_creds "缺失"假象 |
| 排错过程 | `check_alignment.py`, `tail_offsets.py`, `find_missing.py`, `find_missing2.py`, `dbg_names.py`, `name_fix.py`, `verify_name.py`, `peek*.py`, `dump_before.py` | 定位错位根因 |
| **正确解析** | `fix_names_start.py`（发现 num_syms=0x1AC77 与 names_start=0x1feb9cc[旧镜像]）, `verify_final.py`（markers 429/429）| 权威版 = `scripts/parse_kallsyms.py` + `scripts/verify_kallsyms.py` |
| 偏移生成 | `final_offsets.py`, `gen_target_fixed.py`, `near_bootid.py` | 权威版 = `scripts/gen_target_offsets.py` |
| 镜像切割 | `cut_image.py`, `extract_boot.py`, `findboot.py` | 含**错误的 52 字节截断**（见 FAILED_ATTEMPTS）；权威版 = `scripts/extract_boot_image.py` |

## 03_disassembly — futex 取证（本轮结论的证据生成脚本）

| 脚本 | 用途 |
|------|------|
| `disasm_tool.py` | 偏移映射验证（_text@0/wake_up_process/get_futex_key 序言）|
| `analyze_getfutexkey.py` | 自动追踪 key 寄存器存储 → mm@0/addr@8/@16 |
| `dump_gfk.py`, `dump_gfk2.py` | get_futex_key 全函数/私有路径反汇编 |
| `dump_futex_wake.py` | futex_wake 内联 hash_futex（种子 0xdeadbeff + key+0..12 加载）|
| `dump_futex_init.py` | hashsize = roundup_pow_of_two(256×cpus) |
| `dump_get_task_mm.py` | task_struct.mm@0x580 交叉验证 |
| `scan_hash_sites.py` | 全 futex 区扫描 12 处内联 hash 种子点 |
| `analyze_sub.py` | 辅助分析 |

权威整合版 = `scripts/disasm_futex.py`（一条命令复现全部证据）。

## data/ — 中间数据

- `alphabet*.json`（12 个版本）：字母表从残缺到完整的演化快照
  （`alphabet.json`→`_cpsat`→`_victory`→`_done`→`_repaired`→`_final`→`_final2`✓→`_final3`→`_exact`→`_url*`）
- `name_variants.json`：URL fileName 未知字符的 62 变体清单
- `DOWNLOAD_URL.txt`：最终固件下载 URL（用户已授权公开）
- `kallsyms_struct_old_image.json`：**旧 52 字节截断镜像**的结构元数据（仅历史参考）

> 🔒 **已从本目录移除：19 份 OTA 密文的中间/最终解密样本**（`conf_*.txt`、
> `param_*.txt`、`request_param.txt`）。原因：这些样本处于各解码阶段，部分仍以
> 乱码形式残留设备标识符（IMEI 哈希 / emmcid 片段），脱敏无法做到完全可靠，
> 而其对研究的边际价值低于隐私风险。**协议结构、字母表与破解方法均已完整保留**
> （见 `docs/02_ota_protocol_analysis.md` 与 `alphabet*.json`），足够复现破解过程；
> 若需样本，请用自己的设备重新抓取（方法见文档）。唯一保留的示例是
> `analysis/examples/decrypted_ota_response.sample.txt`（已完整脱敏）。

## 已知问题汇总

见根目录 `FAILED_ATTEMPTS.md`（错误全记录）与 `KNOWN_LIMITATIONS.md`（未决事项）。
