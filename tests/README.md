# tests/ — 离线安全测试

本目录包含**只读、离线、安全**的自动化检查。CI（`.github/workflows/ci.yml`）
调用它们，你也可以在本地直接运行。

> **红线**：这里的任何测试都**不会**触发 CVE-2026-43499、不会提权、不会接触设备、
> 不会写分区、不会解锁 Bootloader。

## 测试清单

| 脚本 | 作用 | 依赖 |
|------|------|------|
| `privacy_scan.py` | 隐私/密钥扫描（结构性检测标识符字段、token、私钥、开发者路径）| Python 3 |
| `check_docs.py` | Markdown 相对链接/路径检查 | Python 3 |
| `../scripts/verify_kallsyms.py` | kallsyms 6 重独立校验（从 boot.img 复现）| Python 3 + capstone |
| `../scripts/disasm_futex.py` | futex 反汇编证据复现 | Python 3 + capstone |
| `../exploit/Makefile` 的 `test` 目标 | C 单元测试（纯计算）| gcc/make |

## 本地运行

```bash
# 1. 隐私扫描（必须通过，否则不要提交）
python3 tests/privacy_scan.py

# 2. 文档链接检查
python3 tests/check_docs.py

# 3. kallsyms 解析 + 6 重校验（需要仓库内的 boot.img）
python3 scripts/parse_kallsyms.py --from-boot boot.img -o /tmp/kallsyms.txt
python3 scripts/verify_kallsyms.py --from-boot boot.img --kallsyms kallsyms.txt

# 4. futex 反汇编证据
python3 scripts/disasm_futex.py --from-boot boot.img --kallsyms kallsyms.txt --scan-hash

# 5. C 单元测试
cd exploit && make test
```

## 一键（Linux/macOS/WSL）

```bash
set -e
python3 tests/privacy_scan.py
python3 tests/check_docs.py
python3 scripts/verify_kallsyms.py --from-boot boot.img --kallsyms kallsyms.txt
python3 scripts/disasm_futex.py --from-boot boot.img --kallsyms kallsyms.txt --scan-hash > /dev/null
(cd exploit && make test)
```

## 隐私扫描说明

`privacy_scan.py` **不内嵌**任何真实设备标识符，而是**结构性检测**：

- `up.imei=` / `imei=` / `emmcid=` / `serial=` / `android_id=` 字段中
  出现非全零、非 `<REDACTED_*>` 的值
- GitHub token / AWS key / 私钥块 / JWT / Cookie/Authorization 头
- 开发者绝对路径（Windows 用户目录、`/home/<user>/`、本地研究目录）
- 邮箱（仅报告，因为上游版权声明中的联系邮箱是合法且必须保留的）

退出码非 0 表示存在必须修复的硬性问题。
