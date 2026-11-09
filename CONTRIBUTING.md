# 贡献指南 / Contributing

感谢你对 iQOO Neo5 内核研究项目的关注！欢迎贡献。

## 贡献前必读

1. **本仓库是安全研究项目**，仅限自有硬件与合法研究用途。
2. 遵守 `SECURITY.md` 的隐私与红线条款。
3. **绝不**在 CI 或提交中执行任何会修改设备状态的代码。

## 可以贡献什么

- ✅ 修复文档/脚本/构建问题
- ✅ 补充新的**离线**分析工具（kallsyms、反汇编、协议分析等）
- ✅ 完善单元测试与 CI
- ✅ 纠正技术结论（附证据：反汇编/实测/独立参考）
- ✅ 报告 typo、链接失效、路径错误

## 不要贡献什么

- ❌ 真实设备唯一标识（IMEI/emmcid/序列号）
- ❌ 凭据、密钥、token、私人路径、内网信息
- ❌ 会**自动**触发漏洞/提权/刷机的代码
- ❌ 未获授权的第三方固件/代码

## 开发流程

```bash
# 1. fork + 克隆
git clone https://github.com/<you>/iqoo-neo5-temp-root.git
cd iqoo-neo5-temp-root

# 2. 建分支
git checkout -b feature/xxx

# 3. 修改 + 测试（离线安全）
cd exploit && make test          # C 单元测试
python3 -m py_compile scripts/*.py tools/*.py   # Python 语法

# 4. 提交（信息清晰）
git commit -m "fix: ..." / "feat: ..." / "docs: ..."

# 5. 推送 + 发 PR
```

## 提交规范

- 类型前缀：`feat` / `fix` / `docs` / `refactor` / `test` / `ci` / `chore`
- 技术结论变更必须**附证据**（反汇编片段 / 实测输出 / 独立参考），不得只改文档。

## 目录约定

| 目录 | 用途 |
|------|------|
| `scripts/` | 权威可复现工具（CLI、--help、只读、不覆盖输入）|
| `scripts/legacy/` | 已取代的历史脚本（标注状态）|
| `research/archive/` | 研究过程原始快照（明确 HISTORICAL）|
| `docs/` | 技术文档（编号 01-10）|
| `analysis/reports/` | 验证报告 |
| `analysis/examples/` | 脱敏示例数据 |
| `analysis/evidence/` | 实测证据（slabinfo 等）|
| `exploit/` | exploit 源码 + 测试 + 构建 |

## 隐私自查清单

提交前运行：

```bash
grep -RniE "imei|emmc|serial|imei_hash|token|password|private|gho_|Q:\\\\|/home/|/Users/" \
  --exclude-dir=.git --exclude='*.img' --exclude='*.elf' .
```

任何命中都需确认是 `<REDACTED_*>` 占位符而非真实值。

## 代码风格

- C：遵循现有 `exploit/` 风格（`pr_info` 日志、4 空格缩进）
- Python：PEP 8，脚本必须支持 `--help`，输入输出用 CLI 参数
- 文档：中文为主（必要时英文），技术术语保留英文

## 提问 / 讨论

- 用 GitHub Issues
- 安全问题见 `SECURITY.md`
- 明确说明设备型号/固件版本/现象/期望，附最小复现

---

再次感谢！你的贡献帮助其他研究者少走弯路。