# 08 - 构建与测试 / Build and Testing

> **文档状态**: ✅ 已完成  
> **最后更新**: 2026-11-09  
> **作者**: Viper-Boss

---

## 概述

本章节记录项目的构建环境、构建命令、测试方法、依赖清单和常见错误。

---

## 环境要求

### 主机端（单元测试 / 脚本验证）

```
- Ubuntu 22.04+ / WSL2 Ubuntu（推荐）
- Python 3.8+ 
- pip 包: capstone（反汇编）、python-magic（可选）
- gcc 或 clang（编译 C 单元测试）
```

### 交叉编译（构建 aarch64 exploit）

```
- Android NDK r27c 或更新
- 目标架构: aarch64-linux-android (API 35)
```

### 设备端（可选，仅诊断）

```
- adb（Android Debug Bridge）
- 设备已启用 USB 调试
```

---

## 构建命令

### 1. 单元测试（无需 NDK）

```bash
cd exploit
make test
# 输出:
#   16/16 passed, 0 failed  (futex hash + state table)
#   4/4 passed, 2 skipped   (diag_params host mode)
```

### 2. 完整 Payload（需要 NDK）

```bash
cd exploit
export NDK_ROOT=~/android-ndk-r27c
make preload
# 输出: build/pd2055-4.19.152-perf/bin/preload.so
# sha256: 712d1fd1...
```

### 3. 无 Root Payload（需要 NDK）

```bash
cd exploit
export NDK_ROOT=~/android-ndk-r27c
make noroot-payload
# 输出: build/pd2055-4.19.152-perf/bin/preload_noroot.so
# ⚠️ 仍触发 CVE，仅去掉最终提权阶段，非只读！
```

### 4. 只读诊断工具（需要 NDK）

```bash
cd exploit
export NDK_ROOT=~/android-ndk-r27c
make diag
# 输出: build/pd2055-4.19.152-perf/bin/diag_params
# ✅ 真正只读：不触发 CVE，只读 /proc/slabinfo + /sys
```

### 5. 全部构建

```bash
cd exploit
export NDK_ROOT=~/android-ndk-r27c
make preload noroot-payload diag
```

---

## 测试方法

### 单元测试

```bash
cd exploit && make test
```

测试项目（16 项）：
1. futex_key_t 布局（mm@0, addr@8, offset@16）
2. 哈希与反汇编参考一致（7/7 用例）
3. 哈希依赖 mm
4. 哈希依赖地址
5. jhash2 顺序敏感性
6. target ≠ upstream 顺序
7. KernelSnitch 状态名映射（6/6）
8. mm_struct slab 算术

### kallsyms 验证

```bash
python3 scripts/verify_kallsyms.py --from-boot boot.img --kallsyms kallsyms.txt
# 9 项验证（计数/单调/markers/段序/聚簇/ARM64 抽查）
```

### Python 脚本语法检查

```bash
find scripts tools -name "*.py" -exec python3 -m py_compile {} \;
# 所有脚本应无语法错误
```

---

## 依赖清单

### requirements.txt

```
capstone>=5.0.0
```

### 构建依赖（非 pip）

| 工具 | 版本 | 用途 |
|------|------|------|
| Android NDK | r27c+ | aarch64 交叉编译 |
| gcc/clang | 任意现代版本 | 主机单元测试 |
| make | 任意 | 构建管理 |
| Python | 3.8+ | 脚本工具 |
| adb | 最新 | 设备通信（可选） |

---

## 常见错误

### 1. `make: *** No rule to make target 'preload'`

**原因**: 不在 `exploit/` 目录下。

**解决**: `cd exploit && make preload`

### 2. `ERROR: Android NDK clang not found`

**原因**: NDK_ROOT 未设置或路径不对。

**解决**:
```bash
export NDK_ROOT=~/android-ndk-r27c
# 或
export ANDROID_NDK_HOME=/path/to/ndk
```

### 3. `ModuleNotFoundError: No module named 'capstone'`

**原因**: capstone 未安装。

**解决**:
```bash
pip install capstone
# WSL 中可能需要:
pip install --break-system-packages capstone
```

### 4. `make test` 中 `error: expected ')' before`

**原因**: 宏参数格式错误（CHECK 宏的第一个变参必须是格式字符串）。

**解决**: 已修复，如遇到请报 issue。

### 5. `futex_hash.h` 中的 `_Static_assert` 失败

**原因**: futex_key_t 布局被意外修改（回归）。

**解决**: 检查是否误改了 mm@0/address@8 顺序。运行 `make test` 确认。

---

## GitHub Actions CI

### 工作流文件

`.github/workflows/ci.yml` 执行：

1. **Python 语法检查**: 所有 `.py` 文件
2. **C 单元测试**: `make test`（无需 NDK）
3. **脚本帮助检查**: 验证 `--help` 正常
4. **隐私扫描**: 检查敏感模式（IMEI/token/路径）
5. **文档链接检查**: 验证内部链接有效

### 安全边界

CI **不会**执行：
- ❌ 内核漏洞利用
- ❌ 权限提升
- ❌ Bootloader 操作
- ❌ 分区写入
- ❌ 网络请求（OTA 查询）

CI **只执行**安全的离线测试和静态验证。

---

## 构建 SHA256 记录

| 产物 | SHA256 |
|------|--------|
| preload.so (FULL) | 712d1fd1f1912332... |
| preload_noroot.so | df314690efe18f97... |
| diag_params | 3ca59b8beb591d57... |

---

## 参考

- Makefile: `exploit/Makefile`
- CI: `.github/workflows/ci.yml`
- 测试: `exploit/tests/test_futex_hash.c`
- 诊断: `exploit/src/diag_params.c`
