# 安全政策 / Security Policy

## 项目性质与使用须知

本仓库是 **iQOO Neo5（PD2055）内核安全研究项目**，仅用于：

- 教育、学习、安全研究
- **仅在你自己的硬件上使用**
- 遵守当地法律法规

**本项目不提供、也不应被用于任何未授权的设备访问。**

---

## 支持版本

| 版本 | 支持状态 |
|------|---------|
| master（最新研究） | ✅ 活跃维护 |
| 历史分支（fix/futex-key-layout、analysis/futex-disassembly） | 仅存档参考 |

---

## 报告安全漏洞

本项目研究的漏洞是 **CVE-2026-43499**（rtmutex `remove_waiter()` UAF）。
若你在本仓库代码中发现**新的**安全问题，请：

1. **不要**在公开 Issue 中直接披露可利用细节
2. 通过 GitHub 私有方式或在 Issue 中标注「Security」联系维护者
3. 给予合理修复时间

---

## 隐私与敏感信息

本仓库已执行隐私审计，所有设备唯一标识（IMEI 哈希、emmcid、序列号）均已脱敏为
`<REDACTED_*>` 占位符。**请贡献者遵守：**

- 不要提交含 IMEI/MEID/ICCID/IMSI/手机号/序列号/Android ID 的文件
- 不要提交 token/密钥/密码/cookie/私钥
- 不要提交真实的 ADB bugreport、私人路径、内网地址
- 提交前自查：`grep -RniE "imei|emmc|serial|token|password|private" .`

若发现历史提交中存在隐私泄漏，请参考「Git 历史清理」一节，并**先联系维护者确认**，
不要擅自强制推送改写历史。

### Git 历史清理方案（供维护者参考）

1. `git filter-repo --invert-paths --path <泄露文件>` 或按内容 `--replace-text`
2. 相关 hex 串替换：IMEI 哈希 `7495e721...`、emmcid 串、设备序列号
3. 清理后 `git push --force --all`（需所有协作者重新 clone）
4. 联系 GitHub 清除缓存（`git gc --prune=now` 后再 push 仍可能残留 pack）

> ⚠️ 未获确认前**不得**执行破坏性历史重写或强制推送。

---

## 第三方资源版权边界

| 资源 | 来源/许可 | 状态 |
|------|----------|------|
| 内核 exploit 源码 | NebuSec / CyberMeowfia（GhostLock），Apache-2.0 | 保留原许可 |
| K40 移植版 | yijiacloud/ghostlock-cve-2026-43499-4.19-k40，Apache-2.0 | 保留原许可 |
| boot.img / xbl_config.elf | vivo 官方固件（PD2055_A_9.10.3） | 仅研究用途，受控 |
| tools/vivo_ota.py、scripts/*、docs/* | 本项目原创 | GPLv3 |

### 许可证兼容性说明

- 原创代码/文档采用 **GPLv3**。
- exploit 主体继承上游 **Apache-2.0**，与 GPLv3 相容（Apache-2.0 单向兼容 GPLv3）。
- 仓库根 `LICENSE` 为 GPLv3；`exploit/` 内的上游版权声明保留原位，**未**擅自改写为原创。
- Key 点：GPLv3 与 Apache-2.0 可组合（Apache-2.0 代码可被 GPLv3 项目使用），
  但需保留 Apache-2.0 的版权与声明。本仓库已保留 `exploit/LICENSE_UPSTREAM`（若存在）。

> 附注：`exploit/` 目录下如缺 `LICENSE_UPSTREAM` 文件，需补回上游 Apache-2.0 声明。
> 详见「待办」。

---

## 安全测试边界（CI 红线）

GitHub Actions 与所有自动化测试**只运行离线安全操作**，**绝不**：

- 触发内核漏洞（CVE-2026-43499）
- 执行权限提升 / 提权
- 修改 Bootloader / 分区
- 执行刷机、擦除、持久化 root
- 发起网络请求（OTA 查询等）

CI 仅编译单元测试、静态校验语法、跑纯计算测试、扫描敏感信息、检查文档链接。

---

## 负责任披露

若研究过程中发现 vivo/Qualcomm 产品的新漏洞，请遵循：

1. 优先向厂商（vivo SRC / Qualcomm）报告
2. 遵循既定披露窗口（通常 90 天）
3. 本项目专注于已知 CVE-2026-43499 的移植与教育研究

---

## 免责声明

**本项目仅用于教育研究目的。** 使用本项目代码对任何设备（包括你自己的设备）进行操作，
可能违反设备的保修条款、当地法律或造成设备变砖。作者与贡献者不承担任何责任。