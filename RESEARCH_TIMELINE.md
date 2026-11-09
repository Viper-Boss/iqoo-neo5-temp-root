# 研究时间线 / Research Timeline

> 按时间顺序记录完整研究历程，含所有成功与失败。确切时刻为 Asia/Shanghai。

## 2026-11-08（Day 1）

| 时间 | 事件 | 结果 |
|------|------|------|
| ~23:00 | 评估 Bootloader 解锁可能性 | ❌ `fastboot flashing unlock` = unknown command，vivo 已删除命令 |
| ~23:15 | 分析市面上临时 Root 工具（月虹/GhostLock/DirtyFrag 等 ~15 款） | ❌ 均不支持 vivo 4.19（Neo5 太老，非 GKI） |
| ~23:30 | 确认 recovery 无 adbd，无法 dd 分区 | ❌ 此路不通 |
| ~23:45 | 确认公开镜像站无 9.10.3（EOL 最终版） | ❌ 无公开下载 |

## 2026-11-09（Day 2）

| 时间 | 事件 | 结果 |
|------|------|------|
| ~00:00 | 用户在 recovery 触发"联网更新"，抓取 OTA 流量日志 | ✅ 获得加密请求/响应样本 |
| ~00:20 | 发现 OTA 协议是「替换密码 + base64」，开始破解字母表 | ✅ 结构判定 |
| ~00:40 | 已知明文攻击（用 IMEI 哈希/版本串锚定符号值） | ✅ 锚点建立 |
| ~01:00 | 发现并修复 base64 第三字节 `<<6`（曾错写 `<<4`） | ✅ 关键 bug 修复 |
| ~01:20 | CP-SAT + 爬山 + 重编码 oracle 收敛出 60 符号字母表 | ✅ 协议破解完成 |
| ~01:40 | 下载 7GB 全量固件（110 MB/s 直连 vivo CDN） | ✅ 固件到手 |
| ~02:00 | 提取 kernel_Image（**错误地砍掉 52 字节**，后来修正） | ⚠️ 有误 |
| ~02:15 | kallsyms 初版解析（109,641 符号，**names 错位 50 条**） | ⚠️ 有误 |
| ~02:34 | 构建第一版 exploit，设备端测试 | 碰撞成功，mm 定位失败 |
| ~03:00 | 发现 MM_STRUCT_SZ 0x340 错（应 0x3C0）、slab order 重置 bug | ✅ 定位参数错误 |
| ~03:13 | 整理 v1 文档 + 源码发布（91f79fb） | ✅ 首版开源 |
| ~03:24 | futex 哈希第一次错误结论："只哈希 2 u32 不含 mm" | ❌ 错误 |
| ~03:46 | kallsyms 修复：num_syms=0x1AC77=109,687 + markers 429/429 | ✅ 解析修正 |
| ~04:17 | futex 哈希第二次错误结论："key+8，仍不含 mm"（e34852b） | ❌ 错误（参考结构体抄反） |
| ~04:30 | futex 哈希第三次判断：对照上游 v4.19 → address@0/[addr,mm]（43460fa） | ⚠️ 对上游对、对 vivo 错 |
| ~04:48 | **反汇编 vivo boot.img 真实内核** | ✅ 铁证 |
| | get_futex_key→mm@0/addr@8、get_task_mm→mm@0x580、12 处 0xdeadbeff | ✅ 定论 |
| ~05:00 | futex 模型回退到 mm@0/[mm,addr]，16/16 单测（独立反汇编参考） | ✅ 正确 |
| ~05:10 | boot.img 提取修正（wrapper=0，头字段完好）+ kallsyms 6 重验证 | ✅ 修正误判 |
| ~05:30 | 修复 kernelsnitch_strings 缺项（指定索引初始化） | ✅ |
| ~05:40 | scripts/ 去绝对路径，权威流水线可复现（字节级一致） | ✅ |
| ~06:15 | 提交 analysis/futex-disassembly（38a4dd5），推送分支 | ✅ |
| ~06:30 | 开始开源工程化整理（本任务） | 🔄 进行中 |

## 关键转折点

1. **00:20** 判断出 OTA 是替换密码而非真加密 → 破解成为可能
2. **01:00** `<<6` bug → 解密结果从"几乎对"变"完全对"
3. **03:46** num_syms + markers → kallsyms 从"错位"变"逐字节验证"
4. **04:48** 反汇编设备固件 → futex 三次错误判断终结
5. **04:48** 核心教训落地：**上游源码 ≠ 设备内核**

## 状态摘要

- ✅ 完成：协议破解、固件获取、kallsyms、反汇编、构建、单测
- ⏳ 未完成：真机 KernelSnitch 定位、uid=0、BL 解锁（不可行）
- ❌ 失败并记录：3 次 futex 判断、109641 错位、52 字节截断、MM_STRUCT_SZ

详见 `FAILED_ATTEMPTS.md`、`KNOWN_LIMITATIONS.md`、`docs/10_known_issues.md`。