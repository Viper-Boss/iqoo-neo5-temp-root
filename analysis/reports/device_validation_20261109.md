# PD2055 真机与原厂固件复核（2026-11-09）

基线：`chore/open-source-archive`，`136c6cd93969a2324b481c6e00a18b685b72e891`。
本次工作分支：`codex/neo5-device-validation`。

## 实际状态

手机实测为 V2055A / PD2055，PD2055_A_9.10.3，Android 14，
4.19.152-perf+，安全补丁 2025-09-01。测量前后均为 uid=2000(shell)，
SELinux Enforcing；verifiedbootstate=green、vbmeta.device_state=locked。
**尚未取得 uid=0，尚未解锁 BL。**

原厂内核提取、哈希模型复核、主机单元测试及参数诊断已执行。
只读参数诊断真机 6/6 PASS；主机哈希单元测试 16/16 PASS。
参数诊断中的哈希依赖检查验证的是编译进去的用户态模型，并非动态读取内核哈希函数。

## 新发现：扫描区间错误

配置确认 VA_BITS=39、4 KB 页面。原厂 `__get_free_pages`：

```asm
001f264c: lsl x8, x0, #6
001f2654: orr x8, x8, #0xffffffc000000000
```

这与上游 ARM64 memory.h 的 `PAGE_OFFSET = -2^(VA_BITS-1)` 一致。
`0xffffff8000000000` 是该布局的 VA_START，不能当作 PAGE_OFFSET。
仓库将二者混淆，并在 util.c 中将扫描上限限制为错误基址加 MemTotal。
MemTotal 是可用内存容量，不能给出随机化线性映射中的虚拟地址上界。

采用正确的线性映射候选区间后，独立普通 futex 实验取得以下结果：

- 首次单轮：候选 `ffffffe12aa6cec0`。
- 第二次运行在同一个进程中使用两组不同的 target/probe 映射：
  两轮均得到 `ffffffe2a243cec0`，`INDEPENDENT_ROUNDS_AGREE=yes`，退出码 0。
- 上述地址均不在旧代码扫描的区间中。
- 两次运行属于不同进程，mm 地址不同是预期现象。

这些是时序侧信道与用户态哈希匹配证据，不是直接读取 mm 指针的地面真值，
也不证明 UAF 已触发或提权成功。普通 WAIT/WAKE 碰撞发现不能作为 CVE 触发证据。

本次增加 `exploit/src/ks_probe.c` 和 `make ks-probe`：不链接 main.c、fops.c、
pipe.c、root.c、preload.c；不使用 PI/requeue 操作、不解引用候选内核地址。
使用 4096 个普通等待线程，180 秒自动退出。

最新版进一步按 slab 分配扫描工作，检查每 slab 的 34 个实际对象，统计全区间
匹配数并要求唯一匹配。它同时避免旧扫描器将末端向上取整时溢出为零的问题。
连接恢复后，此最新版也完成了真机验证：两轮均报告
`FULL_RANGE_MATCHES=1 (8388608 slabs, 34 objects/slab)`，两轮唯一候选均为
`ffffffe2a29fc740`，`INDEPENDENT_ROUNDS_AGREE=yes`，退出码 0。
原始日志见 [ks_probe_unique_PD2055_20261109.log](../evidence/ks_probe_unique_PD2055_20261109.log)。
该结果增强了候选定位的可信度，但仍未通过独立内核读取取得地面真值。

构建：

```sh
make -C exploit ks-probe API=34 NDK_ROOT=/path/to/android-ndk-r27c
```

## 新发现：完整 payload 的结构体偏移仍不匹配

以下值由仓库原厂 boot.img 的实际 ARM64 指令得到。
本轮保留完整 payload 配置原样，避免把局部修正误当成已验证的完整移植。

| 项目 | 当前 target.h | 固件证据 | 依据 |
|---|---:|---:|---|
| PAGE_OFFSET / DIRECT_MAP_BASE | 0xffffff8000000000 | 0xffffffc000000000 | __get_free_pages @0x1f2654 |
| MM_OWNER_OFF | 0x310 | 0x348 | mm_update_next_owner @0x45b90 / 0x45d28 |
| TASK_REAL_CRED_OFF | 0x7e0 | 0x818 | get_task_cred @0x73e54；copy_creds @0x742b0 |
| TASK_CRED_OFF | 0x7e8 | 0x660 | prepare_creds @0x74068；copy_creds @0x742b4 |
| TASK_COMM_OFF | 0x7f0 | 0x7e8 | __get_task_comm @0x291098 |
| TASK_PI_LOCK_OFF | 0x8b4 | 0x8d4 | remove_waiter @0xd8d4c |
| TASK_PI_WAITERS_OFF | 0x8c0 | 0x8e0 | remove_waiter @0xd8dac / 0xd8dd8 |
| TASK_PI_BLOCKED_ON_OFF | 0x8d8 | 0x8f8 | remove_waiter @0xd8d7c；prio-chain 交叉引用 |
| TASK_TASKS_OFF | 0x538 | 0x530 | mm_update_next_owner 的全进程链表遍历 |

`__start_init_task` 位于 0x2d80000，但它是段起始符号，不能直接推导它与
init_task 本体地址相等。mm_update_next_owner 通过 `adrp+add` 引用
0x2da0ec0 作为全局进程遍历锚点；该位置加实际 comm 偏移 0x7e8 的数据为
`swapper\0`，而 0x2d80000+0x7e8 为零。这强烈支持 init_task 本体候选
0x2da0ec0，仍应结合重定位记录或更多独立引用复核后再用于内核写入。

其他 fake-task、waiter、pipe、file_operations、凭据内部字段、物理地址转换和
运行期 memstart_addr 尚未完成逐项核验；不能把这里列出的值当作完整可运行的 target。

## 新发现：原厂 ABL 保留专用解锁处理逻辑

从作者本机已有的原厂全量包提取 `firmware-update/abl.elf`。
ELF LOAD 段中发现 UEFI FV，标准 LZMA 流起于文件偏移 0x3078；
解压得到 7,128,136 字节。内部 ARM64 PE 起于解压数据偏移 0xb8，ImageBase=0。

命令指针表包含：

| 字符串 | PE RVA | 相邻处理函数指针 |
|---|---:|---:|
| flashing get_unlock_ability | 0x871d0 | 0x442cc |
| vivo_bsp unlock_vivo | 0x8729a | 0x4265c |
| bbk unlock_vivo | 0x872af | 0x455b0 |

0x4265c 的处理代码先调用 0x42584 检查输入/签名数据，并根据结果跳转。
失败路径包含 `fastboot unlock check Signature fail`；检查函数还包含
`fastboot unlock sigdata size error`。另一处理函数检查设备/AT 模式相关状态。
这证明“解锁代码已完全删除”的表述不成立。更准确的是：标准命令曾返回
unknown command，而固件中仍存在厂商专用、带校验和状态门控的处理路径。

目前尚未确认校验算法及全部输入语义，也没有取得能通过校验的授权数据。
仅发现命令和处理函数不等于获得可用解锁方法。本轮未发送这些解锁命令，
未写 devinfo、frp、ABL、XBL、boot、vbmeta，未擦除数据。

## 样本与构建摘要

| 文件 | SHA256 |
|---|---|
| boot.img | 287d94d700644c6a98bdccc132505f4e9a1fac50a090def9c4a4124ea30bd780 |
| abl.elf | d4f3a6d6ee04b68e2b290b3a0720b74591c1bd9f54f96a0758fe3479d0480b4b |
| abl_decompressed.bin | 4688a75c365628b2d5a9d51e04c42c77e4278eded832c6497380140c7b8c4f21 |
| 真机 diag_params | 7ca031967c02e90103b2cbd8fea3231d9a2f371b36eb537d37e5883cdbb2dd76 |
| 最新 ks_probe（两轮唯一匹配通过） | 3b303bb8575ab26ab8c526fc8b90abecf599f62cc1ccf8685656aece1b23df34 |

上游公式参考：
https://github.com/torvalds/linux/blob/v4.19/arch/arm64/include/asm/memory.h

## 接续工作

1. 已完成：唯一匹配版 ks_probe 真机两轮通过，完整日志已保存，手机仍为 shell/Enforcing/locked。
2. 独立核验完整 payload 所需的所有结构体偏移和运行期地址转换。
3. 完成适配后，才设计有明确停止条件及恢复方案的提权实验；成功标准为实际 uid/euid=0。
4. BL 单独继续追踪厂商签名/模式门控；任何解锁方法还需明确其擦除数据行为。

## 证据索引

- [内核关键字段反汇编](../evidence/kernel_offset_evidence_PD2055.txt)
- [ABL 字符串与指针交叉引用](../evidence/abl_unlock_xrefs_PD2055.txt)
- [ABL 解锁处理函数反汇编](../evidence/abl_unlock_handlers_PD2055.txt)

原始固件镜像、运行期临时文件和编译产物不随本次提交上传。
