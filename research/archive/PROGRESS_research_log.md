<!-- HISTORICAL ARCHIVE: 研究过程中的实时进度日志快照，保留原始记录（含后来被推翻的结论）。隐私标识已脱敏。 -->

# GhostLock → iQOO Neo5 (PD2055) 移植进度

## ✅ 已完成（Round 1-2）

### 1. 固件获取（完整破解链条）
- 用户操作 recovery 联网更新 → bugreport 抓取 recovery 日志 → 提取加密响应
- **破解 vivo 老协议（jvq=1.0.3）**: 替换密码+base64(ASCII明文)，非真加密
- 已知明文锚定 + 爬山 + 重编码 oracle + b2 公式修正 (<<6 不是 <<4)
- 最终获得下载 URL → **7GB 全量固件下载完成** (110 MB/s)
- SHA256 不匹配但 zip 结构完整（317 entries，boot.img 96MB）

### 2. kallsyms 完整解析（109,641 个符号）
- boot.img v2 头解析 → 内核 Image 提取（偏移52，48.4MB）
- vivo 反逆向: 无标准 kallsyms_markers，自定义 u32@8步距 格式
- token_table: 0x2159ecc, token_index: 0x215a2cc (256/256 验证)
- offsets: 0x1f805bc (109,691 条), names: 0x1febb9b
- **target.h 全部关键偏移已产出**（见 target_offsets.txt）

### 3. 构建环境就绪
- WSL: NDK r27c ✓, ghostlock-extract ✓, Rust ✓, JDK17 ✓
- exploit 源码: Q:\Deepseek\_neo5\src\ghostlock-cve-2026-43499-4.19-k40-main

## 🔜 剩余步骤

1. **写 target.h** (用 target_offsets.txt 的值填入 exploit 源码模板)
2. **NDK 构建** preload.so + su_daemon
3. **设备测试**: push → LD_PRELOAD 运行 → fsync 日志在 /sdcard/Download

## 关键数据
- KIMAGE_TEXT_BASE = 0xffffff8008080000 (内核 VA 基址)
- 全部偏移 = 符号地址 - _text（kallsyms offset 字段直接就是）
- INIT_TASK: __start_init_task = 0x2926c40 (init_task 符号不存在，用 __start)
- selinux_enforcing 不存在（4.19 用 selinux_state，enforcing 在 +0）

## 内核 config 关键项（Q:\Deepseek\_neo5\kernel-config.txt, 6458行, /proc/config.gz 可读）
- ARM64_VA_BITS=39, PGTABLE_LEVELS=3, PREEMPT=y, IKHEADERS=y, IKCONFIG=y
- FUTEX_PI=y, CGROUP_SCHED=y, FAIR_GROUP_SCHED=y, MEMCG=y
- SLUB + SLAB_FREELIST_RANDOM + SLAB_FREELIST_HARDENED + **SLUB_MIRROR=y(vivo加固)**
- PANIC_ON_REFCOUNT_ERROR=y, PANIC_ON_OOPS=0(好:oops只杀进程)
- MODULE_SIG_FORCE=y(sha512), STATIC_USERMODEHELPER=/system/bin/vivo_coredump
- VMAP_STACK=y, PAGE_POISONING=y(默认关), KASAN 未开

## 运行时可读面（shell 域实测）
- /proc/config.gz ✓, /proc/slabinfo ✓, /proc/modules ✓(地址清零)
- /sys/kernel/tracing/trace ✓(nop tracer), available_events ✓
  但 kprobe_events/set_ftrace_filter/available_filter_functions 不存在
- /proc/kallsyms ✗, dmesg ✗, /proc/iomem ✗, /sys/kernel/kheaders ✗
- **perf_event_paranoid=-1 ✓✓ (未特权 perf 可采样内核! 可作KASLR/地址泄露通道)**

## exploit 源码（已下载解压）
- Q:\Deepseek\_neo5\src\ghostlock-cve-2026-43499-4.19-k40-main\
- target.h 模板: src\targets\oplus-4.19.157-perf\target.h (K40/alioth, A13)
- 需要: ~24个符号偏移([A] kallsyms直取), 结构体偏移([B] RELA验证), 4.19稳定结构([C])
- build.sh: NDK r27c, PROJECT=xxx, 产出 preload.so + su_daemon
- WSL Ubuntu 已装(构建环境), Windows 无 NDK

## vivo OTA 服务器（已打通）
- 工具: Q:\Deepseek\_neo5\otatracker\VIVO-OTA-Tracker-main\ (自带JRE+unidbg+libvivoseckey.so)
- 调法: 见本文件底部命令
- 实测: PD2055+9.10.3 参数合法, 服务器返回 {"message":"无更新","retcode":210}
  = 9.10.3 是 EOL 最终版, 官方 OTA 不再提供任何包(全量也不行)
- PD2408 对照组正常返回更新+下载链接 → 链路健康

## 当前阻塞 (Goal Round 1 结束时的状态)
**拿不到 PD2055_A_9.10.3 的 boot.img** (唯一权威符号来源)

已排除的所有路径:
- 官方OTA API: 全部版本(9.10.x/9.x/8.x/6.x/1.x)返回 无更新/210, 路线图已清空
- vivo官网: 无固件下载页(客服确认已取消网页下载路径)
- 公开镜像站: vivofirmware(1.10.16) onfix(6.12.3/1.x) gbfirmware(6.9.9)
  firmwaredrive(1.10.16) szjytx(1.7.0) jiuphone(6.12.3) — 全部止步2023年的6.x
- 手机本机: /sdcard 无OTA残留; SELinux 拦截分区读取
- vivo recovery: 无 adb (adb reboot recovery 后设备完全不可见) → dd 路线死
- 搜索引擎: PD2055A_9.10.3 精确搜索无结果; 4.19.152-perf 无结果
- 用户已联系 vivo 官方客服: 确认无卡刷包下载地址, 建议去售后网点

## 唯一剩余路径
用户从其圈子(QQ/TG群/酷安/网盘)获取 PD2055_A_9.10.3 全量包(~4-5GB zip)
或任何 boot.img 内核时间戳为 "Thu Oct 16 14:02:35 CST 2025" 的包

## 工具链状态 (全部就绪, 只等包)
- WSL Ubuntu 26.04: NDK r27c 已下载(663MB) ~/android-ndk-r27c-linux.zip
- ghostlock-app 已克隆 ~/ghostlock-app
- **ghostlock-extract 已构建并验证** ~/ghostlock-app/build/extract/release/ghostlock-extract
  直接支持: boot.img / raw Image / gzip Image / payload.bin / OTA ZIP / HTTP(S) URL
  --format conf|json, 自动恢复内嵌kallsyms, --analysis 分析模式
- exploit 源码: Q:\Deepseek\_neo5\src\ghostlock-cve-2026-43499-4.19-k40-main
- target.h 模板已读透(main.c/slide链/root链已分析)
- 拿到包后流程: ghostlock-extract <URL或zip> --format conf → 填 target.h →
  WSL NDK build.sh → push → LD_PRELOAD 测试(fsync日志在 /sdcard/Download)

## 用户侧动态
- 用户在手机上装了 月虹提权助手(roro.stellar.yuehong)+KernelSU+FYLROOT,
  无线调试已连接, Stellar模式就绪未按"开始提权"
- 已警告: 月虹v1.6.4内置payload库无vivo 4.19(K40的4.19 payload是alioth机型门控)
- Shizuku-NEXT 已激活可用(服务在 shell 域, pid 32207)

## OTA 查询命令模板
```
$base='Q:\Deepseek\_neo5\otatracker\VIVO-OTA-Tracker-main'
$props = @('-Djava.net.preferIPv4Stack=true','-Dfile.encoding=UTF-8',
 '-DDEVICE_TYPE=phone','-DMODEL_SW_VER=PD2055','-DDEVICE_MODEL=V2055A',
 '-DSW_VERSION=9.10.3','-DANDROID_VER=14','-DIS_FULL=true',
 '-DVERBOSE=true','-Dhttps.protocols=TLSv1.2')
& "$base\jre\bin\java.exe" @props -jar "$base\unidbg-android-0.9.10-SNAPSHOT.jar"
# workdir = $base
```

