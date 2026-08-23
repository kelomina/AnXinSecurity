# AnXinNetFilter 网络防火墙驱动指南

> 最后更新：2026-07-27
> 适用版本：协议版本 1（`ANX_NET_PROTOCOL_VERSION = 1`）

本文覆盖 `native/net_filter/` 下 WFP Callout 驱动的架构、构建、签名、安装、调试与排障。
规则文件的写法见文末「规则文件」一节。

---

## 一、这是什么

`AnXinNetFilter.sys` 是一个基于 **Windows Filtering Platform（WFP）** 的 callout 驱动，
为 AnXin Security 提供应用级网络流量管控：

| 能力 | 实现层 | 说明 |
|---|---|---|
| 连接级放行 / 拦截 | `ALE_AUTH_CONNECT_V4/V6`、`ALE_AUTH_RECV_ACCEPT_V4/V6` | 按进程、远端 IP/网段、端口、协议裁决 |
| 首次连接弹窗询问 | 同上 + `FwpsPendClassify0` | 挂起连接等待用户点击，超时按配置动作兜底 |
| DNS 域名管控 | `DATAGRAM_DATA_V4/V6` | 解析出站 DNS 查询的 QNAME，命中黑名单则拦截 |
| 内容检查 | `STREAM_V4/V6` | 从 TLS ClientHello 提取 SNI、从明文 HTTP 提取 Host |
| 流量统计 | `ALE_FLOW_ESTABLISHED_V4/V6` + `STREAM` | 按进程累计上下行字节与连接数 |
| 限速 | `STREAM_V4/V6` | 令牌桶，超配额时 `FWPS_STREAM_ACTION_DEFER` 延迟而非丢弃 |

### 最重要的一条设计原则：fail-open

**驱动在以下任何一种情况下都全放行，网络行为与没装这个模块完全一致：**

- 驱动已加载但用户态服务尚未完成版本握手（`UserModeAttached == 0`）
- 用户态服务进程退出或崩溃（内核在 `IRP_MJ_CLEANUP` 中解除接管）
- `networkFirewall.enabled` 为 false
- 挂起决策超过上限（`ANX_NET_MAX_PENDING = 256`）
- 任何分类回调内部出错

理由很直接：一个安全产品把用户的机器弄断网，比漏过一条连接严重得多 —— 断网之后
用户既看不到界面提示，也没有任何办法把它关掉。全放行是唯一可接受的失败姿态。

同一条原则贯穿配置解析：`AnxIoctlSetConfig` 把任何越界的枚举值收敛为 `ALLOW`，
用户态 `build_driver_config` 对无法识别的默认动作同样回落到 `allow`。

---

## 二、目录结构

```
native/net_filter/
├─ include/
│  ├─ anx_net_ioctl.h        用户态/内核共享的二进制契约（IOCTL 码 + 结构体）
│  └─ anx_net_internal.h     驱动内部定义（全局状态、跨模块声明）
├─ src/
│  ├─ driver.c               DriverEntry / Unload / 设备 / IOCTL 派发
│  ├─ wfp.c                  GUID、引擎会话、提供者与子层、BFE 状态订阅
│  ├─ callouts.c             全部 10 个分类回调
│  ├─ rules.c                规则表 / 域名表 / 限速表 / 裁决缓存 / 进程统计
│  ├─ events.c               事件队列 + 取消安全 IRP 队列（倒置调用）
│  ├─ pending.c              挂起决策 + 超时兜底
│  ├─ inspect.c              DNS / TLS SNI / HTTP Host 解析器
│  ├─ util.c                 时间、哈希、CIDR、字符串
│  └─ driver.rc              版本资源
├─ AnXinNetFilter.vcxproj    MSBuild 工程
├─ AnXinNetFilter.inf        INF 安装文件
└─ build_net_filter.bat      构建脚本（含 WDK 检查与签名步骤提示）
```

用户态对应文件：

```
src-tauri/src/utils/net_driver_client.rs    IOCTL 互操作层（anx_net_ioctl.h 的 Rust 镜像）
src-tauri/src/services/firewall_service.rs  编排层：握手、事件泵、裁决队列
src-tauri/src/services/firewall_rules.rs    规则加载与编译
src-tauri/src/commands/firewall.rs          Tauri 命令（11 个）
config/firewall_rules.json                  规则文件
config/app.json → networkFirewall           模块配置
```

---

## 三、构建

### 3.1 前置条件

1. **Visual Studio 2022 或更新版本**，含「使用 C++ 的桌面开发」工作负载
2. **Windows Driver Kit（WDK）**，版本必须与已安装的 Windows SDK 一致

WDK 是否装好，只看一个判据：

```
%ProgramFiles(x86)%\Windows Kits\10\Include\<版本>\km\fwpsk.h
```

这个文件存在才说明内核头文件就位。只装 Windows SDK 是**不够**的 —— SDK 只提供
`um`/`shared`/`ucrt`，没有 `km`，`fwpsk.h` 与 `fwpmk.h` 都在 WDK 里。

> **本仓库当前状态**：系统级 WDK 仍未安装，但 2026-07-27 已使用官方 NuGet
> `Microsoft.Windows.WDK.x64 10.0.28000.2526` 中的 WDK 内容配合本机 SDK
> 10.0.28000.0 完成 `Release|x64` 干净重建，并通过 `InfVerif /w`。
> 该产物未签名、未安装或加载；这只证明源码通过当前编译器，不证明 WFP 功能可用。

安装方式：Visual Studio Installer → 修改 → 单个组件 → 搜索「WDK」；
或从 <https://learn.microsoft.com/windows-hardware/drivers/download-the-wdk> 下载。

### 3.2 构建命令

```bat
cd native\net_filter
build_net_filter.bat Release
```

脚本会先校验 WDK 内核头文件是否存在，缺失时直接报错并给出安装指引，不会留下
一堆看不懂的编译错误。产物：

```
native\net_filter\build\x64\Release\AnXinNetFilter.sys
```

本轮验证产物为 48,640 bytes，SHA-256
`C98E909EF894E89FB78C1A6E22F01568F35AEFC78FADCDB9C3B0FC0A8411C5F3`。
重新构建后哈希会因源码或构建元数据变化而改变，应以当次产物重新计算结果为准。

### 3.3 链接依赖

| 库 | 用途 |
|---|---|
| `fwpkclnt.lib` | WFP 内核 API（`Fwps*` 与 `Fwpm*`） |
| `ndis.lib` | `NdisGetDataBuffer`，数据报层读取载荷 |
| `wdmsec.lib` | `IoCreateDeviceSecure` |
| `uuid.lib` | `FWPM_LAYER_*` GUID 常量 |

---

## 四、签名

### 4.1 开发机（测试签名）

```powershell
# 1. 开启测试签名并重启
bcdedit /set testsigning on

# 2. 生成自签名证书（只需一次）
New-SelfSignedCertificate -Type CodeSigningCert `
  -Subject "CN=AnXin Security Test" `
  -CertStoreLocation Cert:\CurrentUser\My

# 3. 签名
signtool sign /v /fd SHA256 /s My /n "AnXin Security Test" `
  /tr http://timestamp.digicert.com /td SHA256 `
  build\x64\Release\AnXinNetFilter.sys
```

`signtool.exe` 随 Windows SDK 提供，本机路径：
`C:\Program Files (x86)\Windows Kits\10\bin\10.0.28000.0\x64\signtool.exe`

> 测试签名开启后桌面右下角会常驻「测试模式」水印，这是预期行为。

### 4.2 生产环境

Windows 10 1607 之后的 64 位系统要求内核驱动必须经**微软认证签名**才能加载，
自签名和普通 EV 签名都不行。完整流程：

1. 申请 **EV 代码签名证书**（硬件 Token，需企业实名）
2. 注册 <https://partner.microsoft.com/dashboard/hardware>（硬件开发者中心）
3. 用 EV 证书对 `.sys` 做初始签名
4. 制作 `.cab` 提交包（含 `.sys` + `.inf` + 符号）
5. 提交到硬件开发者中心做 **attestation signing**
6. 下载微软回签的驱动，随安装包分发

注意事项：
- `AnXinNetFilter.inf` 的 `DriverVer` 日期必须不早于提交日
- 每次改动 `.sys` 都要重新走一遍提交流程
- INF 里的 `CatalogFile = AnXinNetFilter.cat` 由 `inf2cat` 生成（WDK 提供）

---

## 五、安装与卸载

### 5.1 用 sc.exe（推荐用于开发与调试）

```bat
sc create AnXinNetFilter type= kernel start= demand ^
   binPath= "C:\Program Files\AnXin Security\AnXinNetFilter.sys"
sc start AnXinNetFilter
sc query AnXinNetFilter
```

卸载：

```bat
sc stop AnXinNetFilter
sc delete AnXinNetFilter
```

### 5.2 用 INF

```bat
pnputil /add-driver AnXinNetFilter.inf /install
```

INF 中 `StartType = 3`（SERVICE_DEMAND_START）是**刻意选的**：驱动加载后到
用户态服务完成握手之前处于全放行状态，由服务进程在启动流程里显式拉起驱动，
可以保证「加载即有人负责」。要在开机早期就生效可改为 `1`（SERVICE_SYSTEM_START），
但改之前必须先验证无用户态时的 fail-open 路径确实可靠。

### 5.3 与现有驱动的关系

本仓库已有两个内核驱动，三者互相独立、互不依赖：

| 驱动 | 类型 | 职责 |
|---|---|---|
| `AnXinProcProtect.sys` | WDM + Ob/Ps/Cm 回调 | 进程/线程/窗口站/注册表保护 |
| `AnXinFileProtect.sys` | 文件系统微过滤器 | 关键文件与目录保护 |
| `AnXinNetFilter.sys` | WFP callout | 网络流量管控 |

---

## 六、运行时架构

### 6.1 接管流程

```
服务进程 (SYSTEM)
  │
  ├─ CreateFileW("\\.\AnXinNetFilter")        ← 设备 DACL 限定 SYSTEM + Administrators
  ├─ IOCTL_GET_VERSION                        ← 版本握手，成功即"接管"，驱动开始执行规则
  ├─ IOCTL_SET_RULES / SET_DOMAINS / SET_LIMITS  ← 整表原子替换
  ├─ IOCTL_SET_CONFIG                         ← 启用 + 模式 + 默认动作
  └─ 事件泵线程：阻塞在 IOCTL_GET_EVENT 上     ← 倒置调用
```

**顺序不能颠倒**：必须先装规则再启用，反过来会有一个短暂窗口内所有连接都按
默认动作处理。

### 6.2 倒置调用（内核 → 用户）

用户态投递 `IOCTL_ANX_NET_GET_EVENT`，驱动把 IRP 挂进取消安全队列（CSQ）；
有事件时完成其中一个并回填 `ANX_NET_EVENT`。

事件队列深度 512 条，满了丢**最旧**的并累加丢弃计数，随下一条事件回传给用户态
（`DroppedSinceLast` 字段）。**绝不因为用户态消费不及时而阻塞网络路径。**

### 6.3 弹窗询问的完整链路

```
应用发起 connect()
  → ALE_AUTH_CONNECT classify
  → 缓存未命中、规则判定为 prompt、模式为 prompt
  → FwpsAcquireClassifyHandle0 + AnxPendingAdd + FwpsPendClassify0   [连接挂起]
  → 事件 ANX_NET_EVT_CONNECT_REQUEST 带 DecisionId 上报
  → 服务进程事件泵收到 → emit "network-intercepted"
  → （服务模式下经 IPC 转发到 UI 进程）
  → 独立拦截窗口弹出
  → 用户点击 → handle_network_decision → IOCTL_SET_VERDICT
  → AnxPendingResolve → FwpsCompleteClassify0 + FwpsReleaseClassifyHandle0  [连接恢复]
```

**三条超时兜底**，保证被挂起的连接一定会被完成：

1. 内核 500ms 周期定时器扫描过期项，按 `TimeoutAction` 完成
2. 用户态断开时 `AnxPendingAbortAll(ALLOW)`
3. 驱动卸载时同上

前端倒计时归零时**只收弹窗，不自动提交裁决** —— 驱动的超时扫描已经完成了这次
分类，前端再提交只会撞上一个必然失败的竞态（此时会收到
`STATUS_NOT_FOUND`，用户态把它当作 `alreadyResolved` 正常处理，不报错）。

### 6.4 AppId 哈希的跨语言一致性

规则里的进程匹配靠 `AppIdHash`：对 WFP 的 `ALE_APP_ID`（UTF-16 NT 路径）做
FNV-1a 64 位哈希。两侧实现必须逐字节一致：

- **大小写折叠只处理 ASCII `a`-`z`**，不用 NT 大写表（后者依赖内核版本）
- **每个 WCHAR 按小端两字节喂入**
- **剥掉全部结尾 NUL**
- 结果为 0 时折叠为 1（0 保留表示「匹配任意进程」）

内核侧：`util.c` 的 `AnxHashImagePath` / `AnxHashAppIdBytes`
用户侧：`net_driver_client.rs` 的 `app_id_hash_from_utf16`

用户态取 app id 优先调 `FwpmGetAppIdFromFileName0`（fwpuclnt.dll），因为它返回的
正是 WFP 在 ALE 层交给驱动的那份字节序列。该调用失败时会退化为对原始路径哈希，
此时规则可能匹配不上 —— 编译日志里会有提示。

`net_driver_client.rs` 的单元测试锁定了这个算法（手工展开的期望值 + 大小写不敏感
+ 结尾 NUL 剥离），改动任何一侧都会立刻失败。

---

## 七、调试

### 7.1 内核日志

Debug 构建用 `DbgPrintEx(DPFLTR_IHVNETWORK_ID, ...)` 输出，Release 保留 ERROR 级别。

用 Sysinternals **DbgView.exe**：勾选 `Capture` → `Capture Kernel`，
过滤 `[AnXinNet]`。

如果一条都看不到，先执行：

```
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Debug Print Filter" ^
    /v IHVNETWORK /t REG_DWORD /d 0xF /f
```
（改完需重启）

### 7.2 检查 WFP 对象是否装上

```bat
netsh wfp show state file=wfpstate.xml
```

在 XML 里搜 `AnXin`，应当能看到：
- 一个 provider：`AnXin Security Network Filter`
- 一个 sublayer：`AnXin Security Network Filter SubLayer`
- 每个已注册 callout 对应一条 filter

看不到就说明 BFE 侧对象没装上 —— 检查基础筛选引擎服务（BFE）是否在运行。
驱动会订阅 BFE 状态，BFE 起来后自动补装。

### 7.3 能力位

`IOCTL_GET_VERSION` 返回的 `Capabilities` 是**驱动实际注册成功的层**，
不是编译期能力清单。某一层注册失败不是致命错误，驱动会降级运行并如实上报，
界面上的能力徽章就是从这个字段来的。

排查「DNS 管控不生效」时先看这里有没有 `CAP_DATAGRAM`。

### 7.4 常见问题

| 现象 | 排查方向 |
|---|---|
| 驱动加载失败，`sc start` 报错 577 | 签名问题：未开测试签名，或签名无效 |
| 界面显示「驱动未连接」 | 服务进程不是 SYSTEM/管理员；或驱动服务未启动 |
| 开关打开但一条事件都没有 | `Capabilities` 为 0（callout 全部注册失败）；或 BFE 未运行 |
| 弹窗不出现 | 模式不是 `prompt`；或 `CAP_PEND` 未置位；或事件转发白名单漏了 |
| 规则不生效 | 编译告警里看有没有被跳过；进程路径的 AppIdHash 是否算得出 |
| 卸载驱动报 `STATUS_DEVICE_BUSY` | 有挂起分类未完成 —— 正常路径下 `AnxPendingShutdown` 会先清空 |

---

## 八、规则文件

`config/firewall_rules.json`，采用与 `config/etw_match_rules.json` 一致的
camelCase JSON 风格。

### 8.1 连接级规则

```json
{
  "ruleId": 100,
  "name": "拦截 Telnet 出站",
  "enabled": true,
  "action": "block",
  "direction": "outbound",
  "protocol": "tcp",
  "processPath": "C:\\path\\to\\app.exe",
  "remoteAddress": "10.0.0.0/8",
  "remotePortRange": { "low": 23, "high": 23 },
  "localPortRange": null,
  "matchLoopback": false,
  "log": true,
  "description": "说明文字"
}
```

| 字段 | 取值 | 缺省行为 |
|---|---|---|
| `action` | `allow` / `block` / `prompt` / `continue` | 必填 |
| `direction` | `outbound` / `inbound` / `any` | `any` |
| `protocol` | `tcp` / `udp` / `any` | `any` |
| `processPath` | 可执行文件路径 | 空 = 匹配任意进程 |
| `remoteAddress` | CIDR，如 `10.0.0.0/8`、`::1/128` | 空 = 不限地址 |
| `remotePortRange` | `{ low, high }` 闭区间 | 空 = 不限端口 |
| `matchLoopback` | 本规则是否也作用于回环流量 | `false` |

**匹配语义（容易踩坑的几点）：**

- **匹配顺序 = 数组顺序，首个命中即终止。** 把宽泛的 allow 写在前面会让后面的
  block 永远匹配不到。
- **省略 `/前缀` 按单主机处理**（IPv4 = /32，IPv6 = /128），不是匹配全网。
- **前缀越界直接报错**，不做静默截断 —— 一条本意 `/24` 写成 `/240` 的规则如果被
  悄悄改成 `/32`，作用范围会与作者意图相差极大。
- **默认不作用于回环流量**，需要显式 `matchLoopback: true`。
- `action: "prompt"` 只在 `networkFirewall.mode` 为 `prompt` 时真的弹窗，
  否则回落到 `defaultOutbound` / `defaultInbound`。

### 8.2 域名规则

```json
{
  "ruleId": 1000,
  "domain": "example.com",
  "action": "block",
  "matchType": "suffix",
  "enabled": true
}
```

- `matchType`：`exact` / `suffix` / `contains`
- `suffix` 时 `example.com` 命中 `example.com` 与 `a.example.com`，
  但**不命中** `badexample.com`
- 只接受 `allow` / `block`；`prompt` 在域名层面无从实现
- 需要 `dnsFiltering`（DNS 查询）或 `contentInspection`（SNI/Host）打开才生效

### 8.3 限速

```json
{
  "processPath": "",
  "bytesPerSecIn": 0,
  "bytesPerSecOut": 1048576,
  "burstBytes": 0,
  "enabled": true
}
```

- `processPath` 为空 = 全局限速
- 上下行同时为 0 的条目不会下发给驱动
- `burstBytes` 为 0 时取 1 秒配额作为桶容量
- 需要 `rateLimiting` 打开才生效

### 8.4 容错

单条规则出错只跳过该条并记入编译告警，不让整份规则文件失效 —— 一个手滑写错的
CIDR 不应该导致整台机器失去防护。超出驱动容量上限（规则 512 / 域名 1024 / 限速 64）
的部分会被截断并**明确记录**，绝不静默丢弃。

告警会显示在防火墙页面顶部的黄色卡片里。

---

## 九、模块配置

`config/app.json` 的 `networkFirewall` 段：

```json
{
  "networkFirewall": {
    "enabled": false,
    "mode": "silent",
    "defaultOutbound": "allow",
    "defaultInbound": "allow",
    "promptTimeoutMs": 20000,
    "timeoutAction": "allow",
    "dnsFiltering": false,
    "contentInspection": false,
    "rateLimiting": false,
    "trafficStats": true,
    "allowLoopback": true,
    "cacheTtlMs": 300000
  }
}
```

**默认全部关闭且全放行是刻意的**：防火墙会切断用户网络，必须由用户显式启用。
单纯升级到带这个模块的版本，绝不能默默开始拦截流量。

`allowLoopback` 强烈建议保持 `true`：回环流量承载大量本机进程间通信，
关掉它会造成难以定位的连锁故障。

---

## 十、待办与已知限制

1. ~~本驱动尚未在本机编译验证 —— 开发机缺 WDK（见 §3.1）。补装 WDK 后首次构建
   可能需要处理若干 `TreatWarningAsError` 触发的警告。~~
   **2026-07-28 后更新**：AnXinNetFilter.sys 已通过官方 WDK NuGet 内容 + MSBuild 完成
   `Release|x64` 干净重建（48,640 bytes），并已签名部署到「病毒测试」VM 通过 WFP 攻击
   回归测试（VUL-049/093/094 已修复并验证）；开发机仍无系统级 WDK，构建走 NuGet 包。
2. **DNS 只解析出站查询**，不解析响应。入站方向的 NBL 数据偏移指向传输层头部，
   需要额外的偏移处理；拦截查询已经足以阻断解析，因此暂不处理响应。
3. **TLS SNI 不做跨包重组**：ClientHello 被分片到多个 TCP 段时放弃解析，
   按「未识别域名」处理。绝大多数情况下 ClientHello 落在首个段内。
4. **限速用 interlocked 而非加锁**，允许微小的计量误差（多核同时补充令牌时可能
   多补一次）。对限速器而言可以接受，换来数据路径零锁竞争。
5. **IPv6 地址显示未做零段压缩**，`::1` 会显示成 `0:0:0:0:0:0:0:1`。
6. **规则文件目前只能手工编辑**，界面上还没有规则编辑器，只有「重新加载规则」。

---

## 十一、相关文档

- `docs/etw_rules_guide.md` — ETW 规则写法（JSON 风格与本文一致）
- `docs/continuous-running.md` — 交接日志，每次改动后必须同步更新
- `buglist.md` — 漏洞台账，安全相关改动前必读
- `native/driver/` — 进程保护驱动，IOCTL 客户端写法可参考
- `native/file_protect/` — 文件保护微过滤器
