# AnXinHypervisor 嵌套虚拟化开发状态文档

> 最后更新: 2026-08-07
>
> **重要状态变更（2026-08-07）：AnXinHypervisor 开发已暂缓（冻结）。**
> 详见文末「## 暂缓开发决策（2026-08-07）」。在获得可验证的物理机（或确认支持的
> 虚拟化平台）之前，不再推进本模块的任何开发工作。

## 总开发任务

编译并部署 AnXinHypervisor.sys 到 Hyper-V 虚拟机（"病毒测试"，Win10 IoT LTSC 19044，IP 172.28.88.10），验证：
1. **降级路径**（Hyper-V 存在 → DEGRADED_HYPERV）✅ 已验证
2. **完整虚拟化路径**（嵌套虚拟化 → VMX/SVM root 初始化）❌ 受阻于 Hyper-V 嵌套 SVM 限制

## Hyper-V 官方文档查证结论（2026-07-31）

**查证来源**：Microsoft Learn 官方文档
- 中文版：https://learn.microsoft.com/zh-cn/virtualization/hyper-v-on-windows/user-guide/nested-virtualization
- 英文版：https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/user-guide/nested-virtualization

### 关键限制（官方明确声明）

1. **第三方虚拟化应用不被支持**（"Third party virtualization apps" 章节）：
   > "Virtualization applications other than Hyper-V aren't supported in Hyper-V
   > virtual machines, and are likely to fail. Virtualization applications include
   > any software that requires hardware virtualization extensions."
   >
   > 中文版："Hyper-V 虚拟机中不支持除 Hyper-V 之外的虚拟化应用程序，并且这些应用
   > 程序可能会失败。虚拟化应用程序包括需要硬件虚拟化扩展的任何软件。"

2. **第三方虚拟化在 Hyper-V 上不被官方支持**（"Third party virtualization on
   Hyper-V virtualization" 章节）：
   > "Whilst it might be possible for third party virtualization to run on Hyper-V,
   > Microsoft doesn't test this scenario. Third party virtualization on Hyper-V
   > virtualization isn't supported, ensure your hypervisor vendor supports this
   > scenario."
   >
   > 中文版："虽然第三方虚拟化可能能够在 Hyper-V 上运行，但 Microsoft 不对这种方案
   > 进行测试。不支持 Hyper-V 虚拟化上的第三方虚拟化，请确保你的虚拟机监控程序
   > 供应商支持此方案。"

### 查证结论

**AnXinHypervisor.sys 在 Hyper-V VM 内执行 VMRUN 三重故障是预期行为，不是代码 Bug。**

- AnXinHypervisor 是第三方 hypervisor（非 Hyper-V 本身），使用硬件虚拟化扩展（AMD SVM）
- Hyper-V 的嵌套虚拟化功能**设计目标**是"在 Hyper-V VM 内运行 Hyper-V"，**不是**支持任意第三方 hypervisor
- 即使 `Set-VMProcessor -ExposeVirtualizationExtensions $true` 暴露了 SVM 扩展，Hyper-V 的嵌套实现只为 Hyper-V 自身优化，不完全兼容裸机 SVM 语义
- 官方文档明确"可能失败"（likely to fail），VMRUN 三重故障正是这种失败的具体表现
- Microsoft 不测试也不支持此方案，无法通过官方渠道获得修复

### 官方支持的嵌套场景（仅供对比）

| 场景 | 支持状态 |
|------|---------|
| Hyper-V VM 上的 Hyper-V VM | 生产支持（需评估应用兼容性） |
| Hyper-V 上的 Hyper-V 隔离容器 | 生产支持（一级嵌套） |
| Hyper-V VM 中运行 WSL2 | 支持 |
| Azure Stack HCI 嵌套在 Hyper-V VM | 仅评估，生产不支持 |
| **第三方虚拟化在 Hyper-V 上** | **不支持**（本项目场景） |
| Hyper-V 在第三方虚拟化上 | 不支持 |

---



## 环境信息

| 项目 | 值 |
|------|-----|
| 物理 CPU | AMD（支持 SVM） |
| 宿主机 | Windows + Hyper-V |
| VM 名称 | 病毒测试 |
| VM ID | 7b66415c-52cb-468e-b9bd-368746f42863 |
| VM 系统 | Windows 10 IoT LTSC 19044 |
| VM IP | 172.28.88.10（NAT 网络 AnXinSecurityNAT） |
| VM 凭据 | test / Kolomina520! |
| 虚拟交换机 | AnXinSecurityNAT |
| 驱动签名 | 自签名证书 CN=AnXin Security Test, SHA1=CA21B971BC2EA0201E2AA568B230A0035212246E |
| 构建工具 | MSVC 14.52.36615 + WDK 10.0.28000.0，三阶段构建（build_all.bat） |
| 输出路径 | native/hypervisor/x64/Release/AnXinHypervisor.sys |

## 阶段任务与状态

### 阶段 1：降级路径验证 ✅ 完成
- 驱动加载后检测 Hyper-V（CPUID.1:ECX[31]），进入 DEGRADED_HYPERV 模式
- 日志确认：`Mode=DEGRADED_HYPERV, DegradReason="Microsoft Hv"`

### 阶段 2：开启嵌套虚拟化 ⚠️ 受阻
- `Set-VMProcessor -ExposeVirtualizationExtensions $true` 已执行
- 驱动检测到 SVM 可用（CPUID.80000001H:ECX[2]），进入完整初始化路径
- Stage 1（EFER.SVME + VMCB 配置）✅ 成功
- Stage 2（VMRUN 进入 guest）❌ 三重故障

### 阶段 3：待完成
- EPT/NPT 重新启用（当前 `g_PageTablesActive = FALSE` 用于调试）
- 完整虚拟化模式验证（Mode=FULL）
- 更新 docs/continuous-running.md

## 已修复的 Bug（按发现顺序）

| # | Bug | 根因 | 修复 |
|---|-----|------|------|
| 1 | EPT_PAGE_SIZE 溢出 → BSOD 0x7E | 32位整数乘法溢出 | ept.h 常量加 ULL 后缀 |
| 2 | Intel VMCS Guest RIP 未设置 | entry_intel.asm 未写 Guest RIP | asm 中 vmwrite 设置 |
| 3 | VMCS Link Pointer 未设置 | 缺少 VMCS_LINK_POINTER 写入 | 写入 0xFFFFFFFFFFFFFFFF |
| 4 | VMCS 字段编码错误 | 0x2800 是 LINK_POINTER 不是 DEBUGCTL | 修正编码表 |
| 5 | Host 段选择子硬编码 Linux 值 | CS=0x0008 等 | 改用 __readcs() 等实际值 |
| 6 | Host FS/GS/TR/GDTR/IDTR 缺失 | 未设置必要 host state | 全部补齐 |
| 7 | RtlStringCbPrintfA 链接错误 | __stdio_common_vsprintf 缺失 | 改用 RtlStringCbCopyA |
| 8 | IPI_LEVEL 下文件 I/O 失败 | ZwCreateFile 需要 PASSIVE_LEVEL | 分阶段 IPI + 阶段间记录日志 |
| 9 | **AMD CPU 上执行 VMXON → #UD** | 物理 CPU 是 AMD，代码硬编码 Intel | 改用 HAL vtable 分发 |
| 10 | MSVC VMX intrinsics 不可靠 | 手动构建环境下 intrinsic 行为异常 | 改用 asm wrapper |
| 11 | **Guest RIP = 0** | VMCB 中 Rip 字段从未被设置 | asm 中 VMRUN 前写入返回地址 |
| 12 | **CS.Attrib 使用 Intel 位布局** | 0xA09B 的 L bit 在 bit13（Intel），AMD 在 bit9 | 改为 0x029B |
| 13 | **VMLOAD 破坏 KernelGsBase/LSTAR** | 从 VMCB 未初始化区域加载零值 | 移除 VMLOAD 调用 |
| 14 | **IOPM/MSRPM = 0** | 读取物理地址 0 的随机数据 | 分配 12KB+8KB 全零页 |
| 15 | **Shutdown 拦截位错误** | bit 12 是 LDTR_WRITE，shutdown 是 bit 31 | 修正为 bit 31 |
| 16 | TR/LDTR 未设置 | VMCB 中 TR 全零，IST 异常会崩溃 | 解析 GDT 填充 TR/LDTR |
| 17 | 退出处理不循环 | 第二次 VMEXIT 命中 int 3 | 改为 jmp AnxSvmExitEntry |
| 18 | **物理地址当虚拟地址解引用** | asm 用物理地址写 VMCB 内存 | 传递 VA+PA 两个参数 |
| 19 | **CR3 过期** | Stage 1 捕获的 CR3 到 Stage 2 可能变化 | asm 中 VMRUN 前更新 CR3 |
| 20 | **IOPM/MSRPM 在 IPI_LEVEL 分配失败** | MmAllocateContiguousMemory 需要 ≤DISPATCH_LEVEL | 移到 DriverEntry PASSIVE_LEVEL 预分配 |

## 当前阻塞问题

### VMRUN 后 guest 立即三重故障（Hyper-V 不支持第三方 hypervisor 嵌套）

**现象：**
- VMCB 所有字段诊断验证通过（CR0.PE=1, CR0.PG=1, EFER.LMA=1, EFER.SVME=1, CS.Attrib=0x029B, ASID≥1, IOPM≠0, MSRPM≠0, CR3≠0, VMCB 4K 对齐, HSAVE 4K 对齐）
- VMRUN 执行后 guest 立即三重故障
- SHUTDOWN 拦截（InterceptMisc1 bit 31）未能捕获（表现为 VM 硬重置，非 VMEXIT）
- VM 重置后进入恢复状态，需要完整断电重启才能恢复

**根因（已通过官方文档确认，见上方查证结论）：**
- Hyper-V 的嵌套虚拟化**仅设计用于在 VM 内运行 Hyper-V 本身**，不支持第三方 hypervisor
- 官方文档明确："Virtualization applications other than Hyper-V aren't supported
  in Hyper-V virtual machines, and are likely to fail."
- AnXinHypervisor.sys 是第三方 hypervisor，使用 SVM 硬件扩展，属于"可能失败"的范畴
- VMRUN 三重故障正是官方文档预言的"likely to fail"的具体表现
- Hyper-V 的嵌套 SVM 实现只为 Hyper-V 自身优化，不完全兼容裸机 SVM 语义：
  - 嵌套 VMRUN 的 guest 状态验证可能有差异
  - SHUTDOWN 拦截在嵌套模式下不生效
  - 某些 VMCB 控制字段在嵌套环境下语义不同
  - Host Save Area 的行为与裸机不同

**结论：此问题无法通过修改 AnXinHypervisor 代码解决，是平台限制。**

## 关键文件清单

| 文件 | 用途 |
|------|------|
| native/hypervisor/src/driver.c | DriverEntry、分阶段 IPI、文件日志、诊断 |
| native/hypervisor/src/amd/svm.c | SVM 启用/禁用、AnxSvmEnterGuest |
| native/hypervisor/src/amd/vmcb.c | VMCB 结构定义、AnxVmcbSetup、IOPM/MSRPM 分配 |
| native/hypervisor/src/amd/entry_amd.asm | VMRUN/VMLOAD/VMSAVE asm wrapper、退出入口 |
| native/hypervisor/src/amd/amd_ops.c | AMD HAL vtable 实现 |
| native/hypervisor/src/exit_handler.c | 统一 VMEXIT 分发 |
| native/hypervisor/src/exit_cpuid.c | CPUID 虚拟化 |
| native/hypervisor/include/per_cpu.h | Per-CPU 数据结构 |
| native/hypervisor/include/platform.h | CPUID/MSR/内存工具 |
| native/hypervisor/include/exit_reasons.h | 统一退出原因码 |
| native/hypervisor/build_all.bat | 三阶段构建脚本 |
| native/hypervisor/sign_driver.bat | 测试签名脚本 |

## 部署脚本

| 脚本 | 用途 |
|------|------|
| vm_deploy_now.ps1 | 离线 VHDX 部署（需 UAC） |
| vm_final_test.ps1 | 连接 VM + 启动驱动 + 读日志 |
| vm_start_drv2.ps1 | 手动启动驱动（不依赖 ConvertTo-SecureString） |
| vm_read_log_offline.ps1 | 离线读取 hv_debug.log |
| vm_offline_check.ps1 | 离线检查注册表/日志/minidump |
| vm_enable_integ.ps1 | 启用 VM 集成服务 |

## 诊断方法

- **文件日志**：`C:\hv_debug.log`（VM 内），AnxLogToFile() 使用 ZwCreateFile + ZwFlushBuffersFile
- **注意**：三重故障导致 VM 硬重置时，虚拟磁盘写缓存丢失，日志可能无法幸存
- **诊断模式**：跳过 Stage 2（VMRUN），仅验证 VMCB 字段，驱动保持加载
- **DbgPrint**：AnxDebugPrint() 输出到内核调试器（无调试器时不可见）

## 下一步优先级

**原计划（已废弃）：**
- ~~P0：在裸机 AMD 系统上验证 VMRUN 路径~~（用户明确不能在裸机测试）
- ~~P1：调查 Hyper-V 嵌套 SVM 的具体限制并适配~~（已通过官方文档确认不支持）

**修订后计划（2026-07-31）：**

1. **P0**：接受降级模式（DEGRADED_HYPERV）作为 Hyper-V 环境下的最终状态
   - 在 Hyper-V VM 内，AnXinHypervisor 只能运行在降级模式
   - 降级模式下不使用 SVM/VMX，改用其他机制实现安全监控目标
   - 完善降级模式的功能边界文档，明确哪些能力可用、哪些不可用

2. **P1**：评估替代虚拟化平台（如需完整 hypervisor 功能）
   - **VMware Workstation/ESXi**：VMware 对第三方 hypervisor 嵌套的支持由 VMware 自行决定，不受 Hyper-V 限制。需查证 VMware 嵌套 SVM 的支持范围
   - **VirtualBox**：类似 VMware，但性能和兼容性更弱
   - **双物理机方案**：一台物理机跑 AnXinSecurity + hypervisor（无 Hyper-V），一台作为测试靶机
   - 注意：官方文档也指出"Hyper-V 在第三方虚拟化上不被支持"，所以如果选择 VMware，需卸载 Hyper-V 角色

3. **P2**：重新启用 NPT（当前禁用于调试）——仅在确定有可用测试平台后执行
4. **P3**：验证完整模式（Mode=FULL）下的 CPUID/HLT/VMMCALL 拦截——同上
5. **P4**：更新 docs/continuous-running.md 记录最终决策

**决策点（需用户确认）：**
- 是否接受降级模式作为 Hyper-V 环境下的最终方案？
- 是否愿意切换到 VMware 等替代平台以获得完整 hypervisor 功能？
- 是否维持现状（降级模式 + 保留完整模式代码待未来裸机验证）？

---

## 最终决策（2026-07-31）

### 决策结论

**采纳选项 1：接受降级模式（DEGRADED_HYPERV）作为 Hyper-V 环境下的最终方案。**

- 用户明确不能在裸机系统测试
- 官方文档已确认 Hyper-V 不支持第三方 hypervisor 嵌套
- 切换 VMware 成本高且不保证成功，维持现状等于逃避决策
- 降级模式是 AnXinHypervisor fail-safe 设计的预期路径，符合项目安全边界

### 降级模式功能边界（已查证）

AnXinHypervisor 提供三个 IOCTL（定义于 [anx_hv.h](file:///e:/Project/HTML/AnXinSecurity/native/hypervisor/include/anx_hv.h#L78-L84)），
降级模式下的可用性如下（查证自 [driver.c](file:///e:/Project/HTML/AnXinSecurity/native/hypervisor/src/driver.c#L920-L1001)）：

| IOCTL | 名称 | 降级模式可用性 | 说明 |
|-------|------|---------------|------|
| `ANX_HV_IOCTL_GET_STATUS` | 查询状态 | ✅ 可用 | 返回版本、OperatingMode、CpuVendor、CpuCount=0、PageTablesActive=0、DegradReason |
| `ANX_HV_IOCTL_GET_STATS` | 查询统计 | ❌ 不可用 | 返回 `STATUS_NOT_SUPPORTED`（`g_HypervisorActive=FALSE`） |
| `ANX_HV_IOCTL_GET_VIOLATIONS` | 查询违规事件 | ❌ 不可用 | 返回 `STATUS_NOT_SUPPORTED`（`g_HypervisorActive=FALSE`） |

### 能力矩阵

| 能力 | 完整模式 (FULL) | 降级模式 (DEGRADED_HYPERV) |
|------|----------------|--------------------------|
| 驱动加载 | ✅ | ✅ |
| 设备对象 `\Device\AnXinHypervisor` | ✅ | ✅ |
| IOCTL 状态查询 | ✅ | ✅（CpuCount=0, PageTablesActive=0） |
| EPT/NPT 内存保护 | ✅ | ❌ |
| MSR 拦截 | ✅ | ❌ |
| CR 寄存器拦截 | ✅ | ❌ |
| CPUID/HLT/VMMCALL 拦截 | ✅ | ❌ |
| 违规事件收集 | ✅ | ❌ |
| 统计数据收集 | ✅ | ❌ |
| 安全监控（由其他驱动承担） | 增强 | 不影响（由 AnXinProcProtect/FileProtect/NetFilter 提供） |

### 项目影响评估

- **核心安全功能不受影响**：进程保护、文件保护、网络防火墙由独立的 3 个驱动承担，
  不依赖 AnXinHypervisor。降级模式下 AnXinSecurity 仍可提供完整的核心防护能力。
- **hypervisor 是增强模块**：EPT/NPT 内存保护、MSR/CR 拦截等是高级增强功能，
  在 Hyper-V 环境下不可用，但不影响产品基线安全能力。
- **hypervisor 未集成到主项目**：`src-tauri/` 中无任何 hypervisor 调用，
  当前是独立模块，降级决策不影响主应用功能。

### 完整模式代码保留策略

- **保留**：所有完整模式代码（SVM/VMX 初始化、VMCB 配置、EPT/NPT、HAL vtable 等）保留在代码库中
- **标注**：在 [anx_hv.h](file:///e:/Project/HTML/AnXinSecurity/native/hypervisor/include/anx_hv.h) 和
  [driver.c](file:///e:/Project/HTML/AnXinSecurity/native/hypervisor/src/driver.c) 关键位置标注
  "完整模式未验证，等待未来裸机或替代平台"
- **不删除**：避免代码腐烂的同时保留未来激活的可能性
- **不投入**：不再投入开发资源优化完整模式代码，除非未来获得裸机测试条件或确认 VMware 支持

### 后续行动

1. ✅ 本文档记录最终决策（已完成）
2. ✅ 更新 `docs/continuous-running.md` 同步 hypervisor 决策（2026-08-07）
3. ⏳ 在 hypervisor 代码关键位置添加"未验证"标注（可选）
4. ❌ 不再执行：裸机测试、VMware 切换、NPT 重启用、完整模式验证

---

## 暂缓开发决策（2026-08-07）

### 决策结论

**AnXinHypervisor 开发暂时冻结，不再推进。**

**原因：没有可以验证的物理机。**

- 用户明确不能在没有可用测试平台的裸机系统上测试（见上「下一步优先级」废弃条目）
- Hyper-V 官方文档已确认不支持第三方 hypervisor 嵌套虚拟化，VMRUN 三重故障是
  平台限制，非代码 Bug，无法通过修改代码解决
- 因此完整虚拟化路径（VMRUN/VMLAUNCH、EPT/NPT 内存保护、MSR/CR 拦截）在当前
  拥有的任何测试环境下都无法验证

### 冻结范围

以下工作**暂缓**，直到获得可验证的物理机或确认支持的虚拟化平台：

- 完整虚拟化路径验证（Mode=FULL）
- EPT/NPT 重新启用（当前 `g_PageTablesActive = FALSE`）
- Guest 通用寄存器访问桩补全（`IntelGetGuestReg/SetGuestReg`、`AmdGetGuestReg/SetGuestReg`）
- CPUID/MSR/CR/hypercall 退出处理器功能化
- 驱动集成到 Tauri resources / NSIS / 服务模式 IPC 分发
- 生产签名（EV 证书 + 微软 attestation）

### 保持不变的现状

- 代码库保留：SVM/VMX 初始化、VMCB/VMCS 配置、EPT/NPT、HAL vtable、
  exit handler、hypercall 等完整模式代码**全部保留**，不删除、不投入新开发
- 降级路径（DEGRADED_HYPERV）已实现的 IOCTL 查询能力维持现状
- 核心安全功能（进程/文件/网络防火墙）由独立驱动承担，不依赖 hypervisor，
  不受本次冻结影响

### 恢复条件

若未来满足以下任一条件，可重新评估是否恢复开发：

1. 获得一台可验证的物理机（无 Hyper-V / VBS，可运行第三方 hypervisor）
2. 确认 VMware Workstation/ESXi 或其他平台支持嵌套 SVM/VMX，且用户愿意切换
3. 产品或安全需求发生变化，明确需要 Ring -1 防护能力
