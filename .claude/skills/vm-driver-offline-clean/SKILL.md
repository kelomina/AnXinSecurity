---
name: vm-driver-offline-clean
description: 从 Hyper-V 来宾 VHD 离线清除 AnXin 内核驱动（关机→挂载 VHD→以 SYSTEM 删除驱动服务键→删除 .sys→分离），用于恢复启动循环或在重装前重置干净状态。Elevated admin required。
---

# 离线清除 AnXin 内核驱动（Hyper-V）

## 何时使用 / When to use

- 来宾 VM 进入无限自动修复 / 启动循环，怀疑 AnXin 内核驱动导致。
- 重装安装包前，需要把来宾恢复到「无 AnXin 驱动、无 AnXin 服务」的干净基线。
- 驱动在内存中无法热卸载（`sc stop` 对内核驱动无效，error 1052），只有重启才卸载 —— 所以**必须离线改盘**才能删服务键。

## 前置 / Prerequisites

- **先关机 VM**（`Stop-VM -Force`），否则 VHD 被占用、挂载失败。
- 在主机上以**管理员**运行脚本（会弹 UAC）。非管理员删服务键直接被 ACL 拒绝。
- 挂载 VHD 需要磁盘管理权限 —— 本 skill 的脚本用 `Mount-VHD`，Elevated 即可。
- 来宾的 SYSTEM/SOFTWARE 蜂巢路径在挂载后为 `<X>:\Windows\System32\config\SYSTEM` / `SOFTWARE`。

## 流程 / Procedure

1. **关机**：`Stop-VM -Name <vm> -Force`，确认 `State = Off`。
2. **确认活动磁盘**：`(Get-VMHardDiskDrive -VMName <vm>).Path` —— 快照恢复后活动盘是快照自己的 `.avhdx`（子盘），父盘不能挂。把该路径传给脚本。
3. **跑离线清理脚本**（管理员）：
   ```powershell
   powershell -ExecutionPolicy Bypass -File offline-clean.ps1 -VhdPath "D:\Virtual Hard Disks\病毒测试_<GUID>.avhdx"
   ```
   脚本会做四件事（详见 scripts/offline-clean.ps1）：
   - 挂载 VHD、给系统分区分配盘符 X；
   - 写一个 `.cmd` helper 到 `C:\Windows\Temp\anxin-rx-helper.cmd`：`reg load` SYSTEM/SOFTWARE → `reg delete` 所有 `AnXin*` 服务键（ControlSet001/002）→ `reg unload`；
   - 用 **`schtasks /create /ru SYSTEM`** 创建一次性计划任务并以 SYSTEM 身份运行该 helper（这是绕过服务键 ACL 的关键）；
   - 删 `System32\drivers\AnXin*.sys`，`Dismount-VHD` 分离。
4. **主机侧验证**：无残留 `HKLM:\RX_SYSTEM` / `HKLM:\RX_SOFTWARE`（泄漏说明 unload 失败，改动没 flush）；`Get-Disk` 无该 VHD。
5. **开机验证**：`Start-VM`，等 guest 起来后确认全部 AnXin 服务已不存在（`sc query` → 1060，或服务注册表键已删）且 `C:\Windows\System32\drivers` 下无 `AnXin*.sys`。

## 为什么非这样不可 / Key gotchas

- **管理员不能离线删服务键**：把 SYSTEM 蜂巢 `reg load` 到 HKLM 后，`reg delete HKLM\RX_SYSTEM\...\Services\<svc>` 与 `Set-ItemProperty` 都返回 access denied —— Windows 给 `Services\*` 键配了 ACL，**只有 SYSTEM** 能删。所以必须用 `schtasks /run /ru SYSTEM` 让 SYSTEM 上下文执行删除。文件不受此限制。
- **`reg unload` 必须在 VHD 仍挂载时做**：unload 时才把改动 flush 回 `.avhdx`；若已 Dismount 再 unload 会 access denied，改动丢失。
- **驱动 `.sys` 可以删即使驱动已加载**：内核映射文件后不保持文件句柄，离线删（或进系统后用 `del /f`）均可。
- **盘符对 SYSTEM 任务全局可见**：挂载分配的盘符（X:）在会话 0 的 SYSTEM 任务里一样能访问，helper 直接用 `X:\...` 路径即可。不需要 `\\?\Volume{GUID}`（实测 GUID 取到过空值）。
- **`schtasks /tr` 引号**：helper 路径要 `\"C:\Windows\Temp\anxin-rx-helper.cmd\"`，否则带空格路径解析错。
- **helper 幂等**：`reg load` 若蜂巢已加载会报错，但 `reg delete` 仍作用于已加载蜂巢、`reg unload` 仍会 flush —— 重复跑/从脏状态跑都安全。
- **脚本必须是纯 ASCII**（PS 5.1 + cmd helper 双栈），中文注释也要规避，否则编码错乱。

## 运行脚本说明

- 入口：`scripts/offline-clean.ps1`（参数化，`-VhdPath` 必填；`-ServiceNames`/`-DriverFiles`/日志路径可覆盖）。
- 已实测通过：2026-08 于 `病毒测试` VM，全部 AnXin 服务键删除、4 个 `.sys` 删除、开机后全部服务 1060、无残留。
- 日志：`C:\Users\Saika\AppData\Local\Temp\anxin-offline-clean.log`（流程）+ `anxin-rx.log`（SYSTEM 任务内部输出，含每条 reg 的结果）。

## 相关 / Related

- 本 skill 配套的来宾内清理（驱动已加载时删服务）见旧脚本 `anxin-clear-old.ps1`；离线方案始终优先。
- 安装器挂起修复见 `build/nsis-hooks.nsh`：POSTINSTALL 里 `--protect-dir/--protect-pid` 从阻塞的
  `nsExec::ExecToStack`（`nsExec::Exec` 也同样阻塞，实测证实）改为**内建非阻塞 `Exec`**（立即返回、
  不等子进程），避免旧驱动 IOCTL 阻塞导致 app 不退出、安装器永久挂起。Tauri 捆绑的 nsExec 插件
  **没有 `ExecAsync`**，内建 `Exec` 才是可用的非阻塞指令。
