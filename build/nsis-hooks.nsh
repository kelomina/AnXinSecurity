; NSIS 安装/卸载钩子
;  NSIS install/uninstall hooks
;
; Tauri 2.0 的 NSIS 模板使用的宏名与执行时机（已从模板反编译确认）：
;  Tauri 2.0 NSIS template macros and their timing (confirmed from the decompiled template):
; - NSIS_HOOK_PREINSTALL:    Section Install 开头。$INSTDIR 已确定且已建目录，
;                            但安装包里的文件（主 exe、bundle.resources）**尚未释放**。
; - NSIS_HOOK_POSTINSTALL:   文件全部释放、注册表与快捷方式写完之后。
; - NSIS_HOOK_PREUNINSTALL:  Section Uninstall 开头，文件尚未删除。
; - NSIS_HOOK_POSTUNINSTALL: 文件/注册表/快捷方式全部删除之后。
;
; 本文件实现的时间线 / Timeline implemented here:
;   [PREINSTALL]   询问用户是否安装内核防护 → 若是，释放并加载进程保护驱动 → 释放文件保护驱动文件
;                  Ask whether to install kernel protection → if yes, drop and load the process
;                  protection driver, then drop the file protection driver binary
;   [POSTINSTALL]  若选择了内核防护：注册文件保护 minifilter → 保护安装目录与驱动服务键
;                  → 保护安装进程 PID → 无论是否选择内核防护都注册用户态服务
;                  If kernel protection was chosen: register the file protection minifilter,
;                  protect the install dir and driver service keys, protect the installer PID.
;                  The user-mode service is always registered.
;   [PREUNINSTALL] 解除自保护 → 停止并删除用户态服务与两个驱动服务 → 必要时安排重启删除
;                  Release self-protection, stop and delete the user-mode service and both driver
;                  services, scheduling reboot deletion when needed
;
; 设计红线 / Hard rules:
; - 驱动加载失败**绝不能让安装失败**。内核驱动只是纵深防御的一层；加载不了（签名、
;   策略、旧系统）时用户态防护完整可用，安装必须照常完成。
;   A driver failure must never fail the install: the kernel driver is one layer of defence in
;   depth, and user-mode protection stays fully functional without it.
; - 用户主动卸载必须能成功。自保护是为了挡住外部篡改，不是把软件变成删不掉的东西。
;   A user-initiated uninstall must always succeed. Self-protection guards against external
;   tampering; it must never make the product unremovable.

!include "x64.nsh"

; ============================================================================
; 完成页面配置 — 在 MUI_PAGE_FINISH 之前预定义（hooks 在模板顶部被 !include）
;  Finish page config - pre-defined before MUI_PAGE_FINISH (hooks included at the top)
; ============================================================================
; 修改"启动应用"按钮文本为"启动服务"
;  Change "Launch app" button text to "Start Service"
!ifndef MUI_FINISHPAGE_RUN_TEXT
  !define MUI_FINISHPAGE_RUN_TEXT "启动服务"
!endif

; ============================================================================
; 驱动构建产物的编译期路径 / Compile-time paths to driver build outputs
; ${__FILEDIR__} 是本 .nsh 所在目录（仓库的 build/）。
;  ${__FILEDIR__} is this file's directory.
; ============================================================================
!define ANXIN_PROC_SYS_SRC "${__FILEDIR__}\..\native\driver\build\x64\Release\AnXinProcProtect.sys"
!define ANXIN_FILE_SYS_SRC "${__FILEDIR__}\..\native\file_protect\build\x64\Release\AnXinFileProtect.sys"

; ============================================================================
; 内核防护选项变量 / Kernel protection option variable
; ============================================================================
; 0 = 不安装内核防护（仅用户态防护）；1 = 安装内核防护
;  0 = skip kernel drivers (user-mode protection only); 1 = install kernel drivers
Var KernelProtect

!macro NSIS_HOOK_PREINSTALL
  ; --------------------------------------------------------------------------
  ; 询问用户是否安装内核防护
  ;  Ask the user whether to install kernel protection
  ;
  ; 内核防护驱动在内核态运行，具有系统级权限。驱动异常可能导致蓝屏死机。
  ; 用户有权选择不安装内核驱动，仅使用用户态防护（ETW 监控、API Hook 等）。
  ;  Kernel protection drivers run in kernel mode with system-level privileges. A driver
  ;  fault can cause a BSOD. The user may opt out and use user-mode protection only.
  ; --------------------------------------------------------------------------
  MessageBox MB_YESNO|MB_ICONQUESTION "是否安装内核防护驱动？$\n$\n内核防护在内核态运行，提供进程保护和文件保护功能。$\n如果驱动出现异常，可能导致蓝屏死机。$\n$\n选择 [是] 安装内核防护驱动（推荐）。$\n选择 [否] 仅安装用户态防护。" IDYES _install_kernel IDNO _skip_kernel

  _install_kernel:
    StrCpy $KernelProtect 1
    Goto _kernel_decision_done

  _skip_kernel:
    StrCpy $KernelProtect 0
    Goto _kernel_decision_done

  _kernel_decision_done:

  ${If} $KernelProtect == 1
    ; ------------------------------------------------------------------------
    ; 立即加载进程保护驱动，保护安装进程本身
    ;  Load the process protection driver immediately to protect the installer itself
    ;
    ; 此刻 bundle.resources 还没释放，所以驱动必须由本钩子自带的 File 指令内嵌释放。
    ;  bundle.resources is not on disk yet, so the driver must be embedded by this hook's own File.
    ;
    ; 直接写 %SystemRoot%\System32\drivers：NSIS 安装程序是 32 位，写 System32 会被 WoW64
    ; 重定向到 SysWOW64\drivers，驱动将永远加载不了，因此必须先关掉重定向。
    ;  Written straight into %SystemRoot%\System32\drivers: the NSIS installer is 32-bit, so writing
    ;  to System32 would be redirected into SysWOW64\drivers and the driver could never load.
    ; ------------------------------------------------------------------------
    !if /FileExists "${ANXIN_PROC_SYS_SRC}"
      DetailPrint "Loading AnXin process protection driver..."
      ${DisableX64FSRedirection}
      SetOutPath "$SYSDIR\drivers"
      File "/oname=AnXinProcProtect.sys" "${ANXIN_PROC_SYS_SRC}"

      ; type= kernel + start= system：随内核初始化加载，早于普通应用；
      ; system 启动类型的驱动默认不在安全模式加载，为用户保留兜底逃生路径。
      ;  type= kernel + start= system loads during kernel init, ahead of ordinary applications, and a
      ;  system-start driver is not loaded in Safe Mode, preserving the user's escape hatch.
      nsExec::ExecToStack 'sc.exe create "AnXinProcProtect" type= kernel start= system error= normal binPath= "$SYSDIR\drivers\AnXinProcProtect.sys" DisplayName= "AnXin Security Process Protection"'
      Pop $0
      Pop $1
      DetailPrint "proc driver sc create: $0 $1"

      nsExec::ExecToStack 'sc.exe start "AnXinProcProtect"'
      Pop $0
      Pop $1
      ${If} $0 == 0
        DetailPrint "Process protection driver loaded."
      ${Else}
        ; 常见原因：577 签名不被接受、1275 被策略阻止、5 权限不足。
        ; 一律只记录，不中断安装。
        ;  Common causes: 577 signature rejected, 1275 blocked by policy, 5 access denied.
        ;  Logged only - never abort the installation.
        DetailPrint "NOTE: process protection driver not loaded ($0): $1"
        DetailPrint "NOTE: installation continues; user-mode protection is unaffected."
      ${EndIf}

      ; ------------------------------------------------------------------------
      ; 释放文件保护驱动文件到 System32\drivers（仅文件，服务在 POSTINSTALL 注册）
      ;  Drop the file protection driver binary to System32\drivers (file only; the
      ;  service is registered in POSTINSTALL because minifilter needs Instances subkey)
      ; ------------------------------------------------------------------------
      !if /FileExists "${ANXIN_FILE_SYS_SRC}"
        DetailPrint "Extracting AnXin file protection driver binary..."
        File "/oname=AnXinFileProtect.sys" "${ANXIN_FILE_SYS_SRC}"
      !else
        DetailPrint "NOTE: file protection driver not present in this build, skipping."
      !endif

      ${EnableX64FSRedirection}
      SetOutPath "$INSTDIR"
    !else
      DetailPrint "NOTE: process protection driver not present in this build, skipping."
    !endif
  ${Else}
    DetailPrint "Kernel protection not selected by user. Skipping kernel drivers."
  ${EndIf}
!macroend

!macro NSIS_HOOK_POSTINSTALL
  ${If} $KernelProtect == 1
    ; ------------------------------------------------------------------------
    ; 1. 注册文件保护 minifilter（写 Instances 子键 + 创建服务 + 启动）
    ;     Register the file protection minifilter (Instances subkey + service + start)
    ;
    ; minifilter 光有服务是不够的：过滤管理器要读服务键下的 Instances 子键才知道
    ; 挂载高度。sc.exe 写不了 Instances 子键，必须用 WriteRegStr/WriteRegDWORD。
    ;  A service alone is not enough for a minifilter: the filter manager reads the Instances
    ;  subkey for the altitude. sc.exe cannot write it; WriteRegStr/WriteRegDWORD are required.
    ;
    ; 注册表结构（与 driver_install_service.rs 的 write_minifilter_instances 等价）：
    ;  Registry structure (equivalent to write_minifilter_instances):
    ;   HKLM\SYSTEM\CurrentControlSet\Services\AnXinFileProtect\Instances
    ;       DefaultInstance = "AnXinFileProtect Instance"
    ;     \AnXinFileProtect Instance
    ;       Altitude = "328800"
    ;       Flags    = 0
    ;   HKLM\SYSTEM\CurrentControlSet\Services\AnXinFileProtect
    ;       Group = "FSFilter Anti-Virus"
    ; ------------------------------------------------------------------------
    DetailPrint "Registering AnXin file protection minifilter..."
    ${DisableX64FSRedirection}

    WriteRegStr HKLM "SYSTEM\CurrentControlSet\Services\AnXinFileProtect\Parameters\Instances" "DefaultInstance" "AnXinFileProtect Instance"
    WriteRegStr HKLM "SYSTEM\CurrentControlSet\Services\AnXinFileProtect\Parameters\Instances\AnXinFileProtect Instance" "Altitude" "328800"
    WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\AnXinFileProtect\Parameters\Instances\AnXinFileProtect Instance" "Flags" 0
    WriteRegStr HKLM "SYSTEM\CurrentControlSet\Services\AnXinFileProtect" "Group" "FSFilter Anti-Virus"

    ; type= filesys + start= system + depend= FltMgr：minifilter 必须在 FltMgr 之后加载
    ;  type= filesys + start= system + depend= FltMgr: minifilter must load after FltMgr
    nsExec::ExecToStack 'sc.exe create "AnXinFileProtect" type= filesys start= system error= normal binPath= "$SYSDIR\drivers\AnXinFileProtect.sys" DisplayName= "AnXin Security File Protection" depend= "FltMgr"'
    Pop $0
    Pop $1
    DetailPrint "file driver sc create: $0 $1"

    nsExec::ExecToStack 'sc.exe start "AnXinFileProtect"'
    Pop $0
    Pop $1
    ${If} $0 == 0
      DetailPrint "File protection minifilter loaded."
    ${Else}
      DetailPrint "NOTE: file protection minifilter not loaded ($0): $1"
      DetailPrint "NOTE: installation continues; user-mode protection is unaffected."
    ${EndIf}

    ${EnableX64FSRedirection}

    ; ------------------------------------------------------------------------
    ; 2. 把安装目录登记为受保护路径，并保护两个驱动自己的服务注册表键
    ;     Register the install directory as protected and protect both driver service keys
    ;
    ; 服务键被保护后，外部程序无法删除服务键让驱动下次开机不再加载 —— 这是
    ; "安装后驱动不可被外力卸载"的核心。卸载程序会在删除前先解除这项保护。
    ;  With the service keys protected, nothing external can delete them to stop the drivers
    ;  loading next boot - this is the core of "the driver cannot be removed by external force".
    ; ------------------------------------------------------------------------
    DetailPrint "Registering protected paths..."
    nsExec::ExecToStack '"$INSTDIR\anxin-security.exe" --protect-dir "$INSTDIR"'
    Pop $0
    Pop $1
    DetailPrint "protect-dir: $0 $1"

    ; 保护安装进程自身，避免收尾阶段被外部结束导致半安装状态
    ;  Protect the installer process itself so it cannot be killed during the final steps.
    System::Call 'kernel32::GetCurrentProcessId() i .r2'
    nsExec::ExecToStack '"$INSTDIR\anxin-security.exe" --protect-pid $2'
    Pop $0
    Pop $1
    DetailPrint "protect-pid $2: $0 $1"
  ${Else}
    DetailPrint "Kernel protection not selected. Skipping minifilter and path protection."
  ${EndIf}

  ; ------------------------------------------------------------------------
  ; 3. 注册用户态防护服务（开机自启）—— 无论是否安装内核防护都要注册
  ;     Register the user-mode protection service (auto-start at boot)
  ;     — always registered regardless of kernel protection choice
  ; ------------------------------------------------------------------------
  DetailPrint "Cleaning up existing AnXin Security service..."
  nsExec::Exec 'sc.exe stop "AnXinSecurityService"'
  Sleep 5000
  nsExec::Exec 'sc.exe delete "AnXinSecurityService"'
  Sleep 2000

  ; binPath 使用主可执行文件 + --service 参数，以服务模式运行（无 UI）
  ; sc.exe 的 binPath 要求路径中的引号用 \" 转义；NSIS 中 $\" 表示 "，\$\" 生成 \"
  ;  binPath uses the main executable plus --service to run headless. sc.exe requires quotes inside
  ;  binPath to be escaped as \"; in NSIS $\" is a quote, so \$\" produces \".
  DetailPrint "Registering AnXin Security protection service..."
  nsExec::ExecToStack 'sc.exe create "AnXinSecurityService" binPath= "\$\"$INSTDIR\AnXinService.exe\$\" --service" start= auto DisplayName= "AnXin Security Protection Service"'
  Pop $0
  Pop $1
  DetailPrint "sc create exit code: $0"
  DetailPrint "sc create output: $1"
  ${If} $0 == 0
    DetailPrint "Service registered successfully."
    nsExec::Exec 'sc.exe description "AnXinSecurityService" "AnXin Security background protection service - provides ETW behavior monitoring, process monitoring, and file hooks at system startup."'
    DetailPrint "Starting AnXin Security service..."
    nsExec::ExecToStack 'sc.exe start "AnXinSecurityService"'
    Pop $0
    Pop $1
    DetailPrint "sc start exit code: $0"
    DetailPrint "sc start output: $1"
    ${If} $0 != 0
      DetailPrint "WARNING: Service failed to start (exit code: $0). See output above."
    ${EndIf}
  ${Else}
    DetailPrint "ERROR: Service registration failed (exit code: $0). Output: $1"
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ; --------------------------------------------------------------------------
  ; 用户主动卸载 —— 这是唯一允许移除防护的入口
  ;  User-initiated uninstall - the only entry point allowed to remove protection
  ;
  ; 顺序很重要：必须先让主程序解除驱动内部的保护列表（注册表键与受保护 PID），
  ; 否则后面的 sc delete 会被驱动的注册表回调挡住。
  ;  Order matters: the main binary must first clear the driver's in-memory protection lists
  ;  (registry keys and protected PIDs), otherwise the sc delete below is blocked by the driver's
  ;  registry callback.
  ;
  ; 即使安装时用户没选择内核防护，这里也必须无条件尝试清理 —— 用户可能在之后
  ; 手动安装了驱动，或者从旧版本升级过来。sc delete 不存在的服务只会返回错误，
  ; 不会有副作用。
  ;  Even if the user did not choose kernel protection at install time, this must still attempt
  ;  cleanup unconditionally — the user may have installed drivers later, or upgraded from an
  ;  older version that always installed them. sc delete on a non-existent service only returns
  ;  an error with no side effects.
  ; --------------------------------------------------------------------------
  DetailPrint "Releasing driver self-protection..."
  nsExec::ExecToStack '"$INSTDIR\anxin-security.exe" --uninstall-drivers'
  Pop $0
  Pop $1
  DetailPrint "uninstall-drivers: $0 $1"

  ; 停止并删除用户态服务
  ;  Stop and delete the user-mode service
  DetailPrint "Stopping AnXin Security protection service..."
  nsExec::Exec 'sc.exe stop "AnXinSecurityService"'
  Sleep 5000
  DetailPrint "Removing AnXin Security protection service..."
  nsExec::ExecToStack 'sc.exe delete "AnXinSecurityService"'
  Pop $0
  Pop $1
  DetailPrint "sc delete exit code: $0"
  DetailPrint "sc delete output: $1"
  Sleep 2000

  nsExec::Exec 'sc.exe query "AnXinSecurityService"'
  Pop $0
  ${If} $0 == 0
    DetailPrint "WARNING: Service still exists after delete. Forcing removal..."
    nsExec::Exec 'sc.exe delete "AnXinSecurityService"'
    Sleep 2000
  ${Else}
    DetailPrint "Service successfully removed."
  ${EndIf}

  ; 兜底：即使主程序已损坏或无法运行，也必须保证两个驱动服务被删除，
  ; 否则用户会留下一个删不掉的驱动 —— 这是绝对不能接受的结果。
  ;  Fallback: even if the main binary is damaged or cannot run, both driver services must still be
  ;  deleted, otherwise the user is left with a driver they cannot remove - never acceptable.
  DetailPrint "Removing driver services (fallback)..."
  nsExec::Exec 'sc.exe stop "AnXinFileProtect"'
  nsExec::Exec 'sc.exe delete "AnXinFileProtect"'
  nsExec::Exec 'sc.exe stop "AnXinProcProtect"'
  nsExec::Exec 'sc.exe delete "AnXinProcProtect"'

  ; 驱动仍加载时 .sys 被内核占用，Delete /REBOOTOK 会安排重启后删除
  ;  While a driver is still loaded the kernel holds its .sys open; Delete /REBOOTOK schedules the
  ;  removal for the next boot
  ${DisableX64FSRedirection}
  Delete /REBOOTOK "$SYSDIR\drivers\AnXinProcProtect.sys"
  Delete /REBOOTOK "$SYSDIR\drivers\AnXinFileProtect.sys"
  ${EnableX64FSRedirection}
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  ; 残留核查：驱动服务若仍存在，说明前面某一步被挡住了。
  ; 必须明确告诉用户如何自救，绝不能让用户面对一个删不掉又不知所措的驱动。
  ;  Leftover check: a surviving driver service means an earlier step was blocked. Tell the user
  ;  exactly how to recover rather than leaving them stuck with something they cannot remove.
  nsExec::Exec 'sc.exe query "AnXinProcProtect"'
  Pop $0
  ${If} $0 == 0
    DetailPrint "NOTE: AnXinProcProtect is still registered and will be removed after reboot."
    DetailPrint "NOTE: if it persists, boot into Safe Mode (the driver does not load there) and run:"
    DetailPrint "NOTE:   sc delete AnXinProcProtect"
  ${EndIf}
  nsExec::Exec 'sc.exe query "AnXinFileProtect"'
  Pop $0
  ${If} $0 == 0
    DetailPrint "NOTE: AnXinFileProtect is still registered and will be removed after reboot."
    DetailPrint "NOTE:   sc delete AnXinFileProtect  (Safe Mode if necessary)"
  ${EndIf}
!macroend
