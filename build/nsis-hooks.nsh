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
  ; Kernel-protection opt-in. Silent installs (/S: enterprise deployment and
  ; automated testing) auto-answer Yes; interactive installs show the question.
  ; NOTE: MessageBox /SD is deliberately avoided - this NSIS 3.11 build fails to
  ; parse it (Usage error on every standard spelling, reproduced 2026-08-24).
  ; --------------------------------------------------------------------------
  ${If} ${Silent}
    StrCpy $KernelProtect 1
    Goto _kernel_decision_done
  ${EndIf}
  MessageBox MB_YESNO|MB_ICONQUESTION "是否安装内核防护驱动？$\n$\n内核防护在内核态运行，提供进程保护和文件保护功能。$\n如果驱动出现异常，可能导致蓝屏死机。$\n$\n选择 [是] 安装内核防护驱动（推荐）。$\n选择 [否] 仅安装用户态防护。" IDYES _install_kernel IDNO _skip_kernel

  _install_kernel:
    StrCpy $KernelProtect 1
    Goto _kernel_decision_done

  _skip_kernel:
    StrCpy $KernelProtect 0
    Goto _kernel_decision_done

  _kernel_decision_done:
!macroend
!macro NSIS_HOOK_POSTINSTALL
  ${If} $KernelProtect == 1
    ; ------------------------------------------------------------------------
    ; Driver drop + registration happens HERE (POSTINSTALL), not PREINSTALL:
    ; driver binaries ship via bundle.resources and only exist on disk after the
    ; Section released them under $INSTDIR\_up_\. The old PREINSTALL placement
    ; relied on ${__FILEDIR__}\..\native which points into the bundler output
    ; tree (never exists) - the File /FileExists guard therefore silently skipped
    ; every drop; legacy System32 copies masked it for Proc/File drivers while
    ; NetFilter (no legacy copy) never installed. Reproduced 2026-08-24.
    ; ------------------------------------------------------------------------
    DetailPrint "Installing AnXin kernel drivers..."
    ${DisableX64FSRedirection}
    SetOutPath "$SYSDIR\drivers"
    CopyFiles /SILENT "$INSTDIR\_up_\native\driver\build\x64\Release\AnXinProcProtect.sys" "$SYSDIR\drivers\AnXinProcProtect.sys"
    CopyFiles /SILENT "$INSTDIR\_up_\native\file_protect\build\x64\Release\AnXinFileProtect.sys" "$SYSDIR\drivers\AnXinFileProtect.sys"
    CopyFiles /SILENT "$INSTDIR\_up_\native\net_filter\build\x64\Release\AnXinNetFilter.sys" "$SYSDIR\drivers\AnXinNetFilter.sys"

    ; ---- 1) Process protection: load first so subsequent steps run protected ----
    nsExec::ExecToStack 'sc.exe create "AnXinProcProtect" type= kernel start= system error= normal binPath= "$SYSDIR\drivers\AnXinProcProtect.sys" DisplayName= "AnXin Security Process Protection"'
    Pop $0
    Pop $1
    DetailPrint "proc sc create: $0"
    nsExec::ExecToStack 'sc.exe start "AnXinProcProtect"'
    Pop $0
    Pop $1
    DetailPrint "NOTE: proc driver start ($0): $1"

    ; ---- 2) File protection minifilter ----
    ; Instances must be written BOTH under the service key root and Parameters:
    ; FltMgr lookup paths differ across Windows builds; single-side writes break
    ; FltRegisterFilter with 0xC0000034 (reproduced 2026-08-24).
    WriteRegStr HKLM "SYSTEM\CurrentControlSet\Services\AnXinFileProtect\Instances" "DefaultInstance" "AnXinFileProtect Instance"
    WriteRegStr HKLM "SYSTEM\CurrentControlSet\Services\AnXinFileProtect\Instances\AnXinFileProtect Instance" "Altitude" "328800"
    WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\AnXinFileProtect\Instances\AnXinFileProtect Instance" "Flags" 0
    WriteRegStr HKLM "SYSTEM\CurrentControlSet\Services\AnXinFileProtect\Parameters\Instances" "DefaultInstance" "AnXinFileProtect Instance"
    WriteRegStr HKLM "SYSTEM\CurrentControlSet\Services\AnXinFileProtect\Parameters\Instances\AnXinFileProtect Instance" "Altitude" "328800"
    WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\AnXinFileProtect\Parameters\Instances\AnXinFileProtect Instance" "Flags" 0
    WriteRegStr HKLM "SYSTEM\CurrentControlSet\Services\AnXinFileProtect" "Group" "FSFilter Anti-Virus"
    nsExec::ExecToStack 'sc.exe create "AnXinFileProtect" type= filesys start= system error= normal binPath= "$SYSDIR\drivers\AnXinFileProtect.sys" DisplayName= "AnXin Security File Protection" depend= "FltMgr"'
    Pop $0
    Pop $1
    DetailPrint "file sc create: $0"
    nsExec::ExecToStack 'sc.exe start "AnXinFileProtect"'
    Pop $0
    Pop $1
    DetailPrint "NOTE: file driver start ($0): $1"

    ; ---- 3) Network filter callout (WFP): registers callout/provider only;
    ;      blocking rules come from user-mode FirewallService when enabled ----
    nsExec::ExecToStack 'sc.exe create "AnXinNetFilter" type= kernel start= system error= normal binPath= "$SYSDIR\drivers\AnXinNetFilter.sys" DisplayName= "AnXin Security Network Filter" depend= "Tcpip"'
    Pop $0
    Pop $1
    DetailPrint "netfilter sc create: $0"
    nsExec::ExecToStack 'sc.exe start "AnXinNetFilter"'
    Pop $0
    Pop $1
    DetailPrint "NOTE: netfilter driver start ($0): $1"

    ${EnableX64FSRedirection}

    ; ------------------------------------------------------------------------
    ; Register install dir as protected path + protect installer PID.
    ; NOTE: main binary is now AnXinSecurity.exe after the three-process split.
    ; ------------------------------------------------------------------------
    DetailPrint "Registering protected paths..."
    nsExec::ExecToStack '"$INSTDIR\AnXinSecurity.exe" --protect-dir "$INSTDIR"'
    Pop $0
    Pop $1
    DetailPrint "protect-dir: $0 $1"

    System::Call 'kernel32::GetCurrentProcessId() i .r2'
    nsExec::ExecToStack '"$INSTDIR\AnXinSecurity.exe" --protect-pid $2'
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
