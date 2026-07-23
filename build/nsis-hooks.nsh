; NSIS 安装/卸载钩子
;  NSIS install/uninstall hooks
;
; Tauri 2.0 的 NSIS 模板使用的宏名：
;  Tauri 2.0 NSIS template macro names:
; - NSIS_HOOK_POSTINSTALL: 安装后（文件已复制到 $INSTDIR）
; - NSIS_HOOK_PREUNINSTALL: 卸载前（文件尚未删除）
;
; 安装时注册 AnXin Security 防护服务（开机自启）
; 卸载时停止并彻底删除防护服务
;
; Register AnXin Security protection service (auto-start at boot) on install
; Stop and completely remove protection service on uninstall

; ============================================================================
; 完成页面配置 — 在 MUI_PAGE_FINISH 之前预定义（hooks 在模板第 28 行被 !include）
;  Finish page config - pre-defined before MUI_PAGE_FINISH (hooks included at line 28)
; ============================================================================
; 修改"启动应用"按钮文本为"启动服务"
;  Change "Launch app" button text to "Start Service"
!ifndef MUI_FINISHPAGE_RUN_TEXT
  !define MUI_FINISHPAGE_RUN_TEXT "启动服务"
!endif

!macro NSIS_HOOK_POSTINSTALL
  ; 先删除可能存在的旧服务（防止旧配置残留，如旧的 AnXinSecurity.exe 路径）
  ;  Delete existing service first (prevent stale config, e.g. old AnXinSecurity.exe path)
  DetailPrint "Cleaning up existing AnXin Security service..."
  nsExec::Exec 'sc.exe stop "AnXinSecurityService"'
  ; 等待服务停止（固定 5 秒，足够服务完成停止流程）
  ;  Wait for service to stop (fixed 5s, enough for service to complete stop)
  Sleep 5000
  nsExec::Exec 'sc.exe delete "AnXinSecurityService"'
  Sleep 2000

  ; 注册 Windows 服务（自动启动类型）
  ;  Register Windows service (automatic start type)
  ;  binPath 使用主可执行文件 + --service 参数，以服务模式运行（无 UI）
  ;  sc.exe 的 binPath 要求路径中的引号用 \" 转义
  ;  NSIS 中 $\" 表示双引号 "，\$\" 生成 \"
  DetailPrint "Registering AnXin Security protection service..."
  nsExec::ExecToStack 'sc.exe create "AnXinSecurityService" binPath= "\$\"$INSTDIR\anxin-security.exe\$\" --service" start= auto DisplayName= "AnXin Security Protection Service"'
  Pop $0 ; exit code
  Pop $1 ; output
  DetailPrint "sc create exit code: $0"
  DetailPrint "sc create output: $1"
  ${If} $0 == 0
    DetailPrint "Service registered successfully."
    ; 设置服务描述
    nsExec::Exec 'sc.exe description "AnXinSecurityService" "AnXin Security background protection service - provides file hook protection at system startup."'
    ; 启动服务
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
  ; 停止服务（忽略错误，服务可能未运行）
  ;  Stop service (ignore errors, service may not be running)
  DetailPrint "Stopping AnXin Security protection service..."
  nsExec::Exec 'sc.exe stop "AnXinSecurityService"'
  ; 等待服务停止（固定 5 秒）
  ;  Wait for service to stop (fixed 5s)
  Sleep 5000
  ; 删除服务
  DetailPrint "Removing AnXin Security protection service..."
  nsExec::ExecToStack 'sc.exe delete "AnXinSecurityService"'
  Pop $0
  Pop $1
  DetailPrint "sc delete exit code: $0"
  DetailPrint "sc delete output: $1"
  ; 再次等待确保删除完成
  Sleep 2000
  ; 验证服务已删除（sc query 返回非 0 表示服务不存在）
  nsExec::Exec 'sc.exe query "AnXinSecurityService"'
  Pop $0
  ${If} $0 == 0
    DetailPrint "WARNING: Service still exists after delete. Forcing removal..."
    nsExec::Exec 'sc.exe delete "AnXinSecurityService"'
    Sleep 2000
  ${Else}
    DetailPrint "Service successfully removed."
  ${EndIf}
!macroend
