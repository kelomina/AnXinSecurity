/*++
Copyright (c) AnXin Security. All rights reserved.

Module Name:
    lifecycle.c

Abstract:
    AnXinProcMon.sys 生命周期采集：进程创建/退出、远程线程、映像加载。
    Lifecycle collection: process create/exit, remote threads, image loads.

    - 进程回调（PsSetCreateProcessNotifyRoutineEx）：
      * CREATE：捕获 CommandLine（PS_CREATE_NOTIFY_INFO.CommandLine，三级判空）、
        PPID Spoofing 比对（ParentProcessId vs CreatingThreadId.UniqueProcess）、
        Token 提升/完整性标志（PsReferencePrimaryToken + SeQueryInformationToken，
        失败降级 flags=0，用户态补采兜底）。
      * EXIT（CreateInfo == NULL）：退出码。
    - 线程回调（PsSetCreateThreadNotifyRoutineEx，Win10 1709+）：
      CreatingProcessId != ProcessId 即远程线程注入（§13.6），pid=目标进程、
      creator=注入者，负载=目标线程 ID。
    - 映像加载（PsSetLoadImageNotifyRoutine）：DLL 路径 UTF-16 ≤512 字符，
      内置 System32 关键 DLL 精确白名单（不可覆盖）+ 用户过滤表 IMAGE_PATH_EXACT/
      IMAGE_PATH_PREFIX 规则。
    - 防呆：PID 0/4/8 必丢（AnxProcIsSystemPid，用户表不可覆盖）。
    - 活性心跳：每次入队由 events.c 更新（AnxProcTouchHealth，§13.7）。

    Process callback (PsSetCreateProcessNotifyRoutineEx):
      * CREATE: capture CommandLine (triple null-check), PPID-spoof comparison
        (ParentProcessId vs CreatingThreadId.UniqueProcess), token elevation /
        integrity flags (PsReferencePrimaryToken + SeQueryInformationToken;
        degrade to flags=0 on failure, user mode backfills).
      * EXIT (CreateInfo == NULL): exit code.
    Thread callback (PsSetCreateThreadNotifyRoutineEx, Win10 1709+):
      CreatingProcessId != ProcessId => remote thread (§13.6); pid=target,
      creator=injector, payload=target thread ID.
    Image load (PsSetLoadImageNotifyRoutine): DLL path UTF-16 <= 512 chars;
      built-in exact allowlist for critical System32 DLLs (non-overridable)
      plus user table IMAGE_PATH_EXACT / IMAGE_PATH_PREFIX rules.
    Fail-safe: PIDs 0/4/8 always dropped (non-overridable).
    Heartbeat: updated per enqueue in events.c (AnxProcTouchHealth, §13.7).

Environment:
    Kernel mode only.

--*/

#include "anx_proc_internal.h"

/*
 * PsGetProcessSessionId 是未文档化 ntoskrnl 导出（WDK 无头文件声明），
 * 此处按实际签名手动声明。仅用于读取会话 ID，任何失败降级为 0。
 * Undocumented ntoskrnl export (no WDK header); declared manually.
 */
NTKERNELAPI
ULONG
NTAPI
PsGetProcessSessionId(_In_ PEPROCESS Process);

static BOOLEAN g_ProcessNotifyRegistered = FALSE;
static BOOLEAN g_ThreadNotifyRegistered  = FALSE;
static BOOLEAN g_LoadImageRegistered     = FALSE;
/* 注册错误码（P6 诊断：进程/线程回调注册失败时记录原因） */
static NTSTATUS g_ProcessNotifyStatus = STATUS_SUCCESS;
static NTSTATUS g_ThreadNotifyStatus  = STATUS_SUCCESS;
static NTSTATUS g_LoadImageStatus     = STATUS_SUCCESS;

/* ==========================================================================
 * 辅助 / Helpers
 * ========================================================================== */

/*
 * 函数名称：AnxProcCaptureCommandLine
 * 函数作用：安全捕获进程命令行（PS_CREATE_NOTIFY_INFO.CommandLine）。
 * 三级判空：CreateInfo->CommandLine 指针、->Buffer、->Length。
 * 截断至 ANX_PROC_MAX_CMD_CHARS 字符（UTF-16），分配非分页池给调用方
 * （调用方负责用 ANX_PROC_TAG_PAYLOAD 释放）。失败返回 NULL。
 * Purpose: Safely captures the process command line (triple null-check).
 *          Truncated to ANX_PROC_MAX_CMD_CHARS UTF-16 chars, allocated in
 *          non-paged pool for the caller (caller frees with
 *          ANX_PROC_TAG_PAYLOAD). NULL on failure.
 * IRQL：<= DISPATCH_LEVEL
 */
static PUINT8 AnxProcCaptureCommandLine(_In_ PPS_CREATE_NOTIFY_INFO CreateInfo,
                                        _Out_ ULONG* OutBytes)
{
    PCUNICODE_STRING cmdLine = NULL;
    ULONG           bytes = 0;
    PUINT8          buffer = NULL;

    *OutBytes = 0;

    if (CreateInfo != NULL) {
        cmdLine = CreateInfo->CommandLine;
    }
    if (cmdLine == NULL || cmdLine->Buffer == NULL || cmdLine->Length == 0) {
        return NULL;   /* 无命令行：事件不带负载，用户态用 pid 关联补采 */
    }

    /* 截断到 MaxCmdChars（字符），字节数对齐到 2 */
    bytes = cmdLine->Length;
    if (bytes > ANX_PROC_MAX_CMD_CHARS * sizeof(WCHAR)) {
        bytes = ANX_PROC_MAX_CMD_CHARS * sizeof(WCHAR);
    }
    bytes &= ~1u;   /* 偶数对齐 */

    buffer = (PUINT8)ExAllocatePool2(POOL_FLAG_NON_PAGED, bytes,
                                     ANX_PROC_TAG_PAYLOAD);
    if (buffer == NULL) {
        return NULL;
    }
    RtlCopyMemory(buffer, cmdLine->Buffer, bytes);
    *OutBytes = bytes;
    return buffer;
}

/*
 * 函数名称：AnxProcGetTokenFlags
 * 函数作用：读取新进程 Token 的 UAC 提升与完整性级别（仅 CREATE 路径）。
 * 回调运行在创建者线程上下文，新进程可能尚未完全初始化：
 * 用 PsLookupProcessByProcessId + PsReferencePrimaryToken +
 * SeQueryInformationToken 读取，全程 try/except 保护；任何失败降级 flags=0，
 * 由用户态 3s 补采兜底（OpenProcessToken + TokenElevation/完整性）。
 * Purpose: Reads the new process token's UAC elevation & integrity level
 *          (CREATE path only). Wrapped in try/except; any failure degrades to
 *          flags=0 and user mode backfills within the 3s window.
 * IRQL：PASSIVE_LEVEL（ProcessNotify 回调保证）
 */
static UINT16 AnxProcGetTokenFlags(_In_ ULONG Pid)
{
    PEPROCESS     process = NULL;
    PACCESS_TOKEN token = NULL;
    PVOID         info = NULL;
    UINT16        flags = 0;
    NTSTATUS      status;

    if (Pid == 0 || Pid == 4 || Pid == 8) {
        return 0;
    }

    __try {
        status = PsLookupProcessByProcessId(UlongToHandle(Pid), &process);
        if (!NT_SUCCESS(status) || process == NULL) {
            return 0;
        }

        token = PsReferencePrimaryToken(process);
        if (token == NULL) {
            ObDereferenceObject(process);
            return 0;
        }

        status = SeQueryInformationToken(token, TokenElevation, &info);
        if (NT_SUCCESS(status) && info != NULL) {
            if (((PTOKEN_ELEVATION)info)->TokenIsElevated) {
                flags |= ANX_PROC_FLAG_TOKEN_ELEVATED;
            }
            ExFreePoolWithTag(info, ANX_PROC_TAG_PAYLOAD);
            info = NULL;
        }

        status = SeQueryInformationToken(token, TokenIntegrityLevel, &info);
        if (NT_SUCCESS(status) && info != NULL) {
            PTOKEN_MANDATORY_LABEL label = (PTOKEN_MANDATORY_LABEL)info;
            SID*                   sid = (SID*)label->Label.Sid;

            /* 完整性级别由 SID 的 SubAuthority 编码：Medium=0x2000，
             * High=0x3000，System=0x4000（第 1 个 SubAuthority）。 */
            if (sid != NULL && sid->SubAuthorityCount > 0 &&
                sid->SubAuthority[0] >= 0x3000) {
                flags |= ANX_PROC_FLAG_TOKEN_HIGH_INTEGRITY;
            }
            ExFreePoolWithTag(info, ANX_PROC_TAG_PAYLOAD);
            info = NULL;
        }

        ObDereferenceObject(token);
        ObDereferenceObject(process);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        flags = 0;
    }

    return flags;
}

/*
 * 函数名称：AnxProcGetSessionId
 * 函数作用：进程会话 ID（0 = 系统会话 / 不可得）。创建回调中进程尚未
 * 完全初始化，仅在能查到目标 EProcess 时读取，失败置 0（用户态补采）。
 * Purpose: Process session ID (0 = system session / unavailable). The target
 *          EProcess may not exist yet at create time; on failure 0 is used
 *          and user mode backfills.
 * IRQL：PASSIVE_LEVEL
 */
static ULONG AnxProcGetSessionId(_In_ ULONG Pid)
{
    PEPROCESS process = NULL;
    ULONG     session = 0;

    __try {
        if (NT_SUCCESS(PsLookupProcessByProcessId(UlongToHandle(Pid), &process))) {
            if (process != NULL) {
                session = (ULONG)PsGetProcessSessionId(process);
                ObDereferenceObject(process);
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        session = 0;
    }

    return session;
}

/*
 * 函数名称：AnxProcCaptureImagePath
 * 函数作用：安全拷贝映像加载路径（UTF-16，≤512 字符含 NUL），返回
 * 分配好的非分页缓冲（调用方以 ANX_PROC_TAG_PAYLOAD 释放）。
 * 输入为 PsSetLoadImageNotifyRoutine 旧签名回调的 FullImageName。
 * Purpose: Copies the image load path safely (UTF-16, <= 512 chars incl. NUL)
 *          into a non-paged buffer (caller frees with ANX_PROC_TAG_PAYLOAD).
 *          Input is the FullImageName of the legacy load-image callback.
 * IRQL：<= DISPATCH_LEVEL
 */
static PUINT8 AnxProcCaptureImagePath(_In_ PUNICODE_STRING FullImageName,
                                      _Out_ ULONG* OutBytes)
{
    ULONG  bytes = 0;
    PUINT8 buffer = NULL;

    *OutBytes = 0;

    if (FullImageName == NULL || FullImageName->Buffer == NULL ||
        FullImageName->Length == 0) {
        return NULL;
    }

    bytes = FullImageName->Length;
    if (bytes > ANX_PROC_MAX_PATH * sizeof(WCHAR)) {
        bytes = ANX_PROC_MAX_PATH * sizeof(WCHAR);
    }
    bytes &= ~1u;

    buffer = (PUINT8)ExAllocatePool2(POOL_FLAG_NON_PAGED, bytes,
                                     ANX_PROC_TAG_PAYLOAD);
    if (buffer == NULL) {
        return NULL;
    }
    RtlCopyMemory(buffer, FullImageName->Buffer, bytes);
    *OutBytes = bytes;
    return buffer;
}

/* ==========================================================================
 * 回调 / Callbacks
 * ========================================================================== */

/*
 * 函数名称：AnxProcProcessNotify
 * 函数作用：进程创建/退出回调（PsSetCreateProcessNotifyRoutineEx）。
 * - 退出（CreateInfo == NULL）：PROC_EXIT 事件，退出码放 header。
 * - 创建：PROC_CREATE 事件；命令行负载；PPID Spoofing 比对置
 *   ANX_PROC_FLAG_PPID_SPOOFED（仅标记不阻断，防服务 RPC 代建误报）；
 *   Token 标志（失败降级）；会话 ID（失败置 0）；进程名前缀过滤
 *   （PROC_PATH_PREFIX，DROP 命中则不采集，空名无过滤）。
 * - 防呆：PID 0/4/8 必丢。
 * Purpose: Process create/exit callback (PsSetCreateProcessNotifyRoutineEx).
 * IRQL：PASSIVE_LEVEL
 */
static VOID AnxProcProcessNotify(_In_ HANDLE ParentId, _In_ HANDLE ProcessId,
                                 _In_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    ULONG   pid = (ULONG)(ULONG_PTR)ProcessId;
    ULONG   parentPid = (ULONG)(ULONG_PTR)ParentId;
    ULONG   creatorPid = 0;
    ULONG   sessionId = 0;
    UINT16  flags = 0;
    PUINT8  payload = NULL;
    ULONG   payloadBytes = 0;
    PANX_PROC_QUEUE queue;

    if (pid == 0 || AnxProcIsSystemPid(pid)) {
        return;   /* 防呆：0/4/8 必丢，不可被用户表覆盖 */
    }
    if (AnxProcIsShuttingDown() || !AnxProcIsAttached()) {
        return;
    }
    if (!AnxProcIsCollectEnabled()) {
        return;
    }

    if (CreateInfo == NULL) {
        /* ---- 进程退出 ---- */
        queue = &g_AnxProc.LifecycleQueue;
        /* 退出时无负载；退出码 0 表示未知（用户态从状态表取） */
        AnxProcPostEvent(queue, ANX_PROC_EVT_PROC_EXIT, 0, pid, 0, 0, 0,
                         0, 0, NULL, 0);
        return;
    }

    /* ---- 进程创建 ---- */
    creatorPid = (ULONG)(ULONG_PTR)CreateInfo->CreatingThreadId.UniqueProcess;
    if (creatorPid == 0) {
        creatorPid = parentPid;
    }

    /* PPID Spoofing：声称父进程 != 真实发起者（§13.1）。
     * 仅标记，不阻断；服务/COM/RPC 代建也会出现此现象，阻断会误伤。 */
    if (parentPid != creatorPid) {
        flags |= ANX_PROC_FLAG_PPID_SPOOFED;
    }

    /* Token 标志（失败降级，用户态补采兜底） */
    flags |= AnxProcGetTokenFlags(pid);
    sessionId = AnxProcGetSessionId(pid);

    /* 命令行负载（三级判空；无命令行则无负载） */
    payload = AnxProcCaptureCommandLine(CreateInfo, &payloadBytes);

    /* 进程名前缀过滤（PROC_PATH_PREFIX）：Drop 命中则不采集 */
    if (CreateInfo->ImageFileName != NULL &&
        CreateInfo->ImageFileName->Buffer != NULL &&
        CreateInfo->ImageFileName->Length > 0) {
        SIZE_T nameChars = CreateInfo->ImageFileName->Length / sizeof(WCHAR);
        if (!AnxProcFilterDecide(ANX_PROC_RULE_PROC_PATH_PREFIX,
                                 CreateInfo->ImageFileName->Buffer, nameChars)) {
            if (payload != NULL) {
                ExFreePoolWithTag(payload, ANX_PROC_TAG_PAYLOAD);
            }
            return;
        }
    }

    queue = &g_AnxProc.LifecycleQueue;
    AnxProcPostEvent(queue, ANX_PROC_EVT_PROC_CREATE, flags, pid, parentPid,
                     creatorPid, sessionId, 0, 0, payload, payloadBytes);
    if (payload != NULL) {
        ExFreePoolWithTag(payload, ANX_PROC_TAG_PAYLOAD);
    }
}

/*
 * 函数名称：AnxProcThreadNotify
 * 函数作用：线程创建/退出回调（PsSetCreateThreadNotifyRoutineEx，Win10 1709+）。
 * 远程线程：CreatingProcessId != ProcessId → ANX_PROC_EVT_REMOTE_THREAD
 * （§13.6）。pid = 目标进程，parent_pid = creator = 注入者，
 * 负载 = 目标线程 ID（UINT32）。线程退出（Reason == ThreadExiting）不采集。
 * Purpose: Thread create/exit callback. Remote thread:
 *          CreatingProcessId != ProcessId => ANX_PROC_EVT_REMOTE_THREAD.
 *          pid = target, creator = injector, payload = target thread ID.
 *          Thread exit (ThreadExiting) is not collected.
 * IRQL：<= DISPATCH_LEVEL
 */
static VOID AnxProcThreadNotify(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId,
                                _In_ BOOLEAN Create)
{
    ULONG targetPid = (ULONG)(ULONG_PTR)ProcessId;
    ULONG creatorPid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();

    if (!Create) {
        return;   /* 线程退出不采集 */
    }
    if (targetPid == 0 || AnxProcIsSystemPid(targetPid)) {
        return;
    }
    if (AnxProcIsShuttingDown() || !AnxProcIsAttached()) {
        return;
    }
    if (!AnxProcIsCollectEnabled()) {
        return;
    }

    /* 同进程线程创建是正常并发，不是远程注入 */
    if (creatorPid == targetPid) {
        return;
    }

    {
        ULONG threadId = (ULONG)(ULONG_PTR)ThreadId;
        AnxProcPostEvent(&g_AnxProc.LifecycleQueue, ANX_PROC_EVT_REMOTE_THREAD,
                         0, targetPid, creatorPid, creatorPid, 0, 0, 0,
                         &threadId, sizeof(threadId));
    }
}

/*
 * 函数名称：AnxProcLoadImageNotify
 * 函数作用：映像加载回调（PsSetLoadImageNotifyRoutine）。
 * IMAGE_LOAD 事件：路径 UTF-16 ≤512 字符；内置 System32 关键 DLL 精确
 * 白名单（AnxProcImageBuiltinSkip，不可被用户表覆盖）→ 丢弃；
 * 用户过滤表 IMAGE_PATH_EXACT / IMAGE_PATH_PREFIX → DROP 命中丢弃。
 * 驱动加载自身（AnXinProcMon.sys）也在 LoadImage 回调中出现，跳过。
 * Purpose: Image load callback. IMAGE_LOAD event: path UTF-16 <= 512 chars;
 *          built-in exact allowlist for critical System32 DLLs (non-
 *          overridable) -> drop; user table IMAGE_PATH_EXACT/IMAGE_PATH_PREFIX
 *          DROP -> drop. Our own image is skipped.
 * IRQL：<= DISPATCH_LEVEL
 */
static VOID AnxProcLoadImageNotify(_In_ PUNICODE_STRING FullImageName,
                                   _In_ HANDLE ProcessId,
                                   _In_ PIMAGE_INFO ImageInfo)
{
    ULONG  pid;
    PUINT8 payload = NULL;
    ULONG  payloadBytes = 0;

    UNREFERENCED_PARAMETER(ImageInfo);

    pid = (ULONG)(ULONG_PTR)ProcessId;
    if (pid == 0 || AnxProcIsSystemPid(pid)) {
        return;
    }
    if (AnxProcIsShuttingDown() || !AnxProcIsAttached()) {
        return;
    }
    if (!AnxProcIsCollectEnabled()) {
        return;
    }

    payload = AnxProcCaptureImagePath(FullImageName, &payloadBytes);
    if (payload == NULL) {
        return;   /* 无路径（非法映像头等），不采集 */
    }

    {
        PCWSTR path = (PCWSTR)payload;
        SIZE_T chars = payloadBytes / sizeof(WCHAR);

        /* 内置精确白名单：System32 关键 DLL 不过滤（防 Phantom DLL，§13.4） */
        if (AnxProcImageBuiltinSkip(path, chars)) {
            ExFreePoolWithTag(payload, ANX_PROC_TAG_PAYLOAD);
            return;
        }

        /* 用户表规则：EXACT（全等）与 PREFIX（前缀）均为 DROP 语义命中则丢弃 */
        if (!AnxProcFilterDecide(ANX_PROC_RULE_IMAGE_PATH_EXACT, path, chars) ||
            !AnxProcFilterDecide(ANX_PROC_RULE_IMAGE_PATH_PREFIX, path, chars)) {
            ExFreePoolWithTag(payload, ANX_PROC_TAG_PAYLOAD);
            return;
        }
    }

    AnxProcPostEvent(&g_AnxProc.LifecycleQueue, ANX_PROC_EVT_IMAGE_LOAD, 0,
                     pid, 0, 0, 0, 0, 0, payload, payloadBytes);
    ExFreePoolWithTag(payload, ANX_PROC_TAG_PAYLOAD);
}

/* ==========================================================================
 * 生命周期回调的注册 / Registration
 * ========================================================================== */

/*
 * 函数名称：AnxProcLifecycleInitialize
 * 函数作用：初始化（无全局状态，恒成功）。
 * Purpose: Initialization (no global state; always succeeds).
 * IRQL：PASSIVE_LEVEL
 */
NTSTATUS AnxProcLifecycleInitialize(void)
{
    return STATUS_SUCCESS;
}

/*
 * 函数名称：AnxProcLifecycleRegisterCallbacks
 * 函数作用：注册进程/线程/映像回调。线程回调必须用
 * PsSetCreateThreadNotifyRoutineEx（Win10 1709+）才能拿到创建者进程 ID。
 * 注册失败不影响其余回调（fail-open：少一个观测面，不阻塞驱动加载）。
 * Purpose: Registers process/thread/image callbacks. Thread callback must use
 *          PsSetCreateThreadNotifyRoutineEx (Win10 1709+) to get the creator.
 *          A failed registration degrades the observation surface only.
 * IRQL：PASSIVE_LEVEL
 */
void AnxProcLifecycleRegisterCallbacks(void)
{
    NTSTATUS status;

    status = PsSetCreateProcessNotifyRoutineEx(AnxProcProcessNotify, FALSE);
    g_ProcessNotifyStatus = status;
    if (NT_SUCCESS(status)) {
        g_ProcessNotifyRegistered = TRUE;
    } else {
        AnxProcError("PsSetCreateProcessNotifyRoutineEx failed 0x%08X\n", status);
    }

    status = PsSetCreateThreadNotifyRoutineEx(PsCreateThreadNotifySubsystems,
                                              (PVOID)AnxProcThreadNotify);
    g_ThreadNotifyStatus = status;
    if (NT_SUCCESS(status)) {
        g_ThreadNotifyRegistered = TRUE;
    } else {
        AnxProcError("PsSetCreateThreadNotifyRoutineEx failed 0x%08X\n", status);
    }

    status = PsSetLoadImageNotifyRoutine(AnxProcLoadImageNotify);
    g_LoadImageStatus = status;
    if (NT_SUCCESS(status)) {
        g_LoadImageRegistered = TRUE;
    } else {
        AnxProcError("PsSetLoadImageNotifyRoutine failed 0x%08X\n", status);
    }
}

/*
 * 函数名称：AnxProcLifecycleCallbackStatus
 * 函数作用：返回回调注册状态位（供 GET_HEALTH 诊断；P6 VM 实测发现
 * 进程回调不产生事件，需区分"注册失败"与"回调被调用但提前返回"）。
 * 编码（P6 诊断，非产品契约）：
 *   bit0-15   进程回调注册错误码（完整 NTSTATUS 低 16 位）
 *   bit16-23  线程回调注册错误码低 8 位
 *   bit24     进程注册成功
 *   bit25     线程注册成功
 *   bit26     映像注册成功
 *   bit27     任一注册失败
 * Purpose: Returns callback registration bits (GET_HEALTH diagnostics).
 * IRQL：任何 / any
 */
ULONG AnxProcLifecycleCallbackStatus(void)
{
    ULONG bits = 0;
    bits |= ((ULONG)g_ProcessNotifyStatus & 0xFFFF) << 0;
    bits |= ((ULONG)g_ThreadNotifyStatus  & 0xFF)   << 16;
    if (g_ProcessNotifyRegistered) { bits |= 0x01000000; }
    if (g_ThreadNotifyRegistered)  { bits |= 0x02000000; }
    if (g_LoadImageRegistered)     { bits |= 0x04000000; }
    if (!NT_SUCCESS(g_ProcessNotifyStatus) ||
        !NT_SUCCESS(g_ThreadNotifyStatus)  ||
        !NT_SUCCESS(g_LoadImageStatus)) {
        bits |= 0x08000000;
    }
    return bits;
}

/*
 * 函数名称：AnxProcLifecycleUnregisterCallbacks
 * 函数作用：注销全部回调（卸载时；进程回调注销后系统保证不再调用）。
 * Purpose: Unregisters all callbacks (on unload).
 * IRQL：PASSIVE_LEVEL
 */
void AnxProcLifecycleUnregisterCallbacks(void)
{
    if (g_ProcessNotifyRegistered) {
        PsSetCreateProcessNotifyRoutineEx(AnxProcProcessNotify, TRUE);
        g_ProcessNotifyRegistered = FALSE;
    }
    if (g_ThreadNotifyRegistered) {
        /* Ex 版本以 NotifyRoutine = NULL 注销（WDK 语义） */
        PsSetCreateThreadNotifyRoutineEx(PsCreateThreadNotifySubsystems, NULL);
        g_ThreadNotifyRegistered = FALSE;
    }
    if (g_LoadImageRegistered) {
        PsRemoveLoadImageNotifyRoutine(AnxProcLoadImageNotify);
        g_LoadImageRegistered = FALSE;
    }
}

/*
 * 函数名称：AnxProcLifecycleShutdown
 * 函数作用：注销回调（与 UnregisterCallbacks 等价，供 DriverUnload 统一调用）。
 * Purpose: Unregisters callbacks (equivalent; called by DriverUnload).
 * IRQL：PASSIVE_LEVEL
 */
void AnxProcLifecycleShutdown(void)
{
    AnxProcLifecycleUnregisterCallbacks();
}