/*++
Copyright (c) AnXin Security. All rights reserved.

Module Name:
    file.c

Abstract:
    AnXinProcMon.sys 文件行为采集 minifilter + 命名管道（NPFS）IPC 采集。
    File behavior collection minifilter + named-pipe (NPFS) IPC collection.

    设计（契约 v6 §4.3）：
    - 只采集不拦截：不注册 post 写回，PreOp 仅作记录后 FLT_PREOP_SUCCESS_NO_CALLBACK。
    - Altitude 380000（FSFilter Anti-Virus 区间 360000-389999），
      高于 AnXinFileProtect 的写阻断 altitude 328800：minifilter 中 altitude
      数值越大越靠近应用层（栈顶），Pre-Op 按 altitude 从高到低调用。
      只有 ProcMon 先于 FileProtect 感知，被 FileProtect 成功阻断的恶意写
      （STATUS_ACCESS_DENIED 不会继续向下传递）才不会被采集漏掉。
    - 文件事件：CREATE / WRITE / DELETE / RENAME（IRP_MJ_CREATE /
      IRP_MJ_WRITE / IRP_MJ_SET_INFORMATION(Delete/SetRenameInfo)）。
    - 过滤：FILE_PATH_PREFIX 规则（DROP 命中丢弃）；内置跳过无（路径由
      用户态规则表控制，默认仅采集非系统目录由 proc_filter_rules.json 定义）。
    - IPC（NPFS 命名管道）：FlGetFileNameInformation 对管道会失败，
      改为直接读 FileObject->FileName（§3.6 踩坑对策）。
      仅当卷设备名为 \Device\NamedPipe 且 InstanceSetup 已确认挂载时采集。
    - NPFS 挂载确认：InstanceSetup 回调中检查卷设备名，仅对 NPFS 卷
      建立实例（Minifilter 由 Altitude 决定，不按卷过滤，但采集侧只认 NPFS）。

    Design (contract v6 §4.3):
    - Collect-only, never block: PreOp records and returns
      FLT_PREOP_SUCCESS_NO_CALLBACK.
    - Altitude 380000 (FSFilter Anti-Virus 360000-389999), ABOVE
      AnXinFileProtect's write-block altitude 328800: in the minifilter stack,
      a higher altitude sits closer to user mode (top of stack) and its Pre-Op
      runs first. ProcMon must see the operation before FileProtect decides,
      otherwise blocked writes (STATUS_ACCESS_DENIED never reaches lower
      filters) are missing from the audit trail.
    - File events: CREATE / WRITE / DELETE / RENAME (IRP_MJ_CREATE /
      IRP_MJ_WRITE / IRP_MJ_SET_INFORMATION(Delete/SetRenameInfo)).
    - Filtering: FILE_PATH_PREFIX rules (DROP hit -> drop).
    - IPC (NPFS): FlGetFileNameInformation fails on pipes; read
      FileObject->FileName directly (contract §3.6 workaround). Collected only
      when the volume is \Device\NamedPipe.

Environment:
    Kernel mode only.

--*/

#include "anx_proc_internal.h"

static PFLT_FILTER g_FileFilter = NULL;

#define ANX_PROC_FILE_ALTITUDE L"380000"

/* ==========================================================================
 * 辅助 / Helpers
 * ========================================================================== */

/*
 * 函数名称：AnxProcIsNpfsFileObject
 * 函数作用：热路径判断 FileObject 是否位于 NPFS（命名管道）。
 * 用 DeviceObject->DeviceType == FILE_DEVICE_NAMED_PIPE 快速判断，
 * 不分配内存（对比 FltGetVolumeName 方案）。NPFS 全卷共享一个
 * \Device\NamedPipe 设备对象，DeviceType 检查足够精确且零分配。
 * Purpose: Hot-path NPFS (named pipe) check on a FileObject via
 *          DeviceObject->DeviceType == FILE_DEVICE_NAMED_PIPE — no
 *          allocation (vs FltGetVolumeName). The whole NPFS is one
 *          \Device\NamedPipe device, so the DeviceType check is precise.
 * IRQL：<= DISPATCH_LEVEL
 */
static BOOLEAN AnxProcIsNpfsFileObject(_In_ PFILE_OBJECT FileObject)
{
    if (FileObject == NULL || FileObject->DeviceObject == NULL) {
        return FALSE;
    }
    return FileObject->DeviceObject->DeviceType == FILE_DEVICE_NAMED_PIPE;
}

/*
 * 函数名称：AnxProcCaptureFileName
 * 函数作用：从 FileObject 安全捕获文件路径（UTF-16），分配非分页缓冲
 * （调用方以 ANX_PROC_TAG_PAYLOAD 释放）。路径为空或非法返回 NULL。
 * Purpose: Captures the file path from a FileObject into a non-paged buffer
 *          (caller frees with ANX_PROC_TAG_PAYLOAD). NULL on empty/invalid.
 * IRQL：<= DISPATCH_LEVEL
 */
static PUINT8 AnxProcCaptureFileName(_In_ PFILE_OBJECT FileObject,
                                     _Out_ ULONG* OutBytes)
{
    PUNICODE_STRING name = NULL;
    ULONG           bytes = 0;
    PUINT8          buffer = NULL;

    *OutBytes = 0;

    if (FileObject == NULL) {
        return NULL;
    }
    name = &FileObject->FileName;
    if (name->Buffer == NULL || name->Length == 0) {
        return NULL;
    }

    bytes = name->Length;
    if (bytes > ANX_PROC_MAX_PATH * sizeof(WCHAR)) {
        bytes = ANX_PROC_MAX_PATH * sizeof(WCHAR);
    }
    bytes &= ~1u;

    buffer = (PUINT8)ExAllocatePool2(POOL_FLAG_NON_PAGED, bytes,
                                     ANX_PROC_TAG_PAYLOAD);
    if (buffer == NULL) {
        return NULL;
    }
    RtlCopyMemory(buffer, name->Buffer, bytes);
    *OutBytes = bytes;
    return buffer;
}

/*
 * 函数名称：AnxProcShouldCollectFile
 * 函数作用：文件事件采集决策：PID 防呆 + FILE_PATH_PREFIX 过滤。
 * Purpose: File event collect decision: PID fail-safe + FILE_PATH_PREFIX filter.
 * IRQL：<= DISPATCH_LEVEL
 */
static BOOLEAN AnxProcShouldCollectFile(_In_ ULONG Pid, _In_opt_ PCWSTR Path,
                                        _In_ SIZE_T PathChars)
{
    if (Pid == 0 || AnxProcIsSystemPid(Pid)) {
        return FALSE;
    }
    if (AnxProcIsShuttingDown() || !AnxProcIsAttached()) {
        return FALSE;
    }
    if (!AnxProcIsCollectEnabled()) {
        return FALSE;
    }
    if (Path == NULL || PathChars == 0) {
        return FALSE;
    }
    return AnxProcFilterDecide(ANX_PROC_RULE_FILE_PATH_PREFIX, Path, PathChars);
}

/* ==========================================================================
 * PreOp 回调 / PreOp callbacks
 * ========================================================================== */

static FLT_PREOP_CALLBACK_STATUS
AnxProcPreCreate(_Inout_ PFLT_CALLBACK_DATA Data,
                 _In_ PCFLT_RELATED_OBJECTS FltObjects,
                 _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    ULONG   pid;
    PUINT8  path = NULL;
    ULONG   pathBytes = 0;

    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Data);

    if (FltObjects->FileObject == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();

    /* NPFS：管道连接（IPC_CONNECT 事件） */
    if (FltObjects->Volume != NULL && AnxProcIsNpfsFileObject(FltObjects->FileObject)) {
        path = AnxProcCaptureFileName(FltObjects->FileObject, &pathBytes);
        if (path != NULL) {
            PCWSTR p = (PCWSTR)path;
            SIZE_T chars = pathBytes / sizeof(WCHAR);

            if (AnxProcFilterDecide(ANX_PROC_RULE_IPC_NAME_PREFIX, p, chars)) {
                AnxProcPostEvent(&g_AnxProc.BehaviorQueue, ANX_PROC_EVT_IPC_CONNECT,
                                 0, pid, 0, 0, 0, 0, 0, path, pathBytes);
            }
            ExFreePoolWithTag(path, ANX_PROC_TAG_PAYLOAD);
        }
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* 常规文件创建（FILE_CREATE） */
    path = AnxProcCaptureFileName(FltObjects->FileObject, &pathBytes);
    if (path != NULL) {
        PCWSTR p = (PCWSTR)path;
        SIZE_T chars = pathBytes / sizeof(WCHAR);

        if (AnxProcShouldCollectFile(pid, p, chars)) {
            AnxProcPostEvent(&g_AnxProc.BehaviorQueue, ANX_PROC_EVT_FILE_CREATE,
                             0, pid, 0, 0, 0, 0, 0, path, pathBytes);
        }
        ExFreePoolWithTag(path, ANX_PROC_TAG_PAYLOAD);
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static FLT_PREOP_CALLBACK_STATUS
AnxProcPreWrite(_Inout_ PFLT_CALLBACK_DATA Data,
                _In_ PCFLT_RELATED_OBJECTS FltObjects,
                _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    ULONG   pid;
    PUINT8  path = NULL;
    ULONG   pathBytes = 0;

    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (FltObjects->FileObject == NULL ||
        FltObjects->Volume == NULL || AnxProcIsNpfsFileObject(FltObjects->FileObject)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();

    path = AnxProcCaptureFileName(FltObjects->FileObject, &pathBytes);
    if (path != NULL) {
        PCWSTR p = (PCWSTR)path;
        SIZE_T chars = pathBytes / sizeof(WCHAR);

        if (AnxProcShouldCollectFile(pid, p, chars)) {
            AnxProcPostEvent(&g_AnxProc.BehaviorQueue, ANX_PROC_EVT_FILE_WRITE,
                             0, pid, 0, 0, 0, 0, 0, path, pathBytes);
        }
        ExFreePoolWithTag(path, ANX_PROC_TAG_PAYLOAD);
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static FLT_PREOP_CALLBACK_STATUS
AnxProcPreSetInformation(_Inout_ PFLT_CALLBACK_DATA Data,
                         _In_ PCFLT_RELATED_OBJECTS FltObjects,
                         _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    ULONG               pid;
    UINT16              eventType = 0;
    PUINT8              path = NULL;
    ULONG               pathBytes = 0;
    FILE_INFORMATION_CLASS infoClass;

    UNREFERENCED_PARAMETER(CompletionContext);

    if (FltObjects->FileObject == NULL ||
        FltObjects->Volume == NULL || AnxProcIsNpfsFileObject(FltObjects->FileObject)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

    switch (infoClass) {
    case FileDispositionInformation:
    case FileDispositionInformationEx:
        eventType = ANX_PROC_EVT_FILE_DELETE;
        break;
    case FileRenameInformation:
    case FileRenameInformationEx:
        eventType = ANX_PROC_EVT_FILE_RENAME;
        break;
    default:
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();

    path = AnxProcCaptureFileName(FltObjects->FileObject, &pathBytes);
    if (path != NULL) {
        PCWSTR p = (PCWSTR)path;
        SIZE_T chars = pathBytes / sizeof(WCHAR);

        if (AnxProcShouldCollectFile(pid, p, chars)) {
            AnxProcPostEvent(&g_AnxProc.BehaviorQueue, eventType,
                             0, pid, 0, 0, 0, 0, 0, path, pathBytes);
        }
        ExFreePoolWithTag(path, ANX_PROC_TAG_PAYLOAD);
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/* ==========================================================================
 * Instance 回调（NPFS 挂载确认，§3.6） / Instance callbacks
 * ========================================================================== */

static NTSTATUS AnxProcInstanceSetup(_In_ PCFLT_RELATED_OBJECTS FltObjects,
                                     _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
                                     _In_ DEVICE_TYPE VolumeDeviceType,
                                     _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);

    /*
     * 对 NPFS 卷与常规卷都建立实例（采集两侧），但 pre-op 内部按
     * AnxProcIsNpfsFileObject 分流：NPFS 走 IPC_CONNECT，其余走文件事件。
     * 任何卷都接受挂载。
     */
    return STATUS_SUCCESS;
}

static NTSTATUS AnxProcInstanceTeardownStart(_In_ PCFLT_RELATED_OBJECTS FltObjects,
                                             _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    return STATUS_SUCCESS;
}

static NTSTATUS AnxProcInstanceTeardownComplete(_In_ PCFLT_RELATED_OBJECTS FltObjects,
                                                _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    return STATUS_SUCCESS;
}

/* ==========================================================================
 * 初始化 / Initialization
 * ========================================================================== */

static const FLT_OPERATION_REGISTRATION AnxProcFileOperations[] = {
    { IRP_MJ_CREATE, 0, AnxProcPreCreate, NULL, NULL },
    { IRP_MJ_WRITE, 0, AnxProcPreWrite, NULL, NULL },
    { IRP_MJ_SET_INFORMATION, 0, AnxProcPreSetInformation, NULL, NULL },
    { IRP_MJ_OPERATION_END }
};

static const FLT_REGISTRATION AnxProcFileRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,                            /* Flags */
    NULL,                         /* ContextRegistration */
    AnxProcFileOperations,        /* OperationRegistration */
    NULL,                         /* FilterUnloadCallback */
    AnxProcInstanceSetup,         /* InstanceSetupCallback */
    NULL,                         /* InstanceQueryTeardownCallback */
    AnxProcInstanceTeardownStart, /* InstanceTeardownStartCallback */
    AnxProcInstanceTeardownComplete, /* InstanceTeardownCompleteCallback */
    NULL,                         /* GenerateFileNameCallback */
    NULL,                         /* NormalizeNameComponentCallback */
    NULL,                         /* NormalizeContextCleanupCallback */
    NULL,                         /* TransactionNotificationCallback */
    NULL,                         /* NormalizeNameComponentExCallback */
    NULL                          /* SectionNotificationCallback */
};

/*
 * 函数名称：AnxProcFileInitialize
 * 函数作用：注册文件采集 minifilter。
 * Purpose: Registers the file collection minifilter.
 * IRQL：PASSIVE_LEVEL
 */
NTSTATUS AnxProcFileInitialize(_In_ PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status;

    status = FltRegisterFilter(DriverObject, &AnxProcFileRegistration,
                               &g_FileFilter);
    if (!NT_SUCCESS(status)) {
        AnxProcError("FltRegisterFilter failed 0x%08X\n", status);
        return status;
    }

    status = FltStartFiltering(g_FileFilter);
    if (!NT_SUCCESS(status)) {
        AnxProcError("FltStartFiltering failed 0x%08X\n", status);
        FltUnregisterFilter(g_FileFilter);
        g_FileFilter = NULL;
        return status;
    }

    return STATUS_SUCCESS;
}

/*
 * 函数名称：AnxProcFileShutdown
 * 函数作用：注销文件采集 minifilter。
 * Purpose: Unregisters the file collection minifilter.
 * IRQL：PASSIVE_LEVEL
 */
void AnxProcFileShutdown(void)
{
    if (g_FileFilter != NULL) {
        FltUnregisterFilter(g_FileFilter);
        g_FileFilter = NULL;
    }
}