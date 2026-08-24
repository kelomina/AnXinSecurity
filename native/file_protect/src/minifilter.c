/*++
Copyright (c) AnXin Security. All rights reserved.

Module Name:
    minifilter.c

Abstract:
    AnXin Security file protection minifilter driver.
    Prevents unauthorized processes from modifying, deleting, or renaming
    AnXin Security's critical files and directories.

    Architecture:
    - IRP_MJ_CREATE: blocks opens with write/delete/overwrite/delete-on-close access
    - IRP_MJ_WRITE: blocks writes via pre-existing handles
    - IRP_MJ_SET_INFORMATION: blocks delete/rename/truncate/security-change
    - IRP_MJ_FILE_SYSTEM_CONTROL: blocks FSCTL zero/offload-write
    - IRP_MJ_ACQUIRE_FOR_SECTION_SYNC: blocks writable memory-mapped file views
    - Communication port for user-mode service to manage protected paths
    - Caller authorization verified by process name + path
    - Communication port access restricted to anxin-security.exe only

Environment:
    Kernel mode only. Requires FltMgr to be loaded.

--*/

#include <ntifs.h>
#include <fltkernel.h>
#include <ntstrsafe.h>

#pragma prefast(disable: __WARNING_INVALID_PAGING_LEVEL, "Prefast warnings")

// PsGetProcessImageFileName is no longer declared in WDK 10.0.28000 headers
// but is still exported from ntoskrnl.exe.
extern PCHAR PsGetProcessImageFileName(PEPROCESS Process);

/*
 * 可信安装目录辅助函数（VUL-046 重构 / VUL-097 根因修复）。
 * 定义在本文件后部，但 DriverEntry 与 IsCallerAuthorized 会先调用，故前向声明。
 */
static USHORT  AnxinCountSeparators(_In_ PCWSTR buf, _In_ USHORT len);
static BOOLEAN AnxinIsValidVolumeRoot(_In_ PCWSTR buf, _In_ USHORT len);
static BOOLEAN AnxinIsInTrustedInstallDir(_In_ PUNICODE_STRING fullPath, _In_ USHORT tailChars);
static VOID    AnxinLoadTrustedInstallDir(VOID);


// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#define DRIVER_TAG              'xpFA'
#define PORT_NAME               L"\\AnXinFileProtectPort"
#define MAX_PROTECTED_PATHS     128
#define MAX_PATH_LENGTH         520
#define POOL_TAG                'xFAn'
#define ANXIN_EXE_NAME          L"anxin-security.exe"
/*
 * 三进程拆分（2026-08）后的产品家族名表。用于 IsCallerAuthorized 的
 * 预筛与完整路径确认。授权仍需通过可信安装目录校验。
 */
static const WCHAR * const ANXIN_FAMILY_WIDE[] = {
    L"anxin-security.exe",
    L"anxinsecurity.exe",
    L"anxinservice.exe",
    L"anxintray.exe",
};
#define ANXIN_FAMILY_COUNT      4
/* VUL-038: 可信安装目录，路径必须包含此组件 */
#define ANXIN_TRUSTED_DIR       L"\\anxinsecurity\\"
/*
 * EPROCESS.ImageFileName 是 15 字节 ANSI 且会截断，预筛用的 ANSI 常量与比较长度
 * 单独定义。14 个字符（"anxin-security"）落在截断长度内，足够做快速排除。
 * EPROCESS.ImageFileName is a truncated 15-byte ANSI field, so the prefilter's
 * ANSI constant and compare length are defined separately. 14 characters
 * ("anxin-security") fit inside the truncation limit and suffice as a fast reject.
 */
#define ANXIN_EXE_NAME_ANSI     "anxin-security.exe"
#define ANXIN_ANSI_COMPARE_LEN  14
#define CREATE_ALWAYS           2           // Win32 constant, not in kernel headers

// ---------------------------------------------------------------------------
// Complete dangerous access mask for file opens
// ---------------------------------------------------------------------------
// FILE_WRITE_DATA / FILE_APPEND_DATA  - write file content
// FILE_WRITE_ATTRIBUTES / FILE_WRITE_EA - modify metadata
// FILE_ADD_FILE / FILE_ADD_SUBDIRECTORY - create in protected dir
// FILE_DELETE_CHILD - delete child in protected dir
// DELETE - delete the file itself
// WRITE_DAC / WRITE_OWNER - rewrite security descriptor
// ACCESS_SYSTEM_SECURITY - access SACL
#define DANGEROUS_FILE_ACCESS_MASK  (FILE_WRITE_DATA             | \
                                     FILE_APPEND_DATA            | \
                                     FILE_WRITE_ATTRIBUTES       | \
                                     FILE_WRITE_EA               | \
                                     FILE_ADD_FILE               | \
                                     FILE_ADD_SUBDIRECTORY       | \
                                     FILE_DELETE_CHILD           | \
                                     DELETE                      | \
                                     WRITE_DAC                   | \
                                     WRITE_OWNER                 | \
                                     ACCESS_SYSTEM_SECURITY)

// ---------------------------------------------------------------------------
// CreateDisposition values that modify/overwrite existing content
// ---------------------------------------------------------------------------
#define DANGEROUS_DISPOSITION_MASK  (FILE_SUPERSEDE              | \
                                     FILE_OVERWRITE              | \
                                     FILE_OVERWRITE_IF)

// ---------------------------------------------------------------------------
// Registry self-protection (service key protection via CmCallback)
// ---------------------------------------------------------------------------
#define MAX_PROTECTED_KEYS      4
#define REG_PROTECT_ALTITUDE    L"325803"

/* 服务注册表键路径（非 const：供 RTL_CONSTANT_STRING 静态初始化，避免 C4090） */
static WCHAR SVC_KEY_PROCPROTECT_STR[] = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\AnXinProcProtect";
static WCHAR SVC_KEY_FILEPROTECT_STR[] = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\AnXinFileProtect";
static WCHAR SVC_KEY_NETFILTER_STR[]   = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\AnXinNetFilter";
/*
 * 应用自身服务键。注册表保护从 AnXinProcProtect 整体迁移到本驱动时，Rust 侧
 * register_registry_protection() 曾用死的 REG_KEY IOCTL 保护这个键；迁移后若不放
 * 进来，攻击者改写 ImagePath/Start 即可禁用或劫持自保服务。与三个驱动服务键同等保护：
 * CmCallback 挡住非授权写/删，SCM(services.exe)/SYSTEM/anxin-security.exe 仍可正常读写。
 * The app's own service key. When registry protection moved here from AnXinProcProtect,
 * the Rust-side register_registry_protection() had guarded this key via the now-dead REG_KEY
 * IOCTLs; leaving it out would let an attacker rewrite ImagePath/Start to disable or hijack the
 * self-protection service. Protected alongside the three driver service keys: CmCallback blocks
 * unauthorized writes/deletes while SCM(services.exe)/SYSTEM/anxin-security.exe keep full access.
 */
static WCHAR SVC_KEY_APP_STR[] = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\AnXinSecurityService";

static PVOID         g_RegProtectedKeyObjects[MAX_PROTECTED_KEYS] = {0};
static HANDLE        g_RegProtectedKeyHandles[MAX_PROTECTED_KEYS] = {0};
/*
 * CmCallbackGetKeyObjectIDEx 返回的稳定 ObjectID（WDK 10.0.28000.0 中为 PULONG_PTR）。
 * 与对象指针不同，同一个注册表键无论通过什么 handle 打开，ObjectID 都相同，
 * 因此可以可靠地识别 SCM (services.exe) 对受保护键的操作。
 * 只缓存 ObjectID（ULONG_PTR 值），不请求 ObjectName（PCUNICODE_STRING），
 * 因此无需调用 CmCallbackReleaseKeyObjectIDEx。
 *
 * Stable ObjectID from CmCallbackGetKeyObjectIDEx (PULONG_PTR in WDK
 * 10.0.28000.0). The same registry key has the same ObjectID regardless
 * of which handle opened it, so SCM operations are reliably identified.
 * Only ObjectID is cached; ObjectName (PCUNICODE_STRING) is NEVER requested,
 * so CmCallbackReleaseKeyObjectIDEx need not be called.
 */
static ULONG_PTR     g_RegProtectedKeyIDs[MAX_PROTECTED_KEYS] = {0};
static ULONG         g_RegProtectedKeyCount = 0;
static LARGE_INTEGER g_RegCookie = {0};
static BOOLEAN       g_RegCmRegistered = FALSE;
static ULONGLONG     g_RegGracePeriodEnd = 0;

/*
 * VUL-098 / VUL-101 卸载授权窗口。
 * 授权由完整路径验证的 anxin-security.exe（或 SYSTEM）经 FpmAuthorizeUninstall
 * 消息授予，仅用于：让 SCM (services.exe) 在窗口内删除 4 个受保护服务键（卸载/升级），
 * 并让卸载器对 3 个 .sys 做重启删除登记。窗口到期自动失效。
 * Uninstall/upgrade authorization window. Granted only by a full-path-verified
 * anxin-security.exe (or SYSTEM) via FpmAuthorizeUninstall; it lets SCM delete the
 * four protected service keys (uninstall/upgrade) and lets the uninstaller register
 * reboot-deletion of the three .sys files. Expires automatically.
 */
static BOOLEAN     g_UninstallAuthorized = FALSE;
static ULONGLONG   g_UninstallGraceEnd = 0;
#define UNINSTALL_GRACE_100NS (15ULL * 60ULL * 10000000ULL)  /* 15 分钟 / 15 minutes */

// ---------------------------------------------------------------------------
// Message definitions for communication port
// ---------------------------------------------------------------------------

typedef enum _FPM_MESSAGE_TYPE {
    FpmAddPath          = 1,
    FpmRemovePath       = 2,
    FpmClearAll         = 3,
    FpmQueryPaths       = 4,
    FpmAuthorizeUninstall = 5,
} FPM_MESSAGE_TYPE;

typedef struct _FPM_MESSAGE {
    FPM_MESSAGE_TYPE MessageType;
    WCHAR             Path[MAX_PATH_LENGTH];
} FPM_MESSAGE, *PFPM_MESSAGE;

/*
 * FpmQueryPaths response format:
 *   ULONG PathCount
 *   WCHAR Path[PathCount][MAX_PATH_LENGTH] (each null-terminated)
 */
typedef struct _FPM_QUERY_RESPONSE {
    ULONG    PathCount;
    WCHAR    Paths[MAX_PROTECTED_PATHS][MAX_PATH_LENGTH];
} FPM_QUERY_RESPONSE, *PFPM_QUERY_RESPONSE;

// ---------------------------------------------------------------------------
// Protected path entry
// ---------------------------------------------------------------------------

typedef struct _PROTECTED_PATH_ENTRY {
    UNICODE_STRING Path;   // stored in NT namespace, uppercased
} PROTECTED_PATH_ENTRY, *PPROTECTED_PATH_ENTRY;

typedef struct _PROTECTED_PATH_LIST {
    ULONG               Count;
    PROTECTED_PATH_ENTRY Entries[MAX_PROTECTED_PATHS];
} PROTECTED_PATH_LIST, *PPROTECTED_PATH_LIST;

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

static PFLT_FILTER         g_FilterHandle    = NULL;
static PFLT_PORT           g_ServerPort       = NULL;
static PFLT_PORT           g_ClientPort       = NULL;
static PROTECTED_PATH_LIST g_ProtectedPaths   = {0};
static FAST_MUTEX          g_PathListLock     = {0};
static BOOLEAN             g_Registered       = FALSE;
static BOOLEAN             g_ShuttingDown     = FALSE;
static BOOLEAN             g_FilteringStarted = FALSE;

// ---------------------------------------------------------------------------
// Forward declarations
// ---------------------------------------------------------------------------

DRIVER_INITIALIZE DriverEntry;
NTSTATUS          DriverEntry(_In_ PDRIVER_OBJECT, _In_ PUNICODE_STRING);
static void       BootReinitCallback(_In_ PDRIVER_OBJECT DriverObject, _In_ PVOID Context, _In_ ULONG Count);
NTSTATUS          MinifilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS);
NTSTATUS          MinifilterInstanceSetup(_In_ PCFLT_RELATED_OBJECTS, _In_ FLT_INSTANCE_SETUP_FLAGS, _In_ DEVICE_TYPE, _In_ FLT_FILESYSTEM_TYPE);
NTSTATUS          MinifilterInstanceQueryTeardown(_In_ PCFLT_RELATED_OBJECTS, _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS);
VOID              MinifilterInstanceTeardownStart(_In_ PCFLT_RELATED_OBJECTS, _In_ FLT_INSTANCE_TEARDOWN_FLAGS);
VOID              MinifilterInstanceTeardownComplete(_In_ PCFLT_RELATED_OBJECTS, _In_ FLT_INSTANCE_TEARDOWN_FLAGS);

FLT_PREOP_CALLBACK_STATUS MinifilterPreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
FLT_PREOP_CALLBACK_STATUS MinifilterPreWrite(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
FLT_PREOP_CALLBACK_STATUS MinifilterPreSetInformation(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
FLT_PREOP_CALLBACK_STATUS MinifilterPreFileSystemControl(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
FLT_PREOP_CALLBACK_STATUS MinifilterPreAcquireForSectionSync(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);

NTSTATUS PortConnect(_In_ PFLT_PORT, _In_ PVOID, _In_reads_bytes_opt_(ULONG) PVOID, _In_ ULONG, _Outptr_result_maybenull_ PVOID*);
VOID     PortDisconnect(_In_opt_ PVOID);
NTSTATUS PortMessage(_In_ PVOID, _In_reads_bytes_opt_(ULONG) PVOID, _In_ ULONG, _Out_writes_bytes_to_opt_(ULONG, PULONG) PVOID, _In_ ULONG, _Out_ PULONG);

BOOLEAN  IsPathProtected(_In_ PUNICODE_STRING FilePath);
BOOLEAN  IsKernelDriverFile(_In_ PCUNICODE_STRING NormalizedPath);
NTSTATUS AddProtectedPath(_In_ PUNICODE_STRING Path);
NTSTATUS RemoveProtectedPath(_In_ PUNICODE_STRING Path);
VOID     ClearProtectedPaths(VOID);
VOID     PathToUpper(_Inout_ PUNICODE_STRING Path);

BOOLEAN  IsCallerAuthorized(VOID);

/* Registry self-protection */
static BOOLEAN  IsRegProtectedKeyObject(PVOID Object);
static BOOLEAN  IsRegCallerAuthorized(VOID);
static void     RegProtectServiceKeysDacl(VOID);
static NTSTATUS RegProtectCallback(PVOID CallbackContext, PVOID Argument1, PVOID Argument2);

// ===========================================================================
// Boot reinitialization callback (boot-start support)
// ===========================================================================

/*
 * IoRegisterBootDriverReinitialization 回调。
 * 在所有 boot-start 驱动的 DriverEntry 完成后由 I/O 管理器调用，
 * 此时 FltMgr 及其依赖的存储栈已就绪，可以安全启动过滤。
 * Called by the I/O manager after all boot-start DriverEntry routines
 * have completed. FltMgr and the storage stack are ready at this point.
 */
static void BootReinitCallback(PDRIVER_OBJECT DriverObject, PVOID Context, ULONG Count)
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Count);

    if (g_FilteringStarted)
        return;

    status = FltStartFiltering(g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AnXinFlt] FltStartFiltering (boot reinit): 0x%08lX\n", status);
        /*
         * 过滤启动失败不回滚：驱动保持加载，通信端口仍可用，
         * 用户态服务可查询状态。后续可由产品自身重试或告警。
         * Filtering failure is not rolled back: the driver stays loaded,
         * the communication port remains available for status queries.
         */
        return;
    }

    g_FilteringStarted = TRUE;
    DbgPrint("[AnXinFlt] FltStartFiltering OK (boot reinit, count=%lu)\n", Count);

    /* --- 注册表自保 ---
     * 必须先 CmRegisterCallbackEx 获得 Cookie，再 RegProtectServiceKeysDacl，
     * 因为后者需要 Cookie 来调用 CmCallbackGetKeyObjectIDEx 缓存稳定 ObjectID。
     * 顺序颠倒会导致 ObjectID 无法缓存，回调中对象指针比较失败（sc delete 漏洞）。
     *
     * Must CmRegisterCallbackEx first to obtain the Cookie, then
     * RegProtectServiceKeysDacl, because the latter needs the Cookie to call
     * CmCallbackGetKeyObjectIDEx for caching stable ObjectIDs. Reversed order
     * would leave ObjectIDs uncached, causing object-pointer comparison to
     * fail in the callback (the sc delete vulnerability).
     */
    g_RegGracePeriodEnd = KeQueryInterruptTime() + (60ULL * 1000ULL * 1000ULL * 10ULL);
    {
        UNICODE_STRING altitude;
        RtlInitUnicodeString(&altitude, REG_PROTECT_ALTITUDE);
        NTSTATUS cmStatus = CmRegisterCallbackEx(RegProtectCallback, &altitude,
                                                 DriverObject, NULL, &g_RegCookie, NULL);
        if (NT_SUCCESS(cmStatus)) {
            g_RegCmRegistered = TRUE;
            DbgPrint("[AnXinFlt] CmRegisterCallbackEx OK\n");
        } else {
            DbgPrint("[AnXinFlt] CmRegisterCallbackEx failed: 0x%08lX\n", cmStatus);
        }
    }
    RegProtectServiceKeysDacl();
    DriverObject->DriverUnload = NULL;
}

// ===========================================================================
// Driver entry
// ===========================================================================

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;

    DbgPrint("[AnXinFlt] DriverEntry: loading...\n");
    ExInitializeFastMutex(&g_PathListLock);

    // -----------------------------------------------------------------------
    // 1. Register operation callbacks with FltMgr
    // -----------------------------------------------------------------------
    FLT_OPERATION_REGISTRATION callbacks[] = {
        { IRP_MJ_CREATE,                         0, MinifilterPreCreate,                    NULL },
        { IRP_MJ_WRITE,                          0, MinifilterPreWrite,                     NULL },
        { IRP_MJ_SET_INFORMATION,                0, MinifilterPreSetInformation,            NULL },
        { IRP_MJ_FILE_SYSTEM_CONTROL,            0, MinifilterPreFileSystemControl,         NULL },
        { IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION, 0, MinifilterPreAcquireForSectionSync, NULL },
        { IRP_MJ_OPERATION_END }
    };

    FLT_REGISTRATION reg = { 0 };
    reg.Size                        = sizeof(FLT_REGISTRATION);
    reg.Version                     = FLT_REGISTRATION_VERSION;
    reg.FilterUnloadCallback        = MinifilterUnload;
    reg.InstanceSetupCallback       = MinifilterInstanceSetup;
    reg.InstanceQueryTeardownCallback = MinifilterInstanceQueryTeardown;
    reg.InstanceTeardownStartCallback  = MinifilterInstanceTeardownStart;
    reg.InstanceTeardownCompleteCallback = MinifilterInstanceTeardownComplete;
    reg.OperationRegistration       = callbacks;

    status = FltRegisterFilter(DriverObject, &reg, &g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AnXinFlt] FltRegisterFilter: 0x%08lX\n", status);
        return status;
    }
    g_Registered = TRUE;

    /*
     * 自保：清除 DriverUnload，防止 sc stop 卸载 minifilter。
     *
     * FltRegisterFilter 会把 DriverObject->DriverUnload 设为 FltMgr 的卸载
     * 处理例程。当 sc stop 被调用时，SCM 会调用这个例程，FltMgr 再调用
     * 我们的 FilterUnloadCallback。即使 FilterUnloadCallback 返回
     * STATUS_FLT_DO_NOT_DETACH，SCM 仍可能把服务标记为已停止——实测在
     * Windows 10 21H2 上正是如此。
     *
     * 将 DriverUnload 设为 NULL 后，SCM 发现没有卸载例程就直接拒绝停止
     * 请求（错误码 1052「请求的控件对此服务无效」），与 ProcProtect 和
     * NetFilter 的防卸载机制一致。
     *
     * FltUnloadFilter 内核 API 仍可卸载过滤器（用于产品自身的授权卸载
     * 流程），FilterUnloadCallback 也会被 FltMgr 正常调用。
     *
     * Self-protection: clear DriverUnload to prevent sc stop from unloading
     * the minifilter. FltRegisterFilter sets DriverObject->DriverUnload to
     * FltMgr's handler; we clear it after registration. SCM rejects stop
     * requests when DriverUnload is NULL (error 1052), matching the anti-
     * unload mechanism used by ProcProtect and NetFilter. FltUnloadFilter
     * kernel API can still unload the filter for authorized uninstall.
     */
    // DriverObject->DriverUnload = NULL; // Keep FltMgr DriverUnload binding intact for minifilter

    // -----------------------------------------------------------------------
    // 2. Create communication port (verified caller only)
    // -----------------------------------------------------------------------
    /* VUL-097 根因修复：先加载可信安装目录（从服务 ImagePath 读取，默认
     * "\Program Files\AnXinSecurity"），PortConnect 的 IsCallerAuthorized
     * 依赖它做全路径相等校验。 */
    AnxinLoadTrustedInstallDir();

    UNICODE_STRING portName;
    RtlInitUnicodeString(&portName, PORT_NAME);

    PSECURITY_DESCRIPTOR sd = NULL;
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) goto CleanupUnreg;

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &portName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, sd);

    status = FltCreateCommunicationPort(g_FilterHandle, &g_ServerPort, &oa,
                                        NULL, PortConnect, PortDisconnect, PortMessage, 1);
    FltFreeSecurityDescriptor(sd);
    if (!NT_SUCCESS(status)) { DbgPrint("[AnXinFlt] FltCreateCommunicationPort: 0x%08lX\n", status); goto CleanupUnreg; }

    // -----------------------------------------------------------------------
    // 3. Start filtering
    //    对于 SYSTEM_START 驱动，DriverEntry 执行时文件系统已就绪，可以直接
    //    启动过滤。如果直接启动失败（仅在 boot-start 场景下文件系统未就绪），
    //    才回退到 reinitialization 回调中重试。
    //
    //    此前 FltStartFiltering 被无条件延迟到 BootReinitCallback，但
    //    IoRegisterBootDriverReinitialization 只对 boot-start 驱动有效——
    //    当驱动被 sc start 手动启动时，BootReinitCallback 永远不会被调用，
    //    导致过滤器和注册表保护都不会激活。
    //
    //    For SYSTEM_START drivers, the file system is ready when DriverEntry
    //    runs, so we can start filtering immediately. If that fails (only
    //    possible at boot-start when the file system is not yet ready), fall
    //    back to a reinitialization callback.
    //
    //    Previously FltStartFiltering was unconditionally deferred to
    //    BootReinitCallback, but IoRegisterBootDriverReinitialization only
    //    works for boot-start drivers — when the driver is manually started
    //    via sc start, BootReinitCallback is never called, leaving both the
    //    filter and the registry protection inactive.
    // -----------------------------------------------------------------------
    status = FltStartFiltering(g_FilterHandle);
    if (NT_SUCCESS(status)) {
        g_FilteringStarted = TRUE;
        DbgPrint("[AnXinFlt] FltStartFiltering OK (from DriverEntry)\n");

        /*
         * 注册表自保：先 CmRegisterCallbackEx 获得 Cookie，再 RegProtectServiceKeysDacl。
         * 顺序不能颠倒：后者需要 Cookie 来调用 CmCallbackGetKeyObjectIDEx 缓存
         * 稳定 ObjectID，否则回调中只能做对象指针比较，无法识别 SCM 的操作。
         *
         * Registry self-protection: CmRegisterCallbackEx first to obtain the
         * Cookie, then RegProtectServiceKeysDacl. Order matters: the latter
         * needs the Cookie to cache stable ObjectIDs via
         * CmCallbackGetKeyObjectIDEx; without it, the callback falls back to
         * object-pointer comparison, which cannot identify SCM operations.
         */
        g_RegGracePeriodEnd = KeQueryInterruptTime() + (60ULL * 1000ULL * 1000ULL * 10ULL);
        UNICODE_STRING altitude;
        RtlInitUnicodeString(&altitude, REG_PROTECT_ALTITUDE);
        NTSTATUS cmStatus = CmRegisterCallbackEx(RegProtectCallback, &altitude,
                                                 DriverObject, NULL, &g_RegCookie, NULL);
        if (NT_SUCCESS(cmStatus)) {
            g_RegCmRegistered = TRUE;
            DbgPrint("[AnXinFlt] CmRegisterCallbackEx OK (from DriverEntry)\n");
        } else {
            DbgPrint("[AnXinFlt] CmRegisterCallbackEx failed: 0x%08lX\n", cmStatus);
        }
        RegProtectServiceKeysDacl();

        /*
         * 自保：在 FltStartFiltering 成功且注册表保护就绪后，将 DriverUnload 设为 NULL。
         * 此时 FltMgr 已完成微过滤器加载与卷附加。设置 DriverUnload = NULL 后，
         * SCM 收到 sc stop 请求时直接拒绝（错误 1052「请求的控件对此服务无效」），
         * 实现与 ProcProtect 一致的防卸载防护。
         */
        DriverObject->DriverUnload = NULL;
    } else {
        DbgPrint("[AnXinFlt] FltStartFiltering deferred (0x%08lX), registering reinit\n", status);
        IoRegisterBootDriverReinitialization(DriverObject, BootReinitCallback, NULL);
    }

    DbgPrint("[AnXinFlt] Loaded (altitude 328800, boot-start)\n");
    return STATUS_SUCCESS;

CleanupUnreg: if (g_Registered) { FltUnregisterFilter(g_FilterHandle); g_Registered = FALSE; }
    return status;
}

// ===========================================================================
// Unload
// ===========================================================================

NTSTATUS MinifilterUnload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
    /*
     * 自保：除系统关机或 Filter Manager 强制卸载外，拒绝一切卸载请求。
     * fltmc unload / FltUnloadFilter 不带 MANDATORY 标志，会被直接拒绝。
     * 只有系统关机（FLTFL_FILTER_UNLOAD_MANDATORY）才放行，否则文件保护
     * 会在运行期间被攻击者一条命令摘掉。
     * Self-protection: refuse all unload requests except mandatory ones
     * (system shutdown or Filter Manager forced unload). fltmc unload does
     * not set the MANDATORY flag and will be rejected outright.
     */
    if (!(Flags & FLTFL_FILTER_UNLOAD_MANDATORY)) {
        DbgPrint("[AnXinFlt] Unload REFUSED (non-mandatory)\n");
        return STATUS_FLT_DO_NOT_DETACH;
    }

    DbgPrint("[AnXinFlt] Unload (mandatory)\n");
    g_ShuttingDown = TRUE;

    /* --- 注册表自保清理 --- */
    if (g_RegCmRegistered) {
        CmUnRegisterCallback(g_RegCookie);
        g_RegCmRegistered = FALSE;
    }
    for (ULONG i = 0; i < g_RegProtectedKeyCount; i++) {
        if (g_RegProtectedKeyObjects[i]) ObDereferenceObject(g_RegProtectedKeyObjects[i]);
        if (g_RegProtectedKeyHandles[i]) ZwClose(g_RegProtectedKeyHandles[i]);
        g_RegProtectedKeyObjects[i] = NULL;
        g_RegProtectedKeyHandles[i] = NULL;
        g_RegProtectedKeyIDs[i] = 0;
    }
    g_RegProtectedKeyCount = 0;

    if (g_ServerPort) { FltCloseCommunicationPort(g_ServerPort); g_ServerPort = NULL; }
    if (g_ClientPort) { FltCloseClientPort(g_FilterHandle, &g_ClientPort); g_ClientPort = NULL; }
    ClearProtectedPaths();
    if (g_Registered) { FltUnregisterFilter(g_FilterHandle); g_Registered = FALSE; }
    return STATUS_SUCCESS;
}

// ===========================================================================
// Instance mgmt
// ===========================================================================

NTSTATUS MinifilterInstanceSetup(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_SETUP_FLAGS Flags,
                                  DEVICE_TYPE VolumeDeviceType, FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(Flags); UNREFERENCED_PARAMETER(VolumeDeviceType); UNREFERENCED_PARAMETER(FltObjects);
    return (VolumeFilesystemType == FLT_FSTYPE_NTFS || VolumeFilesystemType == FLT_FSTYPE_REFS)
           ? STATUS_SUCCESS : STATUS_FLT_DO_NOT_ATTACH;
}
NTSTATUS MinifilterInstanceQueryTeardown(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags)
{
    /* 自保：拒绝手动实例分离 / refuse manual instance detachment */
    UNREFERENCED_PARAMETER(FltObjects); UNREFERENCED_PARAMETER(Flags);
    return STATUS_FLT_DO_NOT_DETACH;
}
VOID MinifilterInstanceTeardownStart(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_TEARDOWN_FLAGS Flags) { UNREFERENCED_PARAMETER(FltObjects); UNREFERENCED_PARAMETER(Flags); }
VOID MinifilterInstanceTeardownComplete(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_TEARDOWN_FLAGS Flags) { UNREFERENCED_PARAMETER(FltObjects); UNREFERENCED_PARAMETER(Flags); }

// ===========================================================================
// Authorization — process name + path verification
// ===========================================================================

/*++

    判断当前调用者是否为本产品进程。
    Determines whether the calling process is ours.

    修复了两处缺陷 / Two defects fixed here:

    1. PsGetProcessImageFileName 返回 PCHAR（EPROCESS 内 15 字节 ANSI 名字数组），
       原代码把它强转成 PUNICODE_STRING 后交给 RtlCompareUnicodeString。
       结构体的 Buffer 字段实际是用进程名的 ASCII 字节拼出来的野指针，
       解引用它会造成内核越界读并 bugcheck，而且该指针由进程名控制。
       PsGetProcessImageFileName returns PCHAR (a 15-byte ANSI name array inside
       EPROCESS). The old code cast it to PUNICODE_STRING and handed it to
       RtlCompareUnicodeString, whose Buffer field was a wild pointer assembled
       from the process name's own ASCII bytes — dereferencing it is an
       out-of-bounds kernel read, with the pointer chosen by whoever names the
       process.

    2. SeLocateProcessImageName 失败时原代码 `return TRUE`（"名字对上了，路径拿不到
       就信任"）。这是授权路径上的 fail-open：任何能让该调用失败的进程都能直接拿到
       完整授权，从而修改受保护文件。现在改为 fail-closed。
       On SeLocateProcessImageName failure the old code returned TRUE ("name
       matched, path unavailable, trust it"). That is fail-open on an
       authorization path: any process that can make the call fail obtains full
       authorization and can modify protected files. It now fails closed.

    IRQL：PASSIVE_LEVEL（SeLocateProcessImageName 要求）
    IRQL: PASSIVE_LEVEL (required by SeLocateProcessImageName)

--*/
BOOLEAN IsCallerAuthorized(VOID)
{
    HANDLE          pid = PsGetCurrentProcessId();
    PEPROCESS       proc;
    PCHAR           ansiName;
    PUNICODE_STRING fullPath = NULL;
    UNICODE_STRING  target;
    UNICODE_STRING  tail;
    NTSTATUS        status;
    BOOLEAN         valid = FALSE;
    USHORT          tailChars = 0;

    if (pid == NULL) return FALSE;
    if (pid == (HANDLE)4) return TRUE;                      // SYSTEM

    proc = PsGetCurrentProcess();

    /* --- 廉价预筛：15 字节 ANSI 名 / Cheap prefilter: the 15-byte ANSI name --- */
    ansiName = PsGetProcessImageFileName(proc);
    if (ansiName == NULL) return FALSE;

    {
        BOOLEAN familyMatch = FALSE;
        for (ULONG f = 0; f < ANXIN_FAMILY_COUNT && !familyMatch; f++) {
            ULONG elen = 0;
            CHAR buf[16] = {0};
            while (ANXIN_FAMILY_WIDE[f][elen] != L'\0' && elen < 15) { buf[elen] = (CHAR)ANXIN_FAMILY_WIDE[f][elen]; elen++; }
            buf[elen] = '\0';
            if (elen > ANXIN_ANSI_COMPARE_LEN) elen = ANXIN_ANSI_COMPARE_LEN;
            BOOLEAN m = TRUE;
            for (ULONG k = 0; k < elen; k++) {
                CHAR a = ansiName[k];
                CHAR e = buf[k];
                if (a == '\0') { m = FALSE; break; }
                if (a >= 'A' && a <= 'Z') a = (CHAR)(a - 'A' + 'a');
                if (e >= 'A' && e <= 'Z') e = (CHAR)(e - 'A' + 'a');
                if (a != e) { m = FALSE; break; }
            }
            if (m) { familyMatch = TRUE; break; }
        }
        if (!familyMatch) return FALSE;
    }

    /* --- 完整路径确认 / Confirm the full path --- */
    status = SeLocateProcessImageName(proc, &fullPath);
    if (!NT_SUCCESS(status) || fullPath == NULL || fullPath->Buffer == NULL) {
        /* fail-closed：拿不到路径就不授权 / no path means no authorization */
        if (fullPath != NULL) ExFreePool(fullPath);
        return FALSE;
    }

    for (ULONG f = 0; f < ANXIN_FAMILY_COUNT && !valid; f++) {
        RtlInitUnicodeString(&target, (PWSTR)ANXIN_FAMILY_WIDE[f]);
        if (fullPath->Length > target.Length) {
            tailChars = (USHORT)((fullPath->Length - target.Length) / sizeof(WCHAR));
            WCHAR  sep = fullPath->Buffer[tailChars - 1];
            if (sep == L'\\' || sep == L'/') {
                tail.Buffer        = &fullPath->Buffer[tailChars];
                tail.Length        = target.Length;
                tail.MaximumLength = target.Length;
                valid = (BOOLEAN)(RtlCompareUnicodeString(&tail, &target, TRUE) == 0);
            }
        }
    }

    /*
     * VUL-038/VUL-046 可信目录校验（重新实现，修复 VUL-097 根因）。
     *
     * 旧实现（VUL-046 修复）在路径中搜索 "\anxinsecurity\" 组件并要求匹配位置
     * 前一字符是分隔符。但 ANXIN_TRUSTED_DIR 本身以 '\' 开头，匹配起点已经在
     * 组件边界上，检查 Buffer[pos-1] 相当于检查分隔符之前那个字符——对
     * "...\Program Files\AnXinSecurity\..." 而言它是 's'（Files 的末尾），
     * 永远不通过。因此自 VUL-046 起所有合法 anxin-security.exe（含服务进程）
     * 都被拒绝，通信端口连接全部 0x80070005，安装目录文件保护从未生效。
     *
     * 新实现改为全路径相等（仅卷前缀可变）：
     *   完整路径必须 == <卷根> + <可信安装目录> + "\anxin-security.exe"
     *   其中可信安装目录从服务 ImagePath 注册表值得出（默认
     *   "\Program Files\AnXinSecurity"），<卷根> 必须是白名单中的卷根形态
     *   （\Device\... / \??\... / \Volume{...}）。
     * 攻击者即使在任意处创建 "anxinsecurity" 子目录（VUL-046），其完整路径
     * 在 <卷根> 之后会多出额外目录组件，无法与完整结构相等，被拒绝。
     *
     * Old VUL-046 guard required the char before the matched component to be a
     * separator, but the pattern already begins with '\', so it broke every
     * legitimate path. Replaced with full-path equality (volume prefix may
     * vary), where the trusted install dir is derived from the service
     * ImagePath registry value and the volume must be a whitelisted root form.
     */
    if (valid) {
        valid = AnxinIsInTrustedInstallDir(fullPath, tailChars);
    }

    ExFreePool(fullPath);
    return valid;
}

// ---------------------------------------------------------------------------
// Trusted install directory (VUL-046 rework / VUL-097 root-cause fix)
// ---------------------------------------------------------------------------

/*
 * 可信安装目录（卷根之后的目录组件，以 '\' 开头），默认匹配 perMachine 安装：
 * C:\Program Files\AnXinSecurity。DriverEntry 时尝试从服务 ImagePath 读取覆盖，
 * 以支持自定义安装目录。ImagePath 受注册表自保（VUL-098）保护，攻击者无法改写。
 *
 * Trusted install directory (volume-relative components, leading '\'). Default
 * matches the perMachine install C:\Program Files\AnXinSecurity. Overridden at
 * DriverEntry from the service ImagePath registry value to support custom
 * install dirs. The ImagePath is registry-protected (VUL-098).
 */
static WCHAR  g_TrustedInstallDir[128] = L"\\Program Files\\AnXinSecurity";
static USHORT g_TrustedInstallDirLen   = 28; /* wcslen(L"\\Program Files\\AnXinSecurity") */

/* Count path separators in buf[0..len). */
static USHORT AnxinCountSeparators(_In_ PCWSTR buf, _In_ USHORT len)
{
    USHORT n = 0;
    for (USHORT i = 0; i < len; i++) {
        if (buf[i] == L'\\' || buf[i] == L'/') n++;
    }
    return n;
}

/*
 * 卷根白名单：\Device\<单组件卷名>（如 HarddiskVolume3 / CdRom0）、
 * \??\<盘符>:、\Volume{<GUID>}。其余形态视为无效，避免把攻击者构造的
 * 多级目录冒充卷根（VUL-046 绕过：\Device\HarddiskVolume3\<攻击者目录> 若
 * 允许内嵌分隔符，攻击者可在卷根下建目录把 "anxinsecurity" 藏进前缀）。
 * 现代 Windows 挂载卷统一是 \Device\HarddiskVolumeN（0 内嵌分隔符），
 * 0 分隔符规则即可覆盖系统卷安装。
 *
 * Whitelisted volume root forms; anything else is not a real volume root.
 * \Device\<single-component name> only (HarddiskVolumeN etc.), so an
 * attacker-created subdirectory cannot masquerade as part of the root.
 */
static BOOLEAN AnxinIsValidVolumeRoot(_In_ PCWSTR buf, _In_ USHORT len)
{
    if (len < 3 || buf[0] != L'\\') return FALSE;

    /* \Device\... */
    if (len >= 8 && RtlCompareMemory(buf, L"\\Device\\", 8 * sizeof(WCHAR)) == 8 * sizeof(WCHAR)) {
        return AnxinCountSeparators(&buf[8], (USHORT)(len - 8)) == 0;
    }
    /* \??\... */
    if (len >= 4 && RtlCompareMemory(buf, L"\\??\\", 4 * sizeof(WCHAR)) == 4 * sizeof(WCHAR)) {
        return AnxinCountSeparators(&buf[4], (USHORT)(len - 4)) == 0;
    }
    /* \Volume{...} */
    if (len >= 8 && RtlCompareMemory(buf, L"\\Volume{", 8 * sizeof(WCHAR)) == 8 * sizeof(WCHAR)) {
        return AnxinCountSeparators(&buf[8], (USHORT)(len - 8)) == 0;
    }
    return FALSE;
}

/*
 * 全路径相等校验（卷前缀可变）：
 *   fullPath[0..tailChars) == <卷根> + g_TrustedInstallDir
 * 其中 tailChars 指向 exe 文件名（"anxin-security.exe"）的起始位置，其前一个
 * 字符是路径分隔符（由调用方已验证）。
 *
 * Full-path equality (volume prefix may vary): the path before the exe name
 * must be exactly <volume root> + trusted install dir.
 */
static BOOLEAN AnxinIsInTrustedInstallDir(_In_ PUNICODE_STRING fullPath, _In_ USHORT tailChars)
{
    USHORT tdirLen = g_TrustedInstallDirLen;   /* 前导 '\' 的目录组件，不含结尾 '\' */
    if (tdirLen == 0) return FALSE;

    /*
     * fullPath[0..tailChars) = <卷根><可信目录>\（exe 名前，调用方已验证
     * fullPath[tailChars-1] == '\'）。可信目录以 '\' 开头，该字符同时也是
     * 卷根后的分隔符，因此卷根长度为 tailChars - tdirLen - 1。
     * e.g. \Device\HarddiskVolume3\Program Files\AnXinSecurity\anxin-security.exe
     *      tailChars=51 tdirLen=28 volLen=22 -> \Device\HarddiskVolume3
     *      尾比较 fullPath[22..50) == "\Program Files\AnXinSecurity"
     */
    if (tailChars < tdirLen + 3) return FALSE;   /* 卷根至少 2 字符 */
    if (fullPath->Buffer[tailChars - 1] != L'\\') return FALSE;

    USHORT volLen = (USHORT)(tailChars - tdirLen - 1);

    UNICODE_STRING tail;
    tail.Buffer        = &fullPath->Buffer[volLen];
    tail.Length        = (USHORT)(tdirLen * sizeof(WCHAR));
    tail.MaximumLength = tail.Length;

    UNICODE_STRING tdir;
    tdir.Buffer        = g_TrustedInstallDir;
    tdir.Length        = (USHORT)(tdirLen * sizeof(WCHAR));
    tdir.MaximumLength = (USHORT)sizeof(g_TrustedInstallDir);

    if (RtlCompareUnicodeString(&tail, &tdir, TRUE) != 0) return FALSE;
    return AnxinIsValidVolumeRoot(fullPath->Buffer, volLen);
}

/*
 * DriverEntry 时读取服务 ImagePath，覆盖默认可信安装目录（支持自定义安装）。
 * 解析：去掉引号（引号内空格允许）→ 取 exe 路径 token → 去掉 exe 文件名 → 去掉盘符根。
 * 失败时保持默认值（fail-closed：目录为空则不授权）。
 *
 * Reads the service ImagePath at DriverEntry to override the default trusted
 * install dir (custom install support). Keeps the default on failure.
 */
static VOID AnxinLoadTrustedInstallDir(VOID)
{
    UNICODE_STRING keyName;
    RtlInitUnicodeString(&keyName, SVC_KEY_APP_STR);
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &keyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE hKey = NULL;
    NTSTATUS status = ZwOpenKey(&hKey, KEY_QUERY_VALUE, &oa);
    if (!NT_SUCCESS(status)) return;

    UNICODE_STRING valName = RTL_CONSTANT_STRING(L"ImagePath");
    WCHAR data[512];
    ULONG retLen = 0;
    status = ZwQueryValueKey(hKey, &valName, KeyValuePartialInformation,
                             data, sizeof(data), &retLen);
    ZwClose(hKey);
    if (!NT_SUCCESS(status) || retLen <= sizeof(KEY_VALUE_PARTIAL_INFORMATION)) return;

    PKEY_VALUE_PARTIAL_INFORMATION p = (PKEY_VALUE_PARTIAL_INFORMATION)data;
    if (p->DataLength < sizeof(WCHAR) * 2) return;

    ULONG chars = p->DataLength / sizeof(WCHAR);
    if (chars >= 400) chars = 399;

    WCHAR path[400];
    RtlCopyMemory(path, p->Data, chars * sizeof(WCHAR));
    path[chars] = 0;

    /* 解析 ImagePath：允许带引号（"C:\Program Files\AnXinSecurity\anxin-security.exe"），
       引号内的空格不能作为 token 终止符。 */
    BOOLEAN quoted = (path[0] == L'"');
    PWCHAR s = path + (quoted ? 1 : 0);
    USHORT tokLen = 0;
    while (s[tokLen] != 0 && s[tokLen] != (quoted ? L'"' : L' ')) tokLen++;

    if (tokLen < 3 || !(s[0] >= L'A' && s[0] <= L'Z') || s[1] != L':') return;   /* 仅支持盘符形式 */

    /* 去掉 exe 文件名：回退到最后一个 '\' */
    USHORT dirLen = tokLen;
    while (dirLen > 0 && s[dirLen - 1] != L'\\') dirLen--;      /* dirLen 现在含结尾 '\' */
    if (dirLen < 3) return;

    /* 去掉盘符根：从 ':' 之后开始 */
    USHORT start = 2;    /* s[2] 是 ':' 之后的第一个字符（应为 '\'） */
    if (s[start] != L'\\') return;

    USHORT relLen = (USHORT)(dirLen - start);   /* 例如 "\Program Files\AnXinSecurity" 前含结尾 '\' */
    /* 存储时去掉结尾 '\'，与默认常量格式一致 */
    if (relLen >= 2 && s[start + relLen - 1] == L'\\') relLen--;

    if (relLen == 0 || relLen >= 128) return;

    RtlCopyMemory(g_TrustedInstallDir, &s[start], relLen * sizeof(WCHAR));
    g_TrustedInstallDir[relLen] = 0;
    g_TrustedInstallDirLen = relLen;

    {
        UNICODE_STRING dirUs;
        dirUs.Buffer        = g_TrustedInstallDir;
        dirUs.Length        = (USHORT)(relLen * sizeof(WCHAR));
        dirUs.MaximumLength = (USHORT)sizeof(g_TrustedInstallDir);
        DbgPrint("[AnXinFlt] Trusted install dir from ImagePath: %wZ\n", &dirUs);
    }
}

// ===========================================================================
// Registry self-protection — stable ObjectID comparison via CmCallback
// ===========================================================================

/*
 * 使用 CmCallbackGetKeyObjectIDEx 获取的稳定 ObjectID 进行比较。
 * 同一个注册表键无论通过什么 handle 打开，ObjectID 都相同，因此可以
 * 可靠地识别 SCM (services.exe) 对受保护键的操作——而对象指针比较
 * 无法做到这一点，因为 SCM 打开同一键时获得的是不同的 key object。
 *
 * 只使用 ObjectID（ULONGLONG 值），绝不使用 ObjectContext（指针）。
 * 之前在 ProcProtect 中 ObjectContext 指向已释放池内存导致 BugCheck 0x50。
 *
 * Uses the stable ObjectID from CmCallbackGetKeyObjectIDEx for comparison.
 * The same registry key has the same ObjectID regardless of which handle
 * opened it, so SCM operations on protected keys are reliably identified —
 * unlike object pointer comparison, which fails because SCM gets a different
 * key object pointer for the same key.
 *
 * Only ObjectID (a ULONGLONG value) is used; ObjectContext (a pointer) is
 * NEVER requested. ObjectContext previously pointed to freed pool memory
 * and caused BugCheck 0x50 in AnXinProcProtect.
 */
/*
 * 卸载授权窗口是否生效（窗口到期自动失效）。
 * IRQL: PASSIVE_LEVEL（CmCallback / PortMessage / 文件 PreOp 的 PASSIVE 路径保证）。
 * Whether the uninstall authorization window is still active (auto-expires).
 */
static BOOLEAN IsUninstallAuthorized(VOID)
{
    if (!g_UninstallAuthorized) return FALSE;
    if (KeQueryInterruptTime() >= g_UninstallGraceEnd) {
        g_UninstallAuthorized = FALSE;
        return FALSE;
    }
    return TRUE;
}

/*
 * VUL-098 修复：按路径名识别受保护服务键，不依赖 boot 时 ObjectID 是否缓存成功。
 * ObjectName（CmCallbackGetKeyObjectIDEx 返回）可能是完整路径
 * （\REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Services\AnXin...），也可能因
 * 键经父句柄相对打开而只是最后一段（\Anxin...）。两种都覆盖：
 *   1) 完整路径与 4 个 SVC_KEY_*_STR 不区分大小写精确匹配；
 *   2) 名称最后一段等于某个受保护键名（ANXINPROCPROTECT / ANXINFILEPROTECT /
 *      ANXINNETFILTER / ANXINSECURITYSERVICE）。
 *
 * VUL-098 fix: recognize protected service keys by path name, independent of
 * whether the boot-time ObjectID cache succeeded. ObjectName may be a full path
 * (\REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Services\Anxin...) or, for keys
 * opened relative to a parent handle, just the final component (\Anxin...). Both
 * are covered: full-path exact match against the four SVC_KEY_*_STR, or a final
 * component equal to one of the protected key names.
 */
static BOOLEAN IsRegProtectedKeyPathName(_In_ PCUNICODE_STRING KeyName)
{
    if (KeyName == NULL || KeyName->Buffer == NULL || KeyName->Length == 0)
        return FALSE;

    static const UNICODE_STRING kKeyPaths[] = {
        RTL_CONSTANT_STRING(SVC_KEY_PROCPROTECT_STR),
        RTL_CONSTANT_STRING(SVC_KEY_FILEPROTECT_STR),
        RTL_CONSTANT_STRING(SVC_KEY_NETFILTER_STR),
        RTL_CONSTANT_STRING(SVC_KEY_APP_STR),
    };
    static const UNICODE_STRING kKeyNames[] = {
        RTL_CONSTANT_STRING(L"ANXINPROCPROTECT"),
        RTL_CONSTANT_STRING(L"ANXINFILEPROTECT"),
        RTL_CONSTANT_STRING(L"ANXINNETFILTER"),
        RTL_CONSTANT_STRING(L"ANXINSECURITYSERVICE"),
    };

    /* 完整路径精确匹配（不区分大小写） */
    for (ULONG i = 0; i < RTL_NUMBER_OF(kKeyPaths); i++)
        if (RtlCompareUnicodeString(KeyName, &kKeyPaths[i], TRUE) == 0)
            return TRUE;

    /* 最后一段组件匹配（覆盖相对打开 / 带子键的 ObjectName） */
    ULONG len = KeyName->Length / sizeof(WCHAR);
    for (ULONG i = 0; i < RTL_NUMBER_OF(kKeyNames); i++) {
        ULONG nlen = kKeyNames[i].Length / sizeof(WCHAR);
        if (len < nlen) continue;
        if (len > nlen) {
            WCHAR sep = KeyName->Buffer[len - nlen - 1];
            if (sep != L'\\' && sep != L'/') continue;
        }
        UNICODE_STRING tail;
        tail.Buffer = &KeyName->Buffer[len - nlen];
        tail.Length = (USHORT)(nlen * sizeof(WCHAR));
        tail.MaximumLength = tail.Length;
        if (RtlCompareUnicodeString(&tail, &kKeyNames[i], TRUE) == 0)
            return TRUE;
    }
    return FALSE;
}

/*
 * 判断注册表键对象是否为 4 个受保护服务键之一。
 * 快路径：boot 时缓存的稳定 ObjectID 匹配（O(1) 且稳定）。
 * 慢路径（VUL-098）：CmCallbackGetKeyObjectIDEx 取对象名做路径匹配，覆盖
 * ObjectID 因键启动期状态异常而未缓存的键（实测 AnXinSecurityService 与
 * AnXinNetFilter 无保护）。ObjectName 仅在请求非空时返回，用毕须调用
 * CmCallbackReleaseKeyObjectIDEx 释放。
 */
static BOOLEAN IsRegProtectedKeyObject(PVOID Object)
{
    if (Object == NULL) return FALSE;
    if (!g_RegCmRegistered || g_RegCookie.QuadPart == 0) return FALSE;

    ULONG_PTR objID = 0;
    PUNICODE_STRING name = NULL;
    NTSTATUS status = CmCallbackGetKeyObjectIDEx(&g_RegCookie, Object, &objID, &name, 0);
    if (!NT_SUCCESS(status)) return FALSE;

    BOOLEAN hit = FALSE;
    for (ULONG i = 0; i < g_RegProtectedKeyCount; i++) {
        if (g_RegProtectedKeyIDs[i] == objID) { hit = TRUE; break; }
    }
    if (!hit && name != NULL) hit = IsRegProtectedKeyPathName(name);
    if (name != NULL) CmCallbackReleaseKeyObjectIDEx(name);
    return hit;
}

/*
 * 判断注册表操作调用者是否可信。
 * 复用文件保护的 IsCallerAuthorized（检查 PID 4 / anxin-security.exe + 可信目录）。
 * IRQL: PASSIVE_LEVEL（CmRegisterCallbackEx pre-op 回调保证）。
 */
static BOOLEAN IsRegCallerAuthorized(VOID)
{
    HANDLE pid = PsGetCurrentProcessId();
    if (pid == (HANDLE)4) return TRUE;

    /*
     * VUL-098 修复：不再无条件信任 services.exe (SCM)。
     * 旧实现把 SCM 列为授权调用方——services.exe 以 SYSTEM 运行，任何本地管理员
     * 都能借 sc delete / sc config 让 services.exe 删除或改写 4 个受保护服务键，
     * DACL 也因 SCM 是 SYSTEM 而放行，两条防线同时失效（实测 AnXinNetFilter /
     * AnxinSecurityService 键可删）。
     *
     * 现在 SCM 操作在卸载授权窗口外一律被回调拦截；合法卸载/升级由
     * anxin-security.exe 先发送 FpmAuthorizeUninstall 打开授权窗口（见
     * PortMessage 与 uninstall_drivers()）。
     *
     * VUL-098 fix: stop trusting services.exe (SCM) unconditionally. The old code
     * listed SCM as authorized — services.exe runs as SYSTEM, so any local admin
     * could use sc delete / sc config to have services.exe delete or rewrite the
     * four protected service keys, and the DACL let SYSTEM through too. Now SCM
     * operations are blocked by the callback outside the uninstall window; the
     * legitimate uninstall/upgrade flow opens that window via FpmAuthorizeUninstall.
     */

    return IsCallerAuthorized();
}

/*
 * 打开三个驱动服务注册表键 + 应用自身服务键，缓存对象指针（持有引用计数），
 * 并设置 DACL 拒绝非 SYSTEM 的 DELETE / WRITE_DAC / WRITE_OWNER。
 * 在 BootReinitCallback 中调用（PASSIVE_LEVEL，所有驱动已就绪）。
 * Opens the three driver service keys plus the app's own service key, caching object
 * pointers (with reference counts) and setting a DACL that denies DELETE / WRITE_DAC /
 * WRITE_OWNER to non-SYSTEM. Called from BootReinitCallback (PASSIVE_LEVEL, all drivers ready).
 */
static void RegProtectServiceKeysDacl(VOID)
{
    static const WCHAR* keys[MAX_PROTECTED_KEYS] = {
        SVC_KEY_PROCPROTECT_STR, SVC_KEY_FILEPROTECT_STR,
        SVC_KEY_NETFILTER_STR,   SVC_KEY_APP_STR
    };

    for (ULONG i = 0; i < MAX_PROTECTED_KEYS; i++) {
        UNICODE_STRING keyPath;
        RtlInitUnicodeString(&keyPath, keys[i]);

        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &keyPath,
                                   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

        HANDLE hKey = NULL;
        NTSTATUS status = ZwOpenKey(&hKey, READ_CONTROL | WRITE_DAC, &oa);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[AnXinFlt] RegProtect: ZwOpenKey %wZ failed: 0x%08lX\n",
                     &keyPath, status);
            continue;
        }

        /* 缓存对象指针（持有引用计数，用于 Unload 时 ObDereferenceObject） */
        PVOID keyObject = NULL;
        status = ObReferenceObjectByHandle(hKey, 0, NULL, KernelMode, &keyObject, NULL);
        if (NT_SUCCESS(status) && keyObject != NULL) {
            g_RegProtectedKeyObjects[g_RegProtectedKeyCount] = keyObject;
            g_RegProtectedKeyHandles[g_RegProtectedKeyCount] = hKey;

            /*
             * 缓存稳定 ObjectID（CmCallbackGetKeyObjectIDEx）。
             * 必须在 CmRegisterCallbackEx 之后调用，因为需要 Cookie。
             * ObjectID 是 ULONGLONG 值，不是指针，不会导致 BugCheck 0x50。
             * 同一个键无论通过什么 handle 打开，ObjectID 都相同，因此
             * 可以可靠地识别 SCM 对受保护键的操作。
             *
             * Cache the stable ObjectID via CmCallbackGetKeyObjectIDEx.
             * Must be called after CmRegisterCallbackEx (needs Cookie).
             * ObjectID is a ULONGLONG value, not a pointer — no BugCheck 0x50.
             * The same key has the same ObjectID regardless of which handle
             * opened it, so SCM operations are reliably identified.
             */
            if (g_RegCmRegistered && g_RegCookie.QuadPart != 0) {
                ULONG_PTR keyID = 0;
                NTSTATUS idStatus = CmCallbackGetKeyObjectIDEx(&g_RegCookie, keyObject,
                                                               &keyID, NULL, 0);
                if (NT_SUCCESS(idStatus)) {
                    g_RegProtectedKeyIDs[g_RegProtectedKeyCount] = keyID;
                    /* 不请求 ObjectName，无需 CmCallbackReleaseKeyObjectIDEx */
                    DbgPrint("[AnXinFlt] RegProtect: cached ObjectID 0x%Ix for %wZ\n",
                             keyID, &keyPath);
                } else {
                    DbgPrint("[AnXinFlt] RegProtect: CmCallbackGetKeyObjectIDEx %wZ failed: 0x%08lX\n",
                             &keyPath, idStatus);
                }
            }

            g_RegProtectedKeyCount++;
        } else {
            ZwClose(hKey);
            continue;
        }

        /*
         * 设置 DACL：SYSTEM 完全控制，Everyone 仅读。
         * 非 SYSTEM 用户被隐式拒绝 DELETE / WRITE_DAC / WRITE_OWNER。
         * 使用栈上 SID 结构体（RtlAllocateAndInitializeSid 不在 ntoskrnl.lib）。
         */
        {
            /* SYSTEM SID (S-1-5-18) — 栈上构造 */
            struct { SID sid; ULONG subAuth[1]; } systemSidBuf;
            static const SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
            systemSidBuf.sid.Revision = SID_REVISION;
            systemSidBuf.sid.SubAuthorityCount = 1;
            RtlCopyMemory(&systemSidBuf.sid.IdentifierAuthority, &ntAuth,
                          sizeof(SID_IDENTIFIER_AUTHORITY));
            systemSidBuf.sid.SubAuthority[0] = SECURITY_LOCAL_SYSTEM_RID;
            PSID systemSid = (PSID)&systemSidBuf;

            /* Everyone SID (S-1-1-0) — 栈上构造 */
            struct { SID sid; ULONG subAuth[1]; } everyoneSidBuf;
            static const SID_IDENTIFIER_AUTHORITY worldAuth = SECURITY_WORLD_SID_AUTHORITY;
            everyoneSidBuf.sid.Revision = SID_REVISION;
            everyoneSidBuf.sid.SubAuthorityCount = 1;
            RtlCopyMemory(&everyoneSidBuf.sid.IdentifierAuthority, &worldAuth,
                          sizeof(SID_IDENTIFIER_AUTHORITY));
            everyoneSidBuf.sid.SubAuthority[0] = SECURITY_WORLD_RID;
            PSID everyoneSid = (PSID)&everyoneSidBuf;

            /* 计算 ACL 大小 */
            ULONG aclSize = (ULONG)(sizeof(ACL)
                + RtlLengthRequiredSid(1) + sizeof(ACCESS_ALLOWED_ACE) - sizeof(ULONG)
                + RtlLengthRequiredSid(1) + sizeof(ACCESS_ALLOWED_ACE) - sizeof(ULONG));

            PACL dacl = (PACL)ExAllocatePool2(POOL_FLAG_PAGED, aclSize, POOL_TAG);
            if (dacl == NULL) continue;

            RtlCreateAcl(dacl, aclSize, ACL_REVISION);
            RtlAddAccessAllowedAceEx(dacl, ACL_REVISION, 0,
                                     KEY_ALL_ACCESS, systemSid);
            RtlAddAccessAllowedAceEx(dacl, ACL_REVISION, 0,
                                     KEY_READ, everyoneSid);

            /* 构建安全描述符并应用 */
            PSECURITY_DESCRIPTOR sd = ExAllocatePool2(POOL_FLAG_PAGED,
                                    SECURITY_DESCRIPTOR_MIN_LENGTH, POOL_TAG);
            if (sd != NULL) {
                RtlCreateSecurityDescriptor(sd, SECURITY_DESCRIPTOR_REVISION);
                RtlSetDaclSecurityDescriptor(sd, TRUE, dacl, FALSE);

                status = ZwSetSecurityObject(hKey, DACL_SECURITY_INFORMATION, sd);
                if (!NT_SUCCESS(status)) {
                    DbgPrint("[AnXinFlt] RegProtect: ZwSetSecurityObject %wZ: 0x%08lX\n",
                             &keyPath, status);
                }
                ExFreePoolWithTag(sd, POOL_TAG);
            }

            ExFreePoolWithTag(dacl, POOL_TAG);
        }
    }

    DbgPrint("[AnXinFlt] RegProtect: %lu service keys cached\n", g_RegProtectedKeyCount);
}

/*
 * CmRegisterCallbackEx 回调。
 * 使用 CmCallbackGetKeyObjectIDEx 获取的稳定 ObjectID 进行比较，而非对象指针。
 * 同一个注册表键无论通过什么 handle 打开，ObjectID 都相同，因此可以可靠地
 * 识别 SCM (services.exe) 对受保护键的删除/修改操作。
 *
 * 之前使用对象指针比较，但 SCM 打开同一键时获得不同的 key object 指针，
 * 导致 IsRegProtectedKeyObject() 返回 FALSE，sc delete 未被阻止。
 *
 * 只使用 ObjectID（ULONGLONG 值），绝不使用 ObjectContext（指针）。
 * 之前在 ProcProtect 中 ObjectContext 指向已释放池内存导致 BugCheck 0x50。
 *
 * Uses stable ObjectID from CmCallbackGetKeyObjectIDEx for comparison,
 * not object pointers. The same registry key has the same ObjectID
 * regardless of which handle opened it, so SCM operations on protected
 * keys are reliably identified.
 *
 * Previously used object-pointer comparison, but SCM gets a different
 * key object pointer for the same key, causing IsRegProtectedKeyObject()
 * to return FALSE and sc delete to be allowed through.
 *
 * Only ObjectID (a ULONGLONG value) is used; ObjectContext (a pointer)
 * is NEVER requested. ObjectContext previously pointed to freed pool
 * memory and caused BugCheck 0x50 in AnXinProcProtect.
 */
static NTSTATUS RegProtectCallback(PVOID CallbackContext, PVOID Argument1, PVOID Argument2)
{
    UNREFERENCED_PARAMETER(CallbackContext);

    if (KeGetCurrentIrql() > APC_LEVEL) return STATUS_SUCCESS;

    REG_NOTIFY_CLASS notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

    /* 宽限期内：仅拦截 Delete，放行其余（避免启动阶段服务自身写键被阻） */
    if (KeQueryInterruptTime() < g_RegGracePeriodEnd) {
        if (notifyClass != RegNtPreDeleteKey && notifyClass != RegNtPreDeleteValueKey)
            return STATUS_SUCCESS;
    }

    /*
     * VUL-098 / VUL-101：卸载授权窗口内放行全部注册表操作。
     * 合法卸载/升级由 anxin-security.exe 先发送 FpmAuthorizeUninstall；窗口外
     * SCM (services.exe) 不再被视为授权调用方（见 IsRegCallerAuthorized），
     * sc delete / sc config 借道 services.exe 删改 4 个服务键的行为被拦截。
     * Allow all registry operations during the uninstall window (granted via
     * FpmAuthorizeUninstall); outside it, SCM operations on the protected keys
     * are blocked (services.exe is no longer an authorized caller).
     */
    if (IsUninstallAuthorized()) return STATUS_SUCCESS;

    switch (notifyClass) {
    case RegNtPreDeleteKey: {
        PREG_DELETE_KEY_INFORMATION info = (PREG_DELETE_KEY_INFORMATION)Argument2;
        if (info == NULL) break;
        if (IsRegCallerAuthorized()) break;
        if (IsRegProtectedKeyObject(info->Object)) {
            DbgPrint("[AnXinFlt] DENY DeleteKey (id): 0x%p\n", info->Object);
            return STATUS_ACCESS_DENIED;
        }
        break;
    }
    case RegNtPreDeleteValueKey: {
        PREG_DELETE_VALUE_KEY_INFORMATION info = (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;
        if (info == NULL) break;
        if (IsRegCallerAuthorized()) break;
        if (IsRegProtectedKeyObject(info->Object)) {
            DbgPrint("[AnXinFlt] DENY DeleteValue (id): 0x%p\n", info->Object);
            return STATUS_ACCESS_DENIED;
        }
        break;
    }
    case RegNtPreSetValueKey: {
        PREG_SET_VALUE_KEY_INFORMATION info = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
        if (info == NULL) break;
        if (IsRegProtectedKeyObject(info->Object)) {
            if (!IsRegCallerAuthorized()) {
                DbgPrint("[AnXinFlt] DENY SetValue (id): 0x%p\n", info->Object);
                return STATUS_ACCESS_DENIED;
            }
        }
        break;
    }
    case RegNtPreRenameKey: {
        PREG_RENAME_KEY_INFORMATION info = (PREG_RENAME_KEY_INFORMATION)Argument2;
        if (info == NULL) break;
        if (IsRegCallerAuthorized()) break;
        if (IsRegProtectedKeyObject(info->Object)) {
            DbgPrint("[AnXinFlt] DENY RenameKey (id): 0x%p\n", info->Object);
            return STATUS_ACCESS_DENIED;
        }
        break;
    }
    case RegNtPreSetKeySecurity: {
        PREG_SET_KEY_SECURITY_INFORMATION info = (PREG_SET_KEY_SECURITY_INFORMATION)Argument2;
        if (info == NULL) break;
        if (IsRegCallerAuthorized()) break;
        if (IsRegProtectedKeyObject(info->Object)) {
            DbgPrint("[AnXinFlt] DENY SetSecurity (id): 0x%p\n", info->Object);
            return STATUS_ACCESS_DENIED;
        }
        break;
    }
    /*
     * VUL-048: 补齐可整体覆盖/替换服务键的注册表操作。
     * RegRestoreKey 用 hive 文件整体覆盖键内容；RegReplaceKey 替换底层 hive；
     * RegLoadKey 加载 hive 到指定路径；RegCreateKeyEx 在受保护键下创建子键。
     * 这些操作都能绕过仅拦截 SetValue/Delete 的旧保护，篡改 ImagePath/Start 等。
     *
     * VUL-048: Close gaps that could overwrite/replace service keys entirely.
     * RegRestoreKey overwrites a key from a hive file; RegReplaceKey swaps
     * the backing hive; RegLoadKey loads a hive; RegCreateKeyEx creates
     * subkeys under a protected key. The old SetValue/Delete-only checks
     * were bypassable via these operations to tamper with ImagePath/Start.
     */
    case RegNtPreRestoreKey: {
        PREG_RESTORE_KEY_INFORMATION info = (PREG_RESTORE_KEY_INFORMATION)Argument2;
        if (info == NULL) break;
        if (IsRegCallerAuthorized()) break;
        if (IsRegProtectedKeyObject(info->Object)) {
            DbgPrint("[AnXinFlt] DENY RestoreKey (id): 0x%p\n", info->Object);
            return STATUS_ACCESS_DENIED;
        }
        break;
    }
    case RegNtPreReplaceKey: {
        PREG_REPLACE_KEY_INFORMATION info = (PREG_REPLACE_KEY_INFORMATION)Argument2;
        if (info == NULL) break;
        if (IsRegCallerAuthorized()) break;
        if (IsRegProtectedKeyObject(info->Object)) {
            DbgPrint("[AnXinFlt] DENY ReplaceKey (id): 0x%p\n", info->Object);
            return STATUS_ACCESS_DENIED;
        }
        break;
    }
    case RegNtPreLoadKey: {
        PREG_LOAD_KEY_INFORMATION info = (PREG_LOAD_KEY_INFORMATION)Argument2;
        if (info == NULL) break;
        if (IsRegCallerAuthorized()) break;
        /*
         * RegLoadKey 的 Object 是被加载键的父键或根，需检查目标路径。
         * LoadKey 通常用于加载新 hive，受保护键本身不会成为 LoadKey 目标，
         * 但为防御性，检查 Object 是否为受保护键。
         */
        if (info->Object != NULL && IsRegProtectedKeyObject(info->Object)) {
            DbgPrint("[AnXinFlt] DENY LoadKey (id): 0x%p\n", info->Object);
            return STATUS_ACCESS_DENIED;
        }
        break;
    }
    case RegNtPreCreateKeyEx: {
        PREG_CREATE_KEY_INFORMATION info = (PREG_CREATE_KEY_INFORMATION)Argument2;
        if (info == NULL) break;
        if (IsRegCallerAuthorized()) break;
        if (info->RootObject != NULL && IsRegProtectedKeyObject(info->RootObject)) {
            DbgPrint("[AnXinFlt] DENY CreateKeyEx under protected key (id): 0x%p\n", info->RootObject);
            return STATUS_ACCESS_DENIED;
        }
        break;
    }
    default:
        break;
    }
    return STATUS_SUCCESS;
}

// ===========================================================================
// Shared path-check helper used by all PreOp callbacks
// ===========================================================================

/*
 * 内核驱动文件自保：检查归一化路径是否指向 System32\drivers\ 下的三个驱动文件。
 * Kernel driver file self-protection: checks if a normalized path points to
 * one of the three driver files under System32\drivers.
 *
 * 归一化路径形如 \Device\HarddiskVolume2\Windows\System32\drivers\AnXinProcProtect.sys，
 * 卷号随机器变化，因此只做后缀匹配。
 * Normalized paths look like \Device\HarddiskVolume2\Windows\System32\drivers\AnXinProcProtect.sys;
 * the volume number varies per machine, so only suffix matching is used.
 *
 * 这层保护独立于用户态下发的受保护路径列表——驱动文件从 boot 起就必须被锁定，
 * 不能等用户态服务拉起后再补，否则开机到服务启动之间存在无保护窗口。
 * This protection is independent of the user-mode protected path list: driver
 * files must be locked from boot, not after the service starts, otherwise
 * there is an unprotected window between boot and service start.
 */
BOOLEAN IsKernelDriverFile(_In_ PCUNICODE_STRING NormalizedPath)
{
    if (NormalizedPath == NULL || NormalizedPath->Buffer == NULL ||
        NormalizedPath->Length < 20 * sizeof(WCHAR))
        return FALSE;

    static const UNICODE_STRING kDriverSuffixes[] = {
        RTL_CONSTANT_STRING(L"\\SYSTEM32\\DRIVERS\\ANXINPROCPROTECT.SYS"),
        RTL_CONSTANT_STRING(L"\\SYSTEM32\\DRIVERS\\ANXINFILEPROTECT.SYS"),
        RTL_CONSTANT_STRING(L"\\SYSTEM32\\DRIVERS\\ANXINNETFILTER.SYS"),
    };

    /* 将路径拷贝到栈缓冲并转大写，便于后缀比较 */
    WCHAR buf[MAX_PATH_LENGTH];
    ULONG chars = NormalizedPath->Length / sizeof(WCHAR);
    if (chars >= MAX_PATH_LENGTH)
        chars = MAX_PATH_LENGTH - 1;
    RtlCopyMemory(buf, NormalizedPath->Buffer, chars * sizeof(WCHAR));
    buf[chars] = L'\0';
    for (ULONG i = 0; i < chars; i++)
        buf[i] = RtlUpcaseUnicodeChar(buf[i]);

    UNICODE_STRING upperPath;
    upperPath.Buffer = buf;
    upperPath.Length = (USHORT)(chars * sizeof(WCHAR));
    upperPath.MaximumLength = sizeof(buf);

    for (ULONG i = 0; i < RTL_NUMBER_OF(kDriverSuffixes); i++) {
        PCUNICODE_STRING suffix = &kDriverSuffixes[i];
        if (upperPath.Length >= suffix->Length) {
            PWCHAR cmpStart = (PWCHAR)((PUCHAR)upperPath.Buffer +
                                       upperPath.Length - suffix->Length);
            if (RtlCompareMemory(cmpStart, suffix->Buffer, suffix->Length) == suffix->Length) {
                return TRUE;
            }
        }
    }
    return FALSE;
}

BOOLEAN IsFileProtectedByPath(PFLT_CALLBACK_DATA Data)
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    /*
     * 防御性检查：Data 或其 Instance 为 NULL 时，请求来自 FLTMGR 内部操作
     * （attach/detach 期间的伪 I/O）。此时调用 FltGetFileNameInformation
     * 是未定义行为，直接返回 FALSE 放行。
     * Defensive: a NULL Data or NULL Instance means the request comes from
     * FLTMGR internals (pseudo-IO during attach/detach). Calling
     * FltGetFileNameInformation in that state is undefined; return FALSE.
     */
    if (Data == NULL || Data->Iopb == NULL || Data->Iopb->TargetInstance == NULL)
        return FALSE;
    /*
     * VUL-097 修复：必须显式请求 OPENED 格式（设备路径 \Device\HarddiskVolumeN\...），
     * 与用户态注册的路径格式一致——windows_service.rs 的 resolve_nt_path 用
     * GetFinalPathNameByHandle(VOLUME_NAME_NT) 得到的正是设备路径。
     *
     * 旧代码用 FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT：
     *   - NORMALIZED 返回 DOS 形式 \??\C:\...；
     *   - QUERY_DEFAULT 可能返回最近缓存的其他格式（含 NORMALIZED）。
     * 结果与注册的设备路径前缀永不匹配，安装目录文件保护运行期静默失效（VUL-097）。
     *
     * VUL-097 fix: explicitly request the OPENED format (device path
     * \Device\HarddiskVolumeN\...), which matches what the Rust side registers via
     * GetFinalPathNameByHandle(VOLUME_NAME_NT) in resolve_nt_path. The old
     * NORMALIZED|QUERY_DEFAULT call could return DOS-form \??\C:\... names that
     * never matched the registered device prefixes.
     */
    NTSTATUS s = FltGetFileNameInformation(Data, FLT_FILE_NAME_OPENED, &nameInfo);
    if (!NT_SUCCESS(s)) return FALSE;
    if (nameInfo->Format != FLT_FILE_NAME_OPENED) {
        /* 防御：显式请求 OPENED 时理论上必返回 OPENED，这里兜底一次 */
        FltReleaseFileNameInformation(nameInfo);
        s = FltGetFileNameInformation(Data, FLT_FILE_NAME_OPENED, &nameInfo);
        if (!NT_SUCCESS(s)) return FALSE;
    }

    BOOLEAN prot = IsPathProtected(&nameInfo->Name);
    if (!prot) {
        /* 驱动文件自保：即使用户态服务尚未下发受保护路径列表，
         * 三个驱动文件也从 boot 起被锁定。 */
        prot = IsKernelDriverFile(&nameInfo->Name);
    }
    FltReleaseFileNameInformation(nameInfo);
    return prot;
}

// ===========================================================================
// Path list management
// ===========================================================================

VOID PathToUpper(PUNICODE_STRING Path)
{
    for (ULONG i = 0; i < Path->Length / sizeof(WCHAR); i++)
        Path->Buffer[i] = RtlUpcaseUnicodeChar(Path->Buffer[i]);
}

BOOLEAN IsPathProtected(PUNICODE_STRING FilePath)
{
    if (FilePath == NULL || FilePath->Buffer == NULL || FilePath->Length < 3)
        return FALSE;

    WCHAR buf[MAX_PATH_LENGTH];
    RtlZeroMemory(buf, sizeof(buf));
    UNICODE_STRING sp;
    sp.Buffer = buf;
    sp.MaximumLength = sizeof(buf);
    sp.Length = min(FilePath->Length, sizeof(buf) - sizeof(WCHAR));
    RtlCopyMemory(buf, FilePath->Buffer, sp.Length);
    buf[sp.Length / sizeof(WCHAR)] = L'\0';
    PathToUpper(&sp);

    ExAcquireFastMutex(&g_PathListLock);
    BOOLEAN found = FALSE;
    for (ULONG i = 0; i < g_ProtectedPaths.Count; i++) {
        PUNICODE_STRING pp = &g_ProtectedPaths.Entries[i].Path;
        if (sp.Length >= pp->Length &&
            RtlCompareMemory(sp.Buffer, pp->Buffer, pp->Length) == pp->Length) {
            if (sp.Length == pp->Length) { found = TRUE; break; }
            /*
             * VUL-045 修复：pp 可能以 '\\' 结尾（FpmAddPath 强制添加尾部反斜杠
             * 用于目录前缀匹配）。此时 sp[pp.Length] 是文件名首字符，而非路径
             * 分隔符——旧代码因此把目录下所有文件都判定为"未受保护"。
             *
             * 若 pp 已以 '\\' 结尾，前缀匹配成功即视为受保护（pp 自身已包含
             * 分隔符，sp 的剩余部分就是目录下的文件/子路径）。
             * 若 pp 不以 '\\' 结尾，则要求 sp[pp.Length] 是分隔符才算受保护。
             *
             * VUL-045 fix: pp may end with '\\' (FpmAddPath appends a trailing
             * backslash for directory prefix matching). In that case
             * sp[pp.Length] is the first char of the file name, not a
             * separator — the old code therefore treated every file under a
             * protected directory as unprotected. When pp ends with '\\',
             * a successful prefix match means sp is protected (pp already
             * contains the separator). When pp does not end with '\\',
             * sp[pp.Length] must be a separator.
             */
            USHORT lastCharOff = (USHORT)(pp->Length / sizeof(WCHAR)) - 1;
            if (pp->Length >= sizeof(WCHAR) && pp->Buffer[lastCharOff] == L'\\') {
                found = TRUE; break;
            }
            WCHAR n = sp.Buffer[pp->Length / sizeof(WCHAR)];
            if (n == L'\\') { found = TRUE; break; }
        }
    }
    ExReleaseFastMutex(&g_PathListLock);
    return found;
}

NTSTATUS AddProtectedPath(PUNICODE_STRING Path)
{
    if (Path == NULL || Path->Length == 0 || Path->Length >= MAX_PATH_LENGTH * sizeof(WCHAR))
        return STATUS_INVALID_PARAMETER;

    ExAcquireFastMutex(&g_PathListLock);
    if (g_ProtectedPaths.Count >= MAX_PROTECTED_PATHS) { ExReleaseFastMutex(&g_PathListLock); return STATUS_BUFFER_TOO_SMALL; }

    for (ULONG i = 0; i < g_ProtectedPaths.Count; i++)
        if (RtlCompareUnicodeString(&g_ProtectedPaths.Entries[i].Path, Path, TRUE) == 0)
            { ExReleaseFastMutex(&g_PathListLock); return STATUS_ALREADY_REGISTERED; }

    PPROTECTED_PATH_ENTRY e = &g_ProtectedPaths.Entries[g_ProtectedPaths.Count];
    e->Path.MaximumLength = Path->Length + sizeof(WCHAR);
    e->Path.Length = Path->Length;
    e->Path.Buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, e->Path.MaximumLength, POOL_TAG);
    if (!e->Path.Buffer) { ExReleaseFastMutex(&g_PathListLock); return STATUS_INSUFFICIENT_RESOURCES; }

    RtlCopyMemory(e->Path.Buffer, Path->Buffer, Path->Length);
    e->Path.Buffer[Path->Length / sizeof(WCHAR)] = L'\0';
    PathToUpper(&e->Path);
    g_ProtectedPaths.Count++;
    ExReleaseFastMutex(&g_PathListLock);
    DbgPrint("[AnXinFlt] Add path: %wZ\n", Path);
    return STATUS_SUCCESS;
}

NTSTATUS RemoveProtectedPath(PUNICODE_STRING Path)
{
    /* VUL-047: 与 AddProtectedPath 一致的长度校验，防止栈缓冲区溢出 */
    if (Path == NULL || Path->Length == 0 || Path->Length >= MAX_PATH_LENGTH * sizeof(WCHAR))
        return STATUS_INVALID_PARAMETER;

    WCHAR buf[MAX_PATH_LENGTH]; RtlZeroMemory(buf, sizeof(buf));
    UNICODE_STRING sp; sp.Buffer = buf; sp.MaximumLength = sizeof(buf); sp.Length = Path->Length;
    RtlCopyMemory(buf, Path->Buffer, Path->Length); PathToUpper(&sp);

    ExAcquireFastMutex(&g_PathListLock);
    NTSTATUS s = STATUS_NOT_FOUND;
    for (ULONG i = 0; i < g_ProtectedPaths.Count; i++)
        if (RtlCompareUnicodeString(&g_ProtectedPaths.Entries[i].Path, &sp, FALSE) == 0) {
            ExFreePoolWithTag(g_ProtectedPaths.Entries[i].Path.Buffer, POOL_TAG);
            for (ULONG j = i; j < g_ProtectedPaths.Count - 1; j++) g_ProtectedPaths.Entries[j] = g_ProtectedPaths.Entries[j + 1];
            g_ProtectedPaths.Count--; s = STATUS_SUCCESS; break;
        }
    ExReleaseFastMutex(&g_PathListLock);
    return s;
}

VOID ClearProtectedPaths(VOID)
{
    ExAcquireFastMutex(&g_PathListLock);
    for (ULONG i = 0; i < g_ProtectedPaths.Count; i++) ExFreePoolWithTag(g_ProtectedPaths.Entries[i].Path.Buffer, POOL_TAG);
    g_ProtectedPaths.Count = 0;
    ExReleaseFastMutex(&g_PathListLock);
}

// ===========================================================================
// PreOp: IRP_MJ_CREATE — full access + disposition + options check
// ===========================================================================

FLT_PREOP_CALLBACK_STATUS MinifilterPreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects,
                                               PVOID* CompletionContext)
{
    ACCESS_MASK desired = 0;
    ULONG createParams = 0;
    ULONG disposition = 0;
    ULONG options = 0;

    UNREFERENCED_PARAMETER(FltObjects); UNREFERENCED_PARAMETER(CompletionContext);
    if (g_ShuttingDown) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    /*
     * 跳过 FLTMGR 内部操作：当 Instance 为 NULL 时，请求来自 Filter Manager
     * 自身（例如 attach/detach 期间的伪 I/O），而非真实文件系统请求。
     * 此时调用 FltGetFileNameInformation 会触发未定义行为并可能破坏堆。
     * Skip FLTMGR-internal operations: a NULL Instance means the request
     * originates from Filter Manager itself (e.g. pseudo-IO during attach/
     * detach), not a real filesystem call. Calling FltGetFileNameInformation
     * with a NULL instance is undefined and may corrupt the heap.
     */
    if (FltObjects == NULL || FltObjects->Instance == NULL)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    // Fast-path name check
    if (!IsFileProtectedByPath(Data)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    /*
     * VUL-101：卸载授权窗口内放行对受保护文件（含 3 个 .sys）的删除/改写登记，
     * 否则卸载器（NSIS Delete /REBOOTOK 与 Rust MoveFileExW）被 IsKernelDriverFile
     * 自保拦截，重启删除条目从未写入，卸载后 .sys 残留。
     */
    if (IsUninstallAuthorized())     return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (IsCallerAuthorized())        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    // 1) Check DesiredAccess for dangerous rights
    desired = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    if (desired & DANGEROUS_FILE_ACCESS_MASK)
        goto DenyCreate;

    // 2) Check disposition for overwrite/truncate
    //  WDK 10.0.28000: CreateDisposition and CreateOptions combined into Options
    //  High 8 bits = disposition; low 24 bits = options
    createParams = Data->Iopb->Parameters.Create.Options;
    disposition = (createParams >> 24) & 0xFF;
    // FILE_SUPERSEDE, FILE_OVERWRITE, FILE_OVERWRITE_IF all modify content
    if (disposition == FILE_SUPERSEDE || disposition == FILE_OVERWRITE || disposition == FILE_OVERWRITE_IF)
        goto DenyCreate;
    // CREATE_ALWAYS also truncates existing file
    if (disposition == CREATE_ALWAYS)
        goto DenyCreate;

    // 3) Check CreateOptions: FILE_DELETE_ON_CLOSE closes the FILE_DELETE_ON_CLOSE loophole
    options = createParams & 0xFFFFFF;
    if (options & FILE_DELETE_ON_CLOSE)
        goto DenyCreate;

    return FLT_PREOP_SUCCESS_NO_CALLBACK;

DenyCreate:
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    DbgPrint("[AnXinFlt] DENY CREATE caller=%lu access=%08lX disp=%lu opts=%08lX\n",
        (ULONG)(ULONG_PTR)PsGetCurrentProcessId(), (ULONG)desired, disposition, options);
    return FLT_PREOP_COMPLETE;
}

// ===========================================================================
// PreOp: IRP_MJ_WRITE — prevent write via pre-existing handles
// ===========================================================================

FLT_PREOP_CALLBACK_STATUS MinifilterPreWrite(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects,
                                              PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects); UNREFERENCED_PARAMETER(CompletionContext);
    if (g_ShuttingDown) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    /*
     * VUL-091 / VUL-092 修复：缓存管理器 write-behind 线程在 DISPATCH_LEVEL
     * 发起 IRP_MJ_WRITE。此 IRQL 下不能调用 ExAcquireFastMutex（IsPathProtected）
     * 或 SeLocateProcessImageName（IsCallerAuthorized），否则 BugCheck 0xA。
     *
     * 高 IRQL 路径：仅做无锁的驱动文件后缀匹配（IsKernelDriverFile），
     * 且仅放行 System（PID 4）——write-behind 线程始终运行在 System 上下文。
     * 非 System 进程无法获得受保护文件的可写句柄（PreCreate 在 PASSIVE_LEVEL
     * 已拦截），因此高 IRQL 下跳过路径列表检查不会削弱保护。
     *
     * Cache Manager write-behind issues IRP_MJ_WRITE at DISPATCH_LEVEL.
     * ExAcquireFastMutex and SeLocateProcessImageName both require lower IRQL.
     * At high IRQL we only do the lock-free driver-file suffix check and allow
     * only System (PID 4, the write-behind context). Non-System processes cannot
     * hold writable handles to protected files (PreCreate denies them at
     * PASSIVE_LEVEL), so skipping the path list here does not weaken protection.
     */
    if (KeGetCurrentIrql() > APC_LEVEL) {
        PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
        /*
         * VUL-091/092 + BSOD 0x13A 修复：DISPATCH_LEVEL 下禁止使用
         * FLT_FILE_NAME_QUERY_DEFAULT，否则 FLTMGR 会触碰可分页的名称缓存元数据，
         * 触发 kernel-mode heap corruption (LFH metadata)。
         * 必须改用 FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP，它只查
         * 非分页的 name cache，找不到就直接返回失败，不触发分页 I/O。
         * Microsoft 文档明确要求 IRQL > APC_LEVEL 时只能用此 flag。
         *
         * FLT_FILE_NAME_QUERY_DEFAULT is forbidden at IRQL > APC_LEVEL; using it
         * here corrupted LFH heap metadata in FLTMGR's paged name cache, causing
         * KERNEL_MODE_HEAP_CORRUPTION (0x13A). ALWAYS_ALLOW_CACHE_LOOKUP queries
         * only the non-paged cache and returns failure on miss — no paging I/O.
         */
        NTSTATUS ns = FltGetFileNameInformation(Data,
                            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
                            &nameInfo);
        if (NT_SUCCESS(ns)) {
            BOOLEAN isDriver = IsKernelDriverFile(&nameInfo->Name);
            FltReleaseFileNameInformation(nameInfo);
            if (isDriver && PsGetCurrentProcessId() != (HANDLE)4) {
                /* 非 System 写驱动文件 —— fail-closed */
                Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                Data->IoStatus.Information = 0;
                return FLT_PREOP_COMPLETE;
            }
        }
        /* 高 IRQL：System 写驱动文件放行；非驱动文件无保护需求（句柄已被 Create 拦截） */
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!IsFileProtectedByPath(Data)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    /* VUL-101：卸载授权窗口内放行对受保护文件的改写/删除（卸载器清理所需） */
    if (IsUninstallAuthorized())     return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (IsCallerAuthorized())        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    DbgPrint("[AnXinFlt] DENY WRITE caller=%lu\n", (ULONG)(ULONG_PTR)PsGetCurrentProcessId());
    return FLT_PREOP_COMPLETE;
}

// ===========================================================================
// PreOp: IRP_MJ_SET_INFORMATION — extended to cover truncation + security
// ===========================================================================

FLT_PREOP_CALLBACK_STATUS MinifilterPreSetInformation(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects,
                                                       PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects); UNREFERENCED_PARAMETER(CompletionContext);
    if (g_ShuttingDown) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    FILE_INFORMATION_CLASS cls = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

    // Intercept: delete, rename, truncation, security, basic attributes (anti-forensic)
    BOOLEAN intercept = FALSE;
    switch (cls) {
    case FileDispositionInformation:
    case FileDispositionInformationEx:
    case FileRenameInformation:
    case FileRenameInformationEx:
    case FileLinkInformation:
    case FileLinkInformationEx:
    case FileEndOfFileInformation:        // SetEOF(0) truncates
    case FileAllocationInformation:       // SetAllocationSize(0) releases data
    case FileValidDataLengthInformation:  // Change valid data length
    case FileBasicInformation:            // Change timestamps (anti-forensic)
        intercept = TRUE;
        break;
    default:
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!IsFileProtectedByPath(Data)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    /* VUL-101：卸载授权窗口内放行对受保护文件的改写/删除（卸载器清理所需） */
    if (IsUninstallAuthorized())     return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (IsCallerAuthorized())        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    DbgPrint("[AnXinFlt] DENY SetInfo class=%d caller=%lu\n", cls,
        (ULONG)(ULONG_PTR)PsGetCurrentProcessId());
    return FLT_PREOP_COMPLETE;
}

// ===========================================================================
// PreOp: IRP_MJ_FILE_SYSTEM_CONTROL — block FSCTL zero/offload/sparse
// ===========================================================================

FLT_PREOP_CALLBACK_STATUS MinifilterPreFileSystemControl(PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects); UNREFERENCED_PARAMETER(CompletionContext);
    if (g_ShuttingDown) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    ULONG fsctl = Data->Iopb->Parameters.FileSystemControl.Common.FsControlCode;

    // Only intercept destructive FSCTLs
    if (fsctl != FSCTL_SET_ZERO_DATA &&
        fsctl != FSCTL_SET_SPARSE &&
        fsctl != FSCTL_SET_COMPRESSION &&
        fsctl != FSCTL_OFFLOAD_WRITE &&
        fsctl != FSCTL_SET_ENCRYPTION &&
        fsctl != FSCTL_WRITE_USN_CLOSE_RECORD)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (!IsFileProtectedByPath(Data)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    /* VUL-101：卸载授权窗口内放行对受保护文件的改写/删除（卸载器清理所需） */
    if (IsUninstallAuthorized())     return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (IsCallerAuthorized())        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    DbgPrint("[AnXinFlt] DENY FSCTL 0x%08lX caller=%lu\n", fsctl,
        (ULONG)(ULONG_PTR)PsGetCurrentProcessId());
    return FLT_PREOP_COMPLETE;
}

// ===========================================================================
// PreOp: IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION — memory-mapped writes
// ===========================================================================

FLT_PREOP_CALLBACK_STATUS MinifilterPreAcquireForSectionSync(PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects); UNREFERENCED_PARAMETER(CompletionContext);
    if (g_ShuttingDown) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    // Only intercept section creates (not page faults)
    if (Data->Iopb->Parameters.AcquireForSectionSynchronization.SyncType != SyncTypeCreateSection)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    // Check if a writable section is being created (PAGE_READWRITE, PAGE_WRITECOPY, etc.)
    ULONG prot = Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection;
    if (!(prot & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (!IsFileProtectedByPath(Data)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    /* VUL-101：卸载授权窗口内放行对受保护文件的改写/删除（卸载器清理所需） */
    if (IsUninstallAuthorized())     return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (IsCallerAuthorized())        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    DbgPrint("[AnXinFlt] DENY SECTION caller=%lu prot=%08lX\n",
        (ULONG)(ULONG_PTR)PsGetCurrentProcessId(), prot);
    return FLT_PREOP_COMPLETE;
}

// ===========================================================================
// Communication port — caller verified
// ===========================================================================

NTSTATUS PortConnect(PFLT_PORT ClientPort, PVOID ServerPortCookie,
                     PVOID Context, ULONG SizeOfContext, PVOID* ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ServerPortCookie); UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(SizeOfContext); UNREFERENCED_PARAMETER(ConnectionCookie);

    /*
     * BSOD 0x13A 修复：此处绝对不能调用 FltCloseClientPort。
     *
     * MSDN 明确规定：ConnectNotifyCallback 返回失败状态时，Filter Manager
     * 会自动关闭 client port 并释放 FMcp 池块。如果 minifilter 在返回失败前
     * 调用 FltCloseClientPort，FLTMGR 会在回调返回后再次释放同一池块，
     * 造成 double-free → LFH subsegment 元数据损坏 → KERNEL_MODE_HEAP_CORRUPTION。
     *
     * 转储文件确认：崩溃发生在 FltpOpenClientPort 释放 FMcp 块时，
     * 损坏类型 0x11（LFH subsegment free block corruption）。
     *
     * MSDN: "If this callback routine returns an error NTSTATUS value, the
     * Filter Manager cleans up any resources that it allocated for the client
     * port. The minifilter driver should not call FltCloseClientPort in this
     * case."
     */
    if (!IsCallerAuthorized()) {
        DbgPrint("[AnXinFlt] PortConnect rejected: caller is not authorized\n");
        return STATUS_ACCESS_DENIED;
    }

    if (g_ClientPort != NULL) {
        DbgPrint("[AnXinFlt] PortConnect: rejecting second client\n");
        return STATUS_ACCESS_DENIED;
    }

    g_ClientPort = ClientPort;
    DbgPrint("[AnXinFlt] PortConnect: client authorized\n");
    return STATUS_SUCCESS;
}

VOID PortDisconnect(PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);
    if (g_ClientPort) { FltCloseClientPort(g_FilterHandle, &g_ClientPort); g_ClientPort = NULL; }
    DbgPrint("[AnXinFlt] PortDisconnect\n");
}

NTSTATUS PortMessage(PVOID PortCookie, PVOID InputBuffer, ULONG InputBufferLength,
                     PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnOutputBufferLength)
{
    UNREFERENCED_PARAMETER(PortCookie); UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
    if (InputBuffer == NULL || InputBufferLength < sizeof(FPM_MESSAGE))
        return STATUS_INVALID_PARAMETER;

    PFPM_MESSAGE msg = (PFPM_MESSAGE)InputBuffer;
    switch (msg->MessageType) {
    case FpmAddPath: {
        WCHAR pathBuffer[MAX_PATH_LENGTH];
        ULONG pathChars = 0;
        UNICODE_STRING path;

        while (pathChars < MAX_PATH_LENGTH && msg->Path[pathChars] != L'\0') {
            pathChars++;
        }
        if (pathChars == 0 || pathChars == MAX_PATH_LENGTH)
            return STATUS_INVALID_PARAMETER;

        RtlCopyMemory(pathBuffer, msg->Path, (pathChars + 1) * sizeof(WCHAR));
        // Ensure trailing backslash for dir prefix matching
        if (pathBuffer[pathChars - 1] != L'\\') {
            if (pathChars + 1 >= MAX_PATH_LENGTH)
                return STATUS_BUFFER_TOO_SMALL;
            pathBuffer[pathChars++] = L'\\';
            pathBuffer[pathChars] = L'\0';
        }

        path.Buffer = pathBuffer;
        path.Length = (USHORT)(pathChars * sizeof(WCHAR));
        path.MaximumLength = (USHORT)((pathChars + 1) * sizeof(WCHAR));
        return AddProtectedPath(&path);
    }
    case FpmRemovePath: {
        WCHAR pathBuffer[MAX_PATH_LENGTH];
        ULONG pathChars = 0;
        UNICODE_STRING path;

        while (pathChars < MAX_PATH_LENGTH && msg->Path[pathChars] != L'\0') {
            pathChars++;
        }
        if (pathChars == 0 || pathChars == MAX_PATH_LENGTH)
            return STATUS_INVALID_PARAMETER;

        RtlCopyMemory(pathBuffer, msg->Path, (pathChars + 1) * sizeof(WCHAR));
        path.Buffer = pathBuffer;
        path.Length = (USHORT)(pathChars * sizeof(WCHAR));
        path.MaximumLength = (USHORT)((pathChars + 1) * sizeof(WCHAR));
        return RemoveProtectedPath(&path);
    }
    case FpmClearAll:
        ClearProtectedPaths();
        return STATUS_SUCCESS;
    case FpmQueryPaths: {
        /*
         * 返回当前受保护路径列表，用于诊断。
         *
         * VUL-102 修复：改用紧凑回复（ULONG PathCount + 每路径一个 NUL 结尾的
         * WCHAR 串，长度可变），并先算所需字节数再协商缓冲。旧实现按
         * ULONG + 128*520 WCHAR 的定长槽位回复，Rust 侧申请 ~130KB 输出缓冲，
         * 超出过滤通信端口回复上限，FilterSendMessage 一直不返回（挂起）。
         * 现在：OutputBuffer 不足时置 ReturnOutputBufferLength 为所需值并返回
         * STATUS_BUFFER_TOO_SMALL，绝不越界写；回复体积远小于定长版本。
         *
         * VUL-102 fix: compact reply (ULONG PathCount + variable-length NUL-
         * terminated WCHAR strings), with required-size negotiation up front. The
         * old fixed-slot reply needed a ~130KB output buffer, exceeding the filter
         * port reply limit and hanging FilterSendMessage. If the buffer is too
         * small, ReturnOutputBufferLength is set to the required size and
         * STATUS_BUFFER_TOO_SMALL is returned without writing out of bounds.
         */
        if (OutputBuffer == NULL || ReturnOutputBufferLength == NULL)
            return STATUS_INVALID_PARAMETER;

        ExAcquireFastMutex(&g_PathListLock);

        ULONG count = g_ProtectedPaths.Count;
        if (count > MAX_PROTECTED_PATHS) count = MAX_PROTECTED_PATHS;

        /* 先在锁内计算所需字节数，再做长度协商 */
        ULONG required = sizeof(ULONG);
        for (ULONG i = 0; i < count; i++) {
            ULONG chars = g_ProtectedPaths.Entries[i].Path.Length / sizeof(WCHAR);
            if (chars >= MAX_PATH_LENGTH) chars = MAX_PATH_LENGTH - 1;
            required += (chars + 1) * (ULONG)sizeof(WCHAR);
        }

        if (OutputBufferLength < required) {
            *ReturnOutputBufferLength = required;
            ExReleaseFastMutex(&g_PathListLock);
            return STATUS_BUFFER_TOO_SMALL;
        }

        *((PULONG)OutputBuffer) = count;
        ULONG offset = sizeof(ULONG);

        for (ULONG i = 0; i < count; i++) {
            PUNICODE_STRING pp = &g_ProtectedPaths.Entries[i].Path;
            ULONG chars = pp->Length / sizeof(WCHAR);
            if (chars >= MAX_PATH_LENGTH) chars = MAX_PATH_LENGTH - 1;
            PWCHAR dst = (PWCHAR)((PUCHAR)OutputBuffer + offset);
            RtlCopyMemory(dst, pp->Buffer, chars * sizeof(WCHAR));
            dst[chars] = L'\0';
            offset += (chars + 1) * (ULONG)sizeof(WCHAR);
            DbgPrint("[AnXinFlt] Query path %lu: %wZ\n", i, pp);
        }

        ExReleaseFastMutex(&g_PathListLock);

        *ReturnOutputBufferLength = offset;
        return STATUS_SUCCESS;
    }
    case FpmAuthorizeUninstall: {
        /*
         * VUL-098 / VUL-101：授权卸载/升级窗口。
         * 只接受完整路径验证的 anxin-security.exe（或 SYSTEM，见 IsCallerAuthorized）
         * 发起；窗口内注册表回调与文件自保放行 SCM 对 4 个服务键的删改、卸载器对
         * 3 个 .sys 的重启删除登记。窗口到期自动失效（IsUninstallAuthorized）。
         */
        if (!IsCallerAuthorized()) {
            DbgPrint("[AnXinFlt] DENY FpmAuthorizeUninstall from PID %lu\n",
                     (ULONG)(ULONG_PTR)PsGetCurrentProcessId());
            return STATUS_ACCESS_DENIED;
        }
        g_UninstallAuthorized = TRUE;
        g_UninstallGraceEnd = KeQueryInterruptTime() + UNINSTALL_GRACE_100NS;
        DbgPrint("[AnXinFlt] Uninstall authorization granted (grace end=%llu)\n",
                 g_UninstallGraceEnd);
        return STATUS_SUCCESS;
    }
    default:
        return STATUS_INVALID_PARAMETER;
    }
}
