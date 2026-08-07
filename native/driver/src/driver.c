/*++
Copyright (c) AnXin Security. All rights reserved.

Module Name:
    driver.c

Abstract:
    AnXin Security process, thread & window protection driver.
    - Process callback: PsSetCreateProcessNotifyRoutineEx auto-protects anxin-security.exe
    - Process handle protection: ObRegisterCallbacks strips dangerous rights on OpenProcess
    - Thread handle protection: ObRegisterCallbacks on PsThreadType strips dangerous rights
      on OpenThread (prevents TerminateThread/SuspendThread/SetThreadContext)
    - Window handle protection: ObRegisterCallbacks on WindowStation object type
      prevents other processes from enumerating/interacting with our windows
    - Thread callback: PsSetCreateThreadNotifyRoutine tracks threads of protected processes
    - Image load callback: PsSetLoadImageNotifyRoutine detects untrusted DLL loads (VUL-019)
    - IOCTL interface: PID management + window station registration + image event query

Environment:
    Kernel mode only.

--*/

/*
 * 用 ntifs.h 而不是 ntddk.h：SeLocateProcessImageName 只在 ntifs.h 里声明。
 * 两者不能反过来包含（先 ntddk.h 再 ntifs.h 会撞重定义），ntifs.h 是超集，
 * ntddk.h 提供的内容它全都有。
 * ntifs.h rather than ntddk.h: SeLocateProcessImageName is only declared there.
 * The two cannot be included the other way round (ntddk.h before ntifs.h collides
 * on redefinitions); ntifs.h is a superset and covers everything ntddk.h offers.
 */
#include <ntifs.h>
#include <ntstrsafe.h>
/* IoCreateDeviceSecure 与 SDDL_* 常量 / IoCreateDeviceSecure and the SDDL_* constants */
#include <wdmsec.h>

/*
 * 较新的 WDK（10.0.28000 起）不再在公开头文件里声明 PsGetProcessImageFileName，
 * 但 ntoskrnl.exe 仍然导出它。注意返回类型是 PCHAR —— 指向 EPROCESS 内一个
 * 15 字节的 ANSI 名字数组，绝不是 UNICODE_STRING，详见 IsAnxinProcess 的注释。
 * Newer WDKs (10.0.28000 onwards) no longer declare PsGetProcessImageFileName in
 * the public headers, but ntoskrnl.exe still exports it. Note the return type is
 * PCHAR — a pointer to a 15-byte ANSI name array inside EPROCESS, never a
 * UNICODE_STRING. See the comment on IsAnxinProcess.
 */
extern PCHAR PsGetProcessImageFileName(PEPROCESS Process);

// ---------------------------------------------------------------------------
// Win32 access mask constants (not available in kernel-mode WDK headers)
// ---------------------------------------------------------------------------

// Process access rights
#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE                  (0x0001)
#define PROCESS_CREATE_THREAD              (0x0002)
#define PROCESS_VM_OPERATION               (0x0008)
#define PROCESS_VM_READ                    (0x0010)
#define PROCESS_VM_WRITE                   (0x0020)
#define PROCESS_DUP_HANDLE                 (0x0040)
#define PROCESS_CREATE_PROCESS             (0x0080)
#define PROCESS_SET_QUOTA                  (0x0100)
#define PROCESS_SET_INFORMATION            (0x0200)
#define PROCESS_SUSPEND_RESUME             (0x0800)
#define PROCESS_QUERY_LIMITED_INFORMATION  (0x1000)
#endif

// Thread access rights
#ifndef THREAD_TERMINATE
#define THREAD_TERMINATE                   (0x0001)
#endif
#ifndef THREAD_SUSPEND_RESUME
#define THREAD_SUSPEND_RESUME              (0x0002)
#endif
#ifndef THREAD_GET_CONTEXT
#define THREAD_GET_CONTEXT                 (0x0008)
#endif
#ifndef THREAD_SET_CONTEXT
#define THREAD_SET_CONTEXT                 (0x0010)
#endif
#ifndef THREAD_SET_INFORMATION
#define THREAD_SET_INFORMATION             (0x0020)
#endif
#ifndef THREAD_SET_THREAD_TOKEN
#define THREAD_SET_THREAD_TOKEN            (0x0040)
#endif
#ifndef THREAD_IMPERSONATE
#define THREAD_IMPERSONATE                 (0x0100)
#endif
#ifndef THREAD_DIRECT_IMPERSONATION
#define THREAD_DIRECT_IMPERSONATION        (0x0200)
#endif

// Window station access rights
#ifndef WINSTA_ENUMDESKTOPS
#define WINSTA_ENUMDESKTOPS                (0x0001)
#define WINSTA_READSCREEN                  (0x0002)
#define WINSTA_ACCESSCLIPBOARD             (0x0004)
#define WINSTA_CREATEDESKTOP               (0x0008)
#define WINSTA_EXITWINDOWS                 (0x0040)
#define WINSTA_READATTRIBUTES              (0x0200)
#endif

// Desktop access rights
#ifndef DESKTOP_READOBJECTS
#define DESKTOP_READOBJECTS                (0x0001)
#define DESKTOP_CREATEWINDOW               (0x0002)
#define DESKTOP_CREATEMENU                 (0x0004)
#define DESKTOP_HOOKCONTROL                (0x0008)
#define DESKTOP_JOURNALRECORD              (0x0010)
#define DESKTOP_JOURNALPLAYBACK            (0x0020)
#define DESKTOP_ENUMERATE                  (0x0040)
#define DESKTOP_WRITEOBJECTS               (0x0080)
#endif

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#define DRIVER_NAME             L"AnXinProcProtect"
#define DEVICE_NAME             L"\\Device\\AnXinProcProtect"
#define SYMBOLIC_LINK_NAME      L"\\DosDevices\\AnXinProcProtect"
/*
 * 设备 DACL：只有 SYSTEM 与 Administrators 能打开。
 * 服务进程以 LocalSystem 运行，因此这条限制不影响正常使用。
 * Device DACL: only SYSTEM and Administrators may open it. The service process
 * runs as LocalSystem, so this restriction does not affect normal operation.
 */
#define DEVICE_SDDL             L"D:P(A;;GA;;;SY)(A;;GA;;;BA)"
#define PROCESS_NAME            L"anxin-security.exe"
/*
 * VUL-038 修复：可信安装目录。进程完整路径必须包含此目录名，
 * 防止任意目录下的同名 anxin-security.exe 获取驱动信任。
 * Trusted installation directory. The full process path must contain this
 * directory component to prevent a same-named executable in an arbitrary
 * directory from gaining driver trust.
 */
#define TRUSTED_INSTALL_DIR     L"\\anxinsecurity\\"
/*
 * EPROCESS.ImageFileName 是 15 字节 ANSI 且会截断，因此预筛用的 ANSI 常量与
 * 比较长度单独定义。14 个字符（"anxin-security"）落在截断长度内，足够做快速排除。
 * EPROCESS.ImageFileName is a truncated 15-byte ANSI field, so the prefilter's
 * ANSI constant and compare length are defined separately. 14 characters
 * ("anxin-security") fit inside the truncation limit and suffice as a fast reject.
 */
#define PROCESS_NAME_ANSI       "anxin-security.exe"
#define ANSI_NAME_COMPARE_LEN   14
#define MAX_PROTECTED_PIDS      64
#define MAX_PROTECTED_WINSTA    8

// ---------------------------------------------------------------------------
// IOCTL definitions
// ---------------------------------------------------------------------------

#define IOCTL_ANXIN_ADD_PID        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_ANXIN_REMOVE_PID     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_ANXIN_CLEAR_PIDS     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_NEITHER, FILE_WRITE_DATA)
#define IOCTL_ANXIN_QUERY_PIDS     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_ANXIN_ADD_WINSTA     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_ANXIN_REMOVE_WINSTA  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_NEITHER, FILE_WRITE_DATA)
#define IOCTL_ANXIN_QUERY_IMAGE_EVENTS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_READ_DATA)

// ---------------------------------------------------------------------------
// Dangerous access masks
// ---------------------------------------------------------------------------

// Process-level dangerous rights
#define PROTECTED_PROCESS_ACCESS_MASK  (PROCESS_TERMINATE         | \
                                        PROCESS_VM_READ           | \
                                        PROCESS_VM_WRITE          | \
                                        PROCESS_VM_OPERATION      | \
                                        PROCESS_CREATE_THREAD     | \
                                        PROCESS_SET_INFORMATION   | \
                                        PROCESS_SUSPEND_RESUME    | \
                                        PROCESS_DUP_HANDLE        | \
                                        PROCESS_SET_QUOTA         | \
                                        PROCESS_CREATE_PROCESS    | \
                                        DELETE                    | \
                                        WRITE_DAC                 | \
                                        WRITE_OWNER)

// Window station dangerous rights (prevent enumeration and interference)
// WINSTA_ENUMDESKTOPS - enumerate desktops to find our windows
// WINSTA_ACCESSCLIPBOARD / WINSTA_READSCREEN - screen capture
// WINSTA_CREATEDESKTOP - create overlapping desktop
#define PROTECTED_WINSTA_ACCESS_MASK  (WINSTA_ENUMDESKTOPS       | \
                                       WINSTA_ACCESSCLIPBOARD    | \
                                       WINSTA_READSCREEN         | \
                                       WINSTA_CREATEDESKTOP      | \
                                       WINSTA_EXITWINDOWS        | \
                                       DELETE                    | \
                                       WRITE_DAC                 | \
                                       WRITE_OWNER)

// Thread-level dangerous rights (prevent termination, suspension, context hijacking,
// impersonation, and security descriptor manipulation)
// THREAD_TERMINATE            - TerminateThread
// THREAD_SUSPEND_RESUME       - SuspendThread / ResumeThread
// THREAD_SET_CONTEXT          - SetThreadContext (hijack execution)
// THREAD_SET_INFORMATION      - NtSetInformationThread
// THREAD_GET_CONTEXT          - GetThreadContext (read register state)
// THREAD_SET_THREAD_TOKEN     - replace thread token (privilege escalation)
// THREAD_IMPERSONATE          - impersonate
// THREAD_DIRECT_IMPERSONATION - direct impersonation
#define PROTECTED_THREAD_ACCESS_MASK  (THREAD_TERMINATE           | \
                                       THREAD_SUSPEND_RESUME      | \
                                       THREAD_SET_CONTEXT         | \
                                       THREAD_SET_INFORMATION     | \
                                       THREAD_GET_CONTEXT         | \
                                       THREAD_SET_THREAD_TOKEN    | \
                                       THREAD_IMPERSONATE         | \
                                       THREAD_DIRECT_IMPERSONATION | \
                                       DELETE                     | \
                                       WRITE_DAC                  | \
                                       WRITE_OWNER)

// Desktop dangerous rights (prevent window enumeration and message interception)
// DESKTOP_ENUMERATE - enumerate windows on desktop
// DESKTOP_READOBJECTS - read window objects (messages, properties)
// DESKTOP_WRITEOBJECTS - write to window objects
// DESKTOP_HOOKCONTROL - install hooks 
// DESKTOP_JOURNALRECORD / DESKTOP_JOURNALPLAYBACK - journal hooks
#define PROTECTED_DESKTOP_ACCESS_MASK (DESKTOP_ENUMERATE        | \
                                       DESKTOP_READOBJECTS      | \
                                       DESKTOP_WRITEOBJECTS     | \
                                       DESKTOP_HOOKCONTROL      | \
                                       DESKTOP_JOURNALRECORD    | \
                                       DESKTOP_JOURNALPLAYBACK  | \
                                       DESKTOP_CREATEWINDOW     | \
                                       DESKTOP_CREATEMENU       | \
                                       DELETE                   | \
                                       WRITE_DAC                | \
                                       WRITE_OWNER)

// ---------------------------------------------------------------------------
// Object type pointers (exported by ntoskrnl.exe)
// ---------------------------------------------------------------------------
/*
 * ！警告 / WARNING ！
 * ExWindowStationObjectType 不是 WDK 公开声明的标准导出。它在部分 Windows 版本
 * 的 ntoskrnl.exe 中存在，但在另一些版本中不存在或类型不匹配。
 * 如果符号不存在，驱动加载直接失败 (error 127)；如果符号存在但类型布局与
 * POBJECT_TYPE* 不一致，ObRegisterCallbacks 会在 DISPATCH_LEVEL 下解引用
 * 无效指针，触发 BSOD 0x0A (IRQL_NOT_LESS_OR_EQUAL)。
 * 2026-07-28 在 Win10 IoT LTSC 19044 上实测确认：驱动加载后 BSOD，
 * 故障点位于 ObRegisterCallbacks 内部。
 *
 * 当前策略：默认不注册 WinSta ObCallback（ANXIN_ENABLE_WINSTA_OBCALLBACK 未定义）。
 * 如果未来需要 WindowStation 保护，应改用 ObGetObjectType 或按名称查找类型，
 * 而不是依赖这个未文档化的导出符号。
 *
 * ExWindowStationObjectType is NOT a standard WDK-declared export. It exists in
 * some ntoskrnl.exe builds but not others, and its type layout may not match
 * POBJECT_TYPE*. If the symbol is missing the driver fails to load (error 127);
 * if present but mismatched, ObRegisterCallbacks dereferences an invalid pointer
 * at DISPATCH_LEVEL, causing BSOD 0x0A. Confirmed on Win10 IoT LTSC 19044.
 *
 * Current policy: WinSta ObCallback registration is disabled by default.
 * To re-enable, define ANXIN_ENABLE_WINSTA_OBCALLBACK and verify the target
 * kernel exports the symbol with the correct type.
 */
#ifdef ANXIN_ENABLE_WINSTA_OBCALLBACK
extern POBJECT_TYPE* ExWindowStationObjectType;
#endif

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

typedef struct _PROTECTED_PID_LIST {
    ULONG  Count;
    HANDLE Pids[MAX_PROTECTED_PIDS];
} PROTECTED_PID_LIST;

typedef struct _PROTECTED_WINSTA_LIST {
    ULONG   Count;
    PVOID   Objects[MAX_PROTECTED_WINSTA];  // Stored object pointers via ObReferenceObjectByHandle
} PROTECTED_WINSTA_LIST;

static PDEVICE_OBJECT          g_DeviceObject          = NULL;
static UNICODE_STRING          g_DeviceName            = {0};
static UNICODE_STRING          g_SymLinkName           = {0};

static PROTECTED_PID_LIST      g_ProtectedPids         = {0};
static KSPIN_LOCK              g_PidListLock           = {0};

static PROTECTED_WINSTA_LIST   g_ProtectedWinsta       = {0};
static KSPIN_LOCK              g_WinstaListLock         = {0};

static PVOID                   g_ProcessNotifyReg      = NULL;
static PVOID                   g_ThreadNotifyReg        = NULL;
static PVOID                   g_ObProcessRegistration = NULL;
static PVOID                   g_ObThreadRegistration   = NULL;
static PVOID                   g_ObWinstaRegistration   = NULL;
/*
 * 缓存的 WindowStation 对象类型指针。仅在 ANXIN_ENABLE_WINSTA_OBCALLBACK
 * 启用且注册成功时被赋值；否则保持 NULL，使 AddProtectedWinsta 优雅失败。
 * Cached WindowStation object type pointer. Only assigned when
 * ANXIN_ENABLE_WINSTA_OBCALLBACK is enabled and registration succeeds;
 * otherwise stays NULL, making AddProtectedWinsta fail gracefully.
 */
static POBJECT_TYPE            g_WinstaObjType            = NULL;

/*
 * VUL-019 修复：DLL 加载事件环形缓冲区。
 * PsSetLoadImageNotifyRoutine 回调在映像映射时（代码执行前）触发，
 * 将不受信任的 DLL 加载记录到环形缓冲区，用户态服务通过
 * IOCTL_ANXIN_QUERY_IMAGE_EVENTS 查询并排空。
 * Ring buffer for untrusted image load events (VUL-019 fix).
 * The LoadImageNotifyRoutine callback fires at image-map time (before
 * execution), recording untrusted DLL loads for user-mode consumption.
 */
#define IMAGE_EVENT_RING_SIZE   32
#define IMAGE_EVENT_PATH_CHARS  260

typedef struct _IMAGE_LOAD_EVENT {
    LARGE_INTEGER Timestamp;
    HANDLE        ProcessId;
    PVOID         ImageBase;
    SIZE_T        ImageSize;
    BOOLEAN       IsDriverImage;
    WCHAR         ImagePath[IMAGE_EVENT_PATH_CHARS];
} IMAGE_LOAD_EVENT, *PIMAGE_LOAD_EVENT;

static IMAGE_LOAD_EVENT        g_ImageEventRing[IMAGE_EVENT_RING_SIZE] = {0};
static ULONG                   g_ImageEventHead  = 0;   /* next write slot */
static ULONG                   g_ImageEventCount = 0;   /* total events (may exceed ring size) */
static KSPIN_LOCK              g_ImageEventLock  = {0};
static PVOID                   g_LoadImageNotifyReg = NULL;

#ifdef DBG
#define DbgPrintf(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, __VA_ARGS__)
#else
#define DbgPrintf(...)
#endif

// ---------------------------------------------------------------------------
// Forward declarations
// ---------------------------------------------------------------------------

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD     DriverUnload;
DRIVER_DISPATCH   DriverCreateClose;
DRIVER_DISPATCH   DriverDeviceControl;

// Process
void       ProcessNotifyCallback(_Inout_ PEPROCESS Process, _In_ HANDLE ProcessId, _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);
void       ThreadNotifyCallback(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId, _In_ BOOLEAN Create);
void       LoadImageNotifyCallback(_In_opt_ PUNICODE_STRING FullImageName, _In_ HANDLE ProcessId, _In_ PIMAGE_INFO ImageInfo);
OB_PREOP_CALLBACK_STATUS ObPreProcessHandleCreate(_In_ PVOID RegistrationContext, _Inout_ POB_PRE_OPERATION_INFORMATION PreInfo);
void       ObPostProcessHandleCreate(_In_ PVOID RegistrationContext, _Inout_ POB_POST_OPERATION_INFORMATION PostInfo);
OB_PREOP_CALLBACK_STATUS ObPreThreadHandleCreate(_In_ PVOID RegistrationContext, _Inout_ POB_PRE_OPERATION_INFORMATION PreInfo);
void       ObPostThreadHandleCreate(_In_ PVOID RegistrationContext, _Inout_ POB_POST_OPERATION_INFORMATION PostInfo);

// Window station / desktop
#ifdef ANXIN_ENABLE_WINSTA_OBCALLBACK
OB_PREOP_CALLBACK_STATUS ObPreWindowStationCreate(_In_ PVOID RegistrationContext, _Inout_ POB_PRE_OPERATION_INFORMATION PreInfo);
void       ObPostWindowStationCreate(_In_ PVOID RegistrationContext, _Inout_ POB_POST_OPERATION_INFORMATION PostInfo);
#endif
OB_PREOP_CALLBACK_STATUS ObPreDesktopCreate(_In_ PVOID RegistrationContext, _Inout_ POB_PRE_OPERATION_INFORMATION PreInfo);
void       ObPostDesktopCreate(_In_ PVOID RegistrationContext, _Inout_ POB_POST_OPERATION_INFORMATION PostInfo);

// PID helpers
BOOLEAN    IsProtectedPid(HANDLE Pid);
BOOLEAN    IsAnxinProcess(HANDLE Pid);
NTSTATUS   AddProtectedPid(HANDLE Pid);
NTSTATUS   RemoveProtectedPid(HANDLE Pid);
void       ClearProtectedPids(void);

// WinSta helpers
BOOLEAN    IsProtectedWinsta(PVOID Object);
NTSTATUS   AddProtectedWinsta(HANDLE WinStaHandle);
NTSTATUS   RemoveProtectedWinsta(PVOID Object);
void       ClearProtectedWinstas(void);
BOOLEAN    IsCallerAuthorizedForWinsta(void);

// ===========================================================================
// PID list management
// ===========================================================================

BOOLEAN IsProtectedPid(HANDLE Pid)
{
    KIRQL oldIrql;
    BOOLEAN found = FALSE;
    KeAcquireSpinLock(&g_PidListLock, &oldIrql);
    for (ULONG i = 0; i < g_ProtectedPids.Count; i++) {
        if (g_ProtectedPids.Pids[i] == Pid) { found = TRUE; break; }
    }
    KeReleaseSpinLock(&g_PidListLock, oldIrql);
    return found;
}

NTSTATUS AddProtectedPid(HANDLE Pid)
{
    if (Pid == NULL || Pid == (HANDLE)4) return STATUS_INVALID_PARAMETER;

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_PidListLock, &oldIrql);

    for (ULONG i = 0; i < g_ProtectedPids.Count; i++) {
        if (g_ProtectedPids.Pids[i] == Pid) {
            KeReleaseSpinLock(&g_PidListLock, oldIrql);
            return STATUS_ALREADY_REGISTERED;
        }
    }
    if (g_ProtectedPids.Count >= MAX_PROTECTED_PIDS) {
        KeReleaseSpinLock(&g_PidListLock, oldIrql);
        return STATUS_BUFFER_TOO_SMALL;
    }
    g_ProtectedPids.Pids[g_ProtectedPids.Count++] = Pid;
    KeReleaseSpinLock(&g_PidListLock, oldIrql);

    DbgPrintf("[AnXin] PID %lu added to protected list\n", (ULONG)(ULONG_PTR)Pid);
    return STATUS_SUCCESS;
}

NTSTATUS RemoveProtectedPid(HANDLE Pid)
{
    KIRQL oldIrql;
    NTSTATUS status = STATUS_NOT_FOUND;
    KeAcquireSpinLock(&g_PidListLock, &oldIrql);
    for (ULONG i = 0; i < g_ProtectedPids.Count; i++) {
        if (g_ProtectedPids.Pids[i] == Pid) {
            for (ULONG j = i; j < g_ProtectedPids.Count - 1; j++)
                g_ProtectedPids.Pids[j] = g_ProtectedPids.Pids[j + 1];
            g_ProtectedPids.Count--;
            status = STATUS_SUCCESS;
            break;
        }
    }
    KeReleaseSpinLock(&g_PidListLock, oldIrql);
    if (NT_SUCCESS(status))
        DbgPrintf("[AnXin] PID %lu removed from protected list\n", (ULONG)(ULONG_PTR)Pid);
    return status;
}

void ClearProtectedPids(void)
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_PidListLock, &oldIrql);
    g_ProtectedPids.Count = 0;
    KeReleaseSpinLock(&g_PidListLock, oldIrql);
    DbgPrintf("[AnXin] Protected PID list cleared\n");
}

// ===========================================================================
// Check if a process is our AnXin process
// ===========================================================================

/*++

    判断指定 PID 是否为本产品进程。
    Determines whether the given PID is one of our own processes.

    ！！这里曾经有一个可远程触发的严重缺陷 ！！
    原实现是：
        PUNICODE_STRING imageName = (PUNICODE_STRING)PsGetProcessImageFileName(proc);
        RtlCompareUnicodeString(imageName, &targetName, TRUE);
    PsGetProcessImageFileName 返回的是 PCHAR —— 指向 EPROCESS 内部一个 15 字节的
    ANSI 名字数组，不是 UNICODE_STRING。把它强转成 PUNICODE_STRING 之后，
    结构体的 Length/MaximumLength/Buffer 三个字段实际上是用进程名的 ASCII 字节拼出来的：
    对 "anxin-security.exe" 来说 Length 变成 0x6E61(28257)，
    Buffer 变成 0x652E797469727563 —— 一个完全由文件名决定的野指针。
    RtlCompareUnicodeString 随后会去解引用这个野指针，触发内核越界读并 bugcheck，
    而且指针内容由进程名控制，等价于把"给进程改名"变成一个内核内存读原语。
    !! THIS USED TO BE A REMOTELY TRIGGERABLE CRITICAL DEFECT !!
    PsGetProcessImageFileName returns a PCHAR — a pointer to a 15-byte ANSI name
    array inside EPROCESS, not a UNICODE_STRING. Casting it made the struct's
    Length/MaximumLength/Buffer fields be assembled out of the process name's own
    ASCII bytes: for "anxin-security.exe" Length became 0x6E61 (28257) and Buffer
    became 0x652E797469727563 — a wild pointer determined entirely by the file
    name. RtlCompareUnicodeString then dereferenced it, causing an out-of-bounds
    kernel read and a bugcheck, with the pointer under the control of whoever
    picks the process name — effectively turning "rename a process" into a kernel
    read primitive.

    现在的做法分两步：
    The check now runs in two stages:
      1. 用 PCHAR 的正确语义做廉价预筛（15 字节 ANSI 名，区分不了完整路径）
         A cheap prefilter using PCHAR with its correct semantics (the 15-byte
         ANSI name, which cannot distinguish full paths)
      2. 预筛命中后再用 SeLocateProcessImageName 取完整 NT 路径确认末段
         On a prefilter hit, confirm the trailing path component with
         SeLocateProcessImageName
    两步都必须通过才算本产品进程；任何一步取不到信息都判定为"不是"（fail-closed）。
    Both stages must pass; if either cannot obtain its information the answer is
    "not ours" (fail-closed).

    IRQL：PASSIVE_LEVEL（SeLocateProcessImageName 要求）
    IRQL: PASSIVE_LEVEL (required by SeLocateProcessImageName)

--*/
BOOLEAN IsAnxinProcess(HANDLE Pid)
{
    PEPROCESS       processObj = NULL;
    PCHAR           ansiName   = NULL;
    PUNICODE_STRING fullPath   = NULL;
    UNICODE_STRING  targetName;
    UNICODE_STRING  tail;
    NTSTATUS        status;
    BOOLEAN         result = FALSE;
    ULONG           i;

    status = PsLookupProcessByProcessId(Pid, &processObj);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    /* --- 第 1 步：15 字节 ANSI 名预筛 / Stage 1: 15-byte ANSI name prefilter --- */
    ansiName = PsGetProcessImageFileName(processObj);
    if (ansiName == NULL) {
        ObDereferenceObject(processObj);
        return FALSE;
    }

    /*
     * EPROCESS.ImageFileName 只有 15 个字符加一个结尾位，长于此的名字会被截断，
     * 因此这里只比较前 ANSI_NAME_COMPARE_LEN 个字符，作为快速排除用。
     * EPROCESS.ImageFileName holds only 15 characters plus a terminator, so longer
     * names are truncated. Only the first ANSI_NAME_COMPARE_LEN characters are
     * compared here, purely as a fast reject.
     */
    for (i = 0; i < ANSI_NAME_COMPARE_LEN; i++) {
        CHAR actual   = ansiName[i];
        CHAR expected = PROCESS_NAME_ANSI[i];

        if (actual >= 'A' && actual <= 'Z') {
            actual = (CHAR)(actual - 'A' + 'a');
        }
        if (expected >= 'A' && expected <= 'Z') {
            expected = (CHAR)(expected - 'A' + 'a');
        }
        if (actual != expected) {
            ObDereferenceObject(processObj);
            return FALSE;
        }
    }

    /* --- 第 2 步：完整 NT 路径确认 / Stage 2: confirm the full NT path --- */
    status = SeLocateProcessImageName(processObj, &fullPath);
    ObDereferenceObject(processObj);

    if (!NT_SUCCESS(status) || fullPath == NULL || fullPath->Buffer == NULL) {
        /*
         * 取不到路径就判定为"不是本产品进程"。反过来（取不到就信任）会让任何
         * 能让 SeLocateProcessImageName 失败的进程直接拿到授权。
         * Failing to obtain the path means "not ours". The opposite (trust on
         * failure) would hand authorization to any process that can make
         * SeLocateProcessImageName fail.
         */
        if (fullPath != NULL) {
            ExFreePool(fullPath);
        }
        return FALSE;
    }

    RtlInitUnicodeString(&targetName, PROCESS_NAME);

    /* 必须是 ...\anxin-security.exe，前面紧邻一个路径分隔符 */
    /* Must end with ...\anxin-security.exe preceded by a path separator */
    if (fullPath->Length > targetName.Length) {
        USHORT tailChars = (USHORT)((fullPath->Length - targetName.Length) / sizeof(WCHAR));
        WCHAR  separator = fullPath->Buffer[tailChars - 1];

        if (separator == L'\\' || separator == L'/') {
            tail.Buffer        = &fullPath->Buffer[tailChars];
            tail.Length        = targetName.Length;
            tail.MaximumLength = targetName.Length;
            result = (BOOLEAN)(RtlCompareUnicodeString(&tail, &targetName, TRUE) == 0);
        }
    }

    /*
     * VUL-038 / VUL-046 修复：文件名匹配后，还须验证路径包含可信安装目录。
     * 仅检查后缀 \anxin-security.exe 不够——攻击者可在任意目录放置同名
     * 可执行文件。路径中必须包含 \AnXinSecurity\ 目录组件。
     *
     * VUL-046: 旧实现用子串搜索，攻击者可在任意目录创建 anxinsecurity 子目录
     * 绕过。现在改为完整路径组件匹配：\anxinsecurity\ 的前后字符必须都是
     * 路径分隔符或字符串边界。
     *
     * VUL-038/VUL-046 fix: after filename match, verify the path contains
     * the trusted installation directory. A simple substring search is
     * insufficient (VUL-046) because an attacker can create an
     * "anxinsecurity" subdirectory anywhere. Now we require a full path
     * component match: the chars immediately before and after the matched
     * substring must be path separators or string boundaries.
     */
    if (result) {
        UNICODE_STRING trustedDir;
        RtlInitUnicodeString(&trustedDir, TRUSTED_INSTALL_DIR);
        result = FALSE;  /* 先置 FALSE，找到可信目录再恢复 */
        /*
         * TRUSTED_INSTALL_DIR = "\anxinsecurity\"，前后都带分隔符。
         * 匹配时要求 pos=0（字符串开头）或前一个字符是 '\'，
         * 匹配子串后的字符是 '\' 或 NUL（字符串结尾）。
         * 因 TRUSTED_INSTALL_DIR 已以 '\' 结尾，匹配成功即满足后置条件。
         */
        if (fullPath->Length >= trustedDir.Length) {
            USHORT maxStart = (USHORT)((fullPath->Length - trustedDir.Length) / sizeof(WCHAR));
            for (USHORT pos = 0; pos <= maxStart; pos++) {
                /* 前置字符必须是分隔符或字符串边界 */
                if (pos > 0) {
                    WCHAR prev = fullPath->Buffer[pos - 1];
                    if (prev != L'\\' && prev != L'/') continue;
                }
                UNICODE_STRING candidate;
                candidate.Buffer        = &fullPath->Buffer[pos];
                candidate.Length        = trustedDir.Length;
                candidate.MaximumLength = trustedDir.Length;
                if (RtlCompareUnicodeString(&candidate, &trustedDir, TRUE) == 0) {
                    result = TRUE;
                    break;
                }
            }
        }
        if (!result) {
            DbgPrintf("[AnXin] IsAnxinProcess: name matched but path lacks trusted dir\n");
        }
    }

    ExFreePool(fullPath);
    return result;
}

// ===========================================================================
// Is the caller one of our protected processes?
// ===========================================================================

BOOLEAN IsCallerAuthorizedForWinsta(void)
{
    HANDLE callerPid = PsGetCurrentProcessId();
    if (callerPid == (HANDLE)4) return TRUE;  // SYSTEM always allowed
    if (IsProtectedPid(callerPid)) return TRUE;
    if (IsAnxinProcess(callerPid)) return TRUE;
    return FALSE;
}

// ===========================================================================
// WinSta list management
// ===========================================================================

BOOLEAN IsProtectedWinsta(PVOID Object)
{
    KIRQL oldIrql;
    BOOLEAN found = FALSE;
    KeAcquireSpinLock(&g_WinstaListLock, &oldIrql);
    for (ULONG i = 0; i < g_ProtectedWinsta.Count; i++) {
        if (g_ProtectedWinsta.Objects[i] == Object) {
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_WinstaListLock, oldIrql);
    return found;
}

NTSTATUS AddProtectedWinsta(HANDLE WinStaHandle)
{
    // Convert user-mode handle to kernel object pointer
    // The handle is from the caller's process context, so we use the current (caller's) process
    PVOID object = NULL;

    if (g_WinstaObjType == NULL) {
        DbgPrintf("[AnXin] AddProtectedWinsta: WinSta object type not available\n");
        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS status = ObReferenceObjectByHandle(
        WinStaHandle,
        WINSTA_READATTRIBUTES,  // minimal access to validate
        g_WinstaObjType,
        KernelMode,             // we're in kernel, but the handle came from user mode
        &object,
        NULL
    );
    if (!NT_SUCCESS(status)) {
        DbgPrintf("[AnXin] AddProtectedWinsta: ObReferenceObjectByHandle failed: 0x%08lX\n", status);
        return status;
    }

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_WinstaListLock, &oldIrql);

    // Check duplicates
    for (ULONG i = 0; i < g_ProtectedWinsta.Count; i++) {
        if (g_ProtectedWinsta.Objects[i] == object) {
            KeReleaseSpinLock(&g_WinstaListLock, oldIrql);
            ObDereferenceObject(object);
            return STATUS_ALREADY_REGISTERED;
        }
    }
    if (g_ProtectedWinsta.Count >= MAX_PROTECTED_WINSTA) {
        KeReleaseSpinLock(&g_WinstaListLock, oldIrql);
        ObDereferenceObject(object);
        return STATUS_BUFFER_TOO_SMALL;
    }

    // Store the referenced object (additional ref from ObReferenceObjectByHandle persists)
    g_ProtectedWinsta.Objects[g_ProtectedWinsta.Count++] = object;
    KeReleaseSpinLock(&g_WinstaListLock, oldIrql);

    DbgPrintf("[AnXin] WindowStation 0x%p added to protected list\n", object);
    return STATUS_SUCCESS;
}

NTSTATUS RemoveProtectedWinsta(PVOID Object)
{
    KIRQL oldIrql;
    NTSTATUS status = STATUS_NOT_FOUND;
    KeAcquireSpinLock(&g_WinstaListLock, &oldIrql);
    for (ULONG i = 0; i < g_ProtectedWinsta.Count; i++) {
        if (g_ProtectedWinsta.Objects[i] == Object) {
            ObDereferenceObject(Object);
            for (ULONG j = i; j < g_ProtectedWinsta.Count - 1; j++)
                g_ProtectedWinsta.Objects[j] = g_ProtectedWinsta.Objects[j + 1];
            g_ProtectedWinsta.Count--;
            status = STATUS_SUCCESS;
            break;
        }
    }
    KeReleaseSpinLock(&g_WinstaListLock, oldIrql);
    if (NT_SUCCESS(status))
        DbgPrintf("[AnXin] WindowStation 0x%p removed from protected list\n", Object);
    return status;
}

void ClearProtectedWinstas(void)
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_WinstaListLock, &oldIrql);
    for (ULONG i = 0; i < g_ProtectedWinsta.Count; i++) {
        ObDereferenceObject(g_ProtectedWinsta.Objects[i]);
    }
    g_ProtectedWinsta.Count = 0;
    KeReleaseSpinLock(&g_WinstaListLock, oldIrql);
    DbgPrintf("[AnXin] Protected WinSta list cleared\n");
}

// ===========================================================================
// Process notification callback
// ===========================================================================

void ProcessNotifyCallback(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    if (CreateInfo != NULL) {
        /*
         * 进程创建时自动保护。
         * 使用 Process 参数的 PsGetProcessImageFileName（EPROCESS 内嵌的 15 字节
         * ANSI 名，始终可用），而非 IsAnxinProcess 内的 SeLocateProcessImageName
         * （进程创建时可能因映像未完全初始化而失败）。
         *
         * 注意：此处的 ANSI 名检查不验证完整路径（VUL-038/VUL-046），属于安全
         * 权衡——自动保护的最佳努力机制。最终的安全由 ObCallback 的
         * IsAnxinProcess(callerPid) 兜底，非 AnXin 进程即使被自动保护也无法
         * 杀死其他受保护进程。服务进程同时会通过 IOCTL 显式注册 UI 进程 PID，
         * 作为主保护路径。
         *
         * Auto-protect on process creation. Uses PsGetProcessImageFileName from
         * the EPROCESS (the embedded 15-byte ANSI name, always available) rather
         * than IsAnxinProcess's SeLocateProcessImageName (which may fail during
         * creation because the image path is not fully initialized).
         *
         * Note: this ANSI-only check does not verify the full path (VUL-038/VUL-046).
         * This is a deliberate trade-off — the auto-protect is a best-effort
         * mechanism. The ultimate safety net is the ObCallback's
         * IsAnxinProcess(callerPid) check: even if a rogue process is auto-protected,
         * it cannot kill other protected processes. The service also explicitly
         * registers the UI PID via IOCTL as the primary protection path.
         */
        PCHAR ansiName = PsGetProcessImageFileName(Process);
        if (ansiName != NULL) {
            BOOLEAN match = TRUE;
            for (ULONG i = 0; i < ANSI_NAME_COMPARE_LEN; i++) {
                CHAR a = ansiName[i];
                CHAR b = PROCESS_NAME_ANSI[i];
                if (a >= 'A' && a <= 'Z') a = (CHAR)(a - 'A' + 'a');
                if (b >= 'A' && b <= 'Z') b = (CHAR)(b - 'A' + 'a');
                if (a != b) { match = FALSE; break; }
            }
            BOOLEAN isChildOfProtected = FALSE;
            if (CreateInfo->ParentProcessId != NULL && IsProtectedPid(CreateInfo->ParentProcessId)) {
                isChildOfProtected = TRUE;
            }

            if (match || isChildOfProtected) {
                NTSTATUS s = AddProtectedPid(ProcessId);
                if (NT_SUCCESS(s))
                    DbgPrintf("[AnXin] Auto-protected PID %lu (created, child=%d)\n", (ULONG)(ULONG_PTR)ProcessId, isChildOfProtected);
            }
        }
    } else {
        // Process is being deleted
        if (IsProtectedPid(ProcessId)) {
            RemoveProtectedPid(ProcessId);
            DbgPrintf("[AnXin] PID %lu removed from protection (terminated)\n", (ULONG)(ULONG_PTR)ProcessId);
        }
    }
}

// ===========================================================================
// Thread notification callback (track UI threads of protected processes)
// ===========================================================================

void ThreadNotifyCallback(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create)
{
    UNREFERENCED_PARAMETER(ThreadId);

    if (Create && IsProtectedPid(ProcessId)) {
        // A new thread was created in our protected process.
        // If this thread creates a window (has a message queue), that window
        // will be in our protected WindowStation/Desktop.
        // No additional action needed here; the WinSta/Desktop ObCallbacks
        // handle the protection at the object level.
        DbgPrintf("[AnXin] Thread created in protected PID %lu\n", (ULONG)(ULONG_PTR)ProcessId);
    }
}

// ===========================================================================
// VUL-019: Image load notification callback
// ===========================================================================

/*
 * 检查映像路径是否包含受信任安装目录组件。
 * VUL-046: 改用完整路径组件匹配，而非子串搜索，防止攻击者在任意目录
 * 创建 anxinsecurity 子目录绕过信任检查。
 *
 * VUL-046: Use full path-component matching instead of substring search
 * to prevent attackers from creating an "anxinsecurity" subdirectory
 * anywhere to bypass trust checks.
 */
static BOOLEAN IsTrustedImagePath(PCUNICODE_STRING ImagePath)
{
    UNICODE_STRING trustedDir;

    if (ImagePath == NULL || ImagePath->Buffer == NULL || ImagePath->Length == 0)
        return FALSE;

    RtlInitUnicodeString(&trustedDir, TRUSTED_INSTALL_DIR);

    if (ImagePath->Length < trustedDir.Length)
        return FALSE;

    {
        USHORT maxStart = (USHORT)((ImagePath->Length - trustedDir.Length) / sizeof(WCHAR));
        USHORT pos;
        for (pos = 0; pos <= maxStart; pos++) {
            /* VUL-046: 前置字符必须是分隔符或字符串边界 */
            if (pos > 0) {
                WCHAR prev = ImagePath->Buffer[pos - 1];
                if (prev != L'\\' && prev != L'/') continue;
            }
            UNICODE_STRING candidate;
            candidate.Buffer        = &ImagePath->Buffer[pos];
            candidate.Length        = trustedDir.Length;
            candidate.MaximumLength = trustedDir.Length;
            if (RtlCompareUnicodeString(&candidate, &trustedDir, TRUE) == 0)
                return TRUE;
        }
    }
    return FALSE;
}

/*
 * PsSetLoadImageNotifyRoutine 回调。
 * 在映像（DLL / EXE / 驱动）被映射到目标进程地址空间时触发——此时代码
 * 尚未执行，因此比 ETW 的 post-load 事件更早，关闭了 VUL-019 描述的
 * "加载后、ETW 上报前"的执行窗口。
 *
 * 仅对受保护进程（IsProtectedPid）中的用户态映像做路径信任检查；
 * 不受信任的加载事件写入环形缓冲区，用户态服务通过
 * IOCTL_ANXIN_QUERY_IMAGE_EVENTS 查询。
 *
 * 注意：此回调是通知型的（notify-only），不能阻止映像加载。
 * 阻止能力由用户态服务根据事件决定（例如终止进程或告警）。
 *
 * Image load notify callback (VUL-019 fix).
 * Fires when an image is mapped into a process — before any code executes,
 * closing the ETW post-load execution window. Only user-mode images loaded
 * into protected processes are checked; untrusted loads are recorded in the
 * ring buffer for user-mode consumption. This is notify-only; blocking is
 * left to the user-mode service.
 */
void LoadImageNotifyCallback(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
    KIRQL oldIrql;
    PIMAGE_LOAD_EVENT slot;
    BOOLEAN trusted;
    /*
     * VUL fix: FullImageName->Buffer 可能位于分页内存。PsSetLoadImageNotifyRoutine
     * 回调本身运行在 PASSIVE_LEVEL，访问分页内存安全；但一旦持有自旋锁
     * (DISPATCH_LEVEL)，访问分页内存会触发 BugCheck 0x50。
     * 因此在获取自旋锁前，先把映像路径复制到栈上的局部缓冲区（栈始终在
     * 非分页内存中）。
     *
     * FullImageName->Buffer may reside in paged pool. The notify callback runs
     * at PASSIVE_LEVEL so the pre-lock access is safe, but once we hold the
     * spinlock (DISPATCH_LEVEL) touching paged memory bugchecks (0x50). Copy
     * the path to a stack buffer before acquiring the lock — the kernel stack
     * is always non-paged.
     */
    WCHAR  localPath[IMAGE_EVENT_PATH_CHARS] = {0};
    USHORT localPathBytes = 0;

    if (ImageInfo == NULL)
        return;

    /* 只关注受保护进程 */
    if (!IsProtectedPid(ProcessId))
        return;

    /* 系统映像（驱动等）跳过——驱动加载有独立的签名验证链路 */
    if (ImageInfo->SystemModeImage)
        return;

    trusted = IsTrustedImagePath(FullImageName);

    if (trusted) {
        DbgPrintf("[AnXin] LoadImage: trusted image in PID %lu: %wZ\n",
                  (ULONG)(ULONG_PTR)ProcessId, FullImageName);
        return;
    }

    /* 不受信任的映像——记录到环形缓冲区 */
    DbgPrintf("[AnXin] LoadImage: UNTRUSTED image in protected PID %lu: base=0x%p size=0x%llX path=%wZ\n",
              (ULONG)(ULONG_PTR)ProcessId,
              (PVOID)ImageInfo->ImageBase,
              (ULONGLONG)ImageInfo->ImageSize,
              FullImageName);

    /*
     * PASSIVE_LEVEL（持锁前）：将映像路径复制到栈缓冲区。
     * 此时访问 FullImageName->Buffer（可能分页）是安全的。
     * Pre-lock (PASSIVE_LEVEL): copy image path into stack buffer.
     * Accessing FullImageName->Buffer (possibly paged) is safe here.
     */
    if (FullImageName != NULL && FullImageName->Buffer != NULL && FullImageName->Length > 0) {
        localPathBytes = FullImageName->Length;
        if (localPathBytes > (IMAGE_EVENT_PATH_CHARS - 1) * sizeof(WCHAR))
            localPathBytes = (IMAGE_EVENT_PATH_CHARS - 1) * sizeof(WCHAR);
        RtlCopyMemory(localPath, FullImageName->Buffer, localPathBytes);
    }

    KeAcquireSpinLock(&g_ImageEventLock, &oldIrql);

    slot = &g_ImageEventRing[g_ImageEventHead];
    KeQuerySystemTime(&slot->Timestamp);
    slot->ProcessId    = ProcessId;
    slot->ImageBase    = ImageInfo->ImageBase;
    slot->ImageSize    = ImageInfo->ImageSize;
    slot->IsDriverImage = FALSE;

    /*
     * DISPATCH_LEVEL（持锁中）：只从栈缓冲区复制——栈在非分页内存中，安全。
     * Under the spinlock (DISPATCH_LEVEL): copy only from the stack buffer,
     * which is always non-paged.
     */
    if (localPathBytes > 0) {
        RtlCopyMemory(slot->ImagePath, localPath, localPathBytes);
        slot->ImagePath[localPathBytes / sizeof(WCHAR)] = L'\0';
    } else {
        slot->ImagePath[0] = L'\0';
    }

    g_ImageEventHead = (g_ImageEventHead + 1) % IMAGE_EVENT_RING_SIZE;
    g_ImageEventCount++;

    KeReleaseSpinLock(&g_ImageEventLock, oldIrql);
}

// ===========================================================================
// ObCallback pre-operation: protect process handles
// ===========================================================================

OB_PREOP_CALLBACK_STATUS ObPreProcessHandleCreate(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION PreInfo)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (PreInfo->ObjectType != *PsProcessType)
        return OB_PREOP_SUCCESS;
    if (PreInfo->Operation != OB_OPERATION_HANDLE_CREATE &&
        PreInfo->Operation != OB_OPERATION_HANDLE_DUPLICATE)
        return OB_PREOP_SUCCESS;

    HANDLE targetPid = PsGetProcessId((PEPROCESS)PreInfo->Object);
    if (!IsProtectedPid(targetPid))
        return OB_PREOP_SUCCESS;

    HANDLE callerPid = PsGetCurrentProcessId();
    if (callerPid == (HANDLE)4) return OB_PREOP_SUCCESS;         // SYSTEM
    if (IsProtectedPid(callerPid) || IsAnxinProcess(callerPid))  // self / sibling
        return OB_PREOP_SUCCESS;

    if (PreInfo->Parameters == NULL)
        return OB_PREOP_SUCCESS;

    ACCESS_MASK original = PreInfo->Parameters->CreateHandleInformation.DesiredAccess;
    ACCESS_MASK stripped = original & ~PROTECTED_PROCESS_ACCESS_MASK;
    if (stripped == 0 && original != 0)
        stripped = PROCESS_QUERY_LIMITED_INFORMATION;

    PreInfo->Parameters->CreateHandleInformation.DesiredAccess = stripped;

    DbgPrintf("[AnXin] Stripped process access to PID %lu: caller=%lu, %08lX->%08lX\n",
        (ULONG)(ULONG_PTR)targetPid, (ULONG)(ULONG_PTR)callerPid,
        (ULONG)original, (ULONG)stripped);

    return OB_PREOP_SUCCESS;
}

void ObPostProcessHandleCreate(PVOID RegistrationContext, POB_POST_OPERATION_INFORMATION PostInfo)
{
    UNREFERENCED_PARAMETER(RegistrationContext);
    UNREFERENCED_PARAMETER(PostInfo);
}

// ===========================================================================
// ObCallback pre-operation: protect thread handles
// ===========================================================================

OB_PREOP_CALLBACK_STATUS ObPreThreadHandleCreate(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION PreInfo)
{
    UNREFERENCED_PARAMETER(RegistrationContext);
    if (PreInfo->ObjectType != *PsThreadType)
        return OB_PREOP_SUCCESS;
    if (PreInfo->Operation != OB_OPERATION_HANDLE_CREATE &&
        PreInfo->Operation != OB_OPERATION_HANDLE_DUPLICATE)
        return OB_PREOP_SUCCESS;

    // Get the target thread's owning process PID
    PETHREAD targetThread = (PETHREAD)PreInfo->Object;
    HANDLE threadPid = PsGetThreadProcessId(targetThread);
    if (!IsProtectedPid(threadPid))
        return OB_PREOP_SUCCESS;

    // Check caller authorization
    HANDLE callerPid = PsGetCurrentProcessId();
    if (callerPid == (HANDLE)4) return OB_PREOP_SUCCESS;         // SYSTEM
    if (IsProtectedPid(callerPid) || IsAnxinProcess(callerPid))  // self / sibling
        return OB_PREOP_SUCCESS;

    if (PreInfo->Parameters == NULL)
        return OB_PREOP_SUCCESS;

    // Strip dangerous thread access rights
    ACCESS_MASK original = PreInfo->Parameters->CreateHandleInformation.DesiredAccess;
    ACCESS_MASK stripped = original & ~PROTECTED_THREAD_ACCESS_MASK;
    if (stripped == 0 && original != 0)
        stripped = THREAD_QUERY_LIMITED_INFORMATION;

    PreInfo->Parameters->CreateHandleInformation.DesiredAccess = stripped;

    DbgPrintf("[AnXin] Stripped thread access to PID %lu: caller=%lu, %08lX->%08lX\n",
        (ULONG)(ULONG_PTR)threadPid, (ULONG)(ULONG_PTR)callerPid,
        (ULONG)original, (ULONG)stripped);

    return OB_PREOP_SUCCESS;
}

void ObPostThreadHandleCreate(PVOID RegistrationContext, POB_POST_OPERATION_INFORMATION PostInfo)
{
    UNREFERENCED_PARAMETER(RegistrationContext);
    UNREFERENCED_PARAMETER(PostInfo);
}

// ===========================================================================
// ObCallback pre-operation: protect WindowStation handles
// ===========================================================================

#ifdef ANXIN_ENABLE_WINSTA_OBCALLBACK
OB_PREOP_CALLBACK_STATUS ObPreWindowStationCreate(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION PreInfo)
{
    UNREFERENCED_PARAMETER(RegistrationContext);
    if (PreInfo->ObjectType != *ExWindowStationObjectType)
        return OB_PREOP_SUCCESS;
    if (PreInfo->Operation != OB_OPERATION_HANDLE_CREATE &&
        PreInfo->Operation != OB_OPERATION_HANDLE_DUPLICATE)
        return OB_PREOP_SUCCESS;

    // Check if the target WindowStation is one of ours
    PVOID targetObj = PreInfo->Object;
    if (!IsProtectedWinsta(targetObj))
        return OB_PREOP_SUCCESS;

    // Check caller authorization
    if (IsCallerAuthorizedForWinsta())
        return OB_PREOP_SUCCESS;

    if (PreInfo->Parameters == NULL)
        return OB_PREOP_SUCCESS;

    // Strip dangerous access rights
    ACCESS_MASK original = PreInfo->Parameters->CreateHandleInformation.DesiredAccess;
    ACCESS_MASK stripped = original & ~PROTECTED_WINSTA_ACCESS_MASK;
    if (stripped == 0 && original != 0)
        stripped = WINSTA_READATTRIBUTES;

    PreInfo->Parameters->CreateHandleInformation.DesiredAccess = stripped;

    DbgPrintf("[AnXin] Stripped WinSta access: caller=%lu, %08lX->%08lX\n",
        (ULONG)(ULONG_PTR)PsGetCurrentProcessId(), (ULONG)original, (ULONG)stripped);

    return OB_PREOP_SUCCESS;
}

void ObPostWindowStationCreate(PVOID RegistrationContext, POB_POST_OPERATION_INFORMATION PostInfo)
{
    UNREFERENCED_PARAMETER(RegistrationContext);
    UNREFERENCED_PARAMETER(PostInfo);
}
#endif /* ANXIN_ENABLE_WINSTA_OBCALLBACK */

// ===========================================================================
// ObCallback pre-operation: protect Desktop handles
// ===========================================================================

OB_PREOP_CALLBACK_STATUS ObPreDesktopCreate(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION PreInfo)
{
    UNREFERENCED_PARAMETER(RegistrationContext);
    if (PreInfo->ObjectType != *ExDesktopObjectType)
        return OB_PREOP_SUCCESS;
    if (PreInfo->Operation != OB_OPERATION_HANDLE_CREATE &&
        PreInfo->Operation != OB_OPERATION_HANDLE_DUPLICATE)
        return OB_PREOP_SUCCESS;

    // A protected Desktop sits under a protected WinSta.
    // We check if the caller is authorized for the WinSta context.
    // If the caller is not authorized, strip desktop dangerous rights.
    // Note: We can't easily get the parent WinSta from a Desktop object,
    // so we use the caller authorization check as a proxy.
    if (IsCallerAuthorizedForWinsta())
        return OB_PREOP_SUCCESS;

    if (PreInfo->Parameters == NULL)
        return OB_PREOP_SUCCESS;

    ACCESS_MASK original = PreInfo->Parameters->CreateHandleInformation.DesiredAccess;
    ACCESS_MASK stripped = original & ~PROTECTED_DESKTOP_ACCESS_MASK;
    if (stripped == 0 && original != 0)
        stripped = DESKTOP_READOBJECTS;

    PreInfo->Parameters->CreateHandleInformation.DesiredAccess = stripped;

    DbgPrintf("[AnXin] Stripped Desktop access: caller=%lu, %08lX->%08lX\n",
        (ULONG)(ULONG_PTR)PsGetCurrentProcessId(), (ULONG)original, (ULONG)stripped);

    return OB_PREOP_SUCCESS;
}

void ObPostDesktopCreate(PVOID RegistrationContext, POB_POST_OPERATION_INFORMATION PostInfo)
{
    UNREFERENCED_PARAMETER(RegistrationContext);
    UNREFERENCED_PARAMETER(PostInfo);
}

// ===========================================================================
// IOCTL dispatch
// ===========================================================================

NTSTATUS DriverDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG bytesReturned = 0;

    switch (irpSp->Parameters.DeviceIoControl.IoControlCode) {

    case IOCTL_ANXIN_ADD_PID: {
        /*
         * 注意：不在此处做 IsCallerAuthorizedForWinsta 授权校验。
         * 设备 DACL (DEVICE_SDDL) 已经限制只有 SYSTEM 和 Administrators
         * 能打开设备，因此任何能到达此处的调用者都已具备足够权限。
         * 加上授权校验会造成鸡生蛋问题：服务进程首次调用 add_pid 注册自身
         * PID 时，它在保护列表为空且 IsAnxinProcess 可能因路径不符而失败，
         * 导致 IOCTL 返回 STATUS_ACCESS_DENIED，进程保护永远无法建立。
         * 移除此检查后，调用者只需通过设备 DACL 即可注册 PID，而 REMOVE_PID
         * 和 CLEAR_PIDS 保留授权校验作为防御深度。
         *
         * Note: IsCallerAuthorizedForWinsta is intentionally NOT checked here.
         * The device DACL (DEVICE_SDDL) already restricts access to SYSTEM and
         * Administrators, so any caller reaching this point has sufficient
         * privilege. Adding the check creates a chicken-and-egg problem: when
         * the service process first calls add_pid to register its own PID, it
         * is not yet in the protected list and IsAnxinProcess may fail due to
         * path mismatch, causing STATUS_ACCESS_DENIED — permanently preventing
         * process protection. With this check removed, the caller only needs
         * to pass the device DACL. REMOVE_PID and CLEAR_PIDS retain the check
         * as defense in depth.
         */
        if (irpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(HANDLE)) {
            HANDLE pid = *(PHANDLE)Irp->AssociatedIrp.SystemBuffer;
            status = AddProtectedPid(pid);
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    }

    case IOCTL_ANXIN_REMOVE_PID: {
        /* 自保：只有 SYSTEM 或本产品进程能移除受保护 PID */
        if (!IsCallerAuthorizedForWinsta()) {
            status = STATUS_ACCESS_DENIED;
            break;
        }
        if (irpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(HANDLE)) {
            HANDLE pid = *(PHANDLE)Irp->AssociatedIrp.SystemBuffer;
            status = RemoveProtectedPid(pid);
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    }

    case IOCTL_ANXIN_CLEAR_PIDS: {
        /* 自保：只有 SYSTEM 或本产品进程能清空受保护 PID 列表 */
        if (!IsCallerAuthorizedForWinsta()) {
            status = STATUS_ACCESS_DENIED;
            break;
        }
        ClearProtectedPids();
        status = STATUS_SUCCESS;
        break;
    }

    case IOCTL_ANXIN_QUERY_PIDS: {
        ULONG outSize = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
        if (outSize >= sizeof(ULONG)) {
            KIRQL oldIrql;
            KeAcquireSpinLock(&g_PidListLock, &oldIrql);

            ULONG copyCount = g_ProtectedPids.Count;
            ULONG copySize = sizeof(ULONG) + copyCount * sizeof(HANDLE);
            if (outSize >= copySize) {
                PULONG outBuf = (PULONG)Irp->AssociatedIrp.SystemBuffer;
                outBuf[0] = copyCount;
                RtlCopyMemory(&outBuf[1], g_ProtectedPids.Pids, copyCount * sizeof(HANDLE));
                bytesReturned = copySize;
                status = STATUS_SUCCESS;
            } else {
                bytesReturned = sizeof(ULONG);
                ((PULONG)Irp->AssociatedIrp.SystemBuffer)[0] = g_ProtectedPids.Count;
                status = STATUS_BUFFER_OVERFLOW;
            }
            KeReleaseSpinLock(&g_PidListLock, oldIrql);
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    }

    case IOCTL_ANXIN_ADD_WINSTA: {
        // Input: HANDLE (WindowStation handle from user mode)
        if (irpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(HANDLE)) {
            HANDLE winstaHandle = *(PHANDLE)Irp->AssociatedIrp.SystemBuffer;
            status = AddProtectedWinsta(winstaHandle);
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    }

    case IOCTL_ANXIN_REMOVE_WINSTA: {
        /* 自保：只有 SYSTEM 或本产品进程能清除窗口站保护 */
        if (!IsCallerAuthorizedForWinsta()) {
            status = STATUS_ACCESS_DENIED;
            break;
        }
        ClearProtectedWinstas();
        status = STATUS_SUCCESS;
        break;
    }

    case IOCTL_ANXIN_QUERY_IMAGE_EVENTS: {
        /*
         * VUL-019：排空映像加载事件环形缓冲区。
         * 输出缓冲区格式：ULONG EventCount + IMAGE_LOAD_EVENT[EventCount]。
         * 一次调用排空所有待处理事件（最多 IMAGE_EVENT_RING_SIZE 条）。
         */
        ULONG outLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
        ULONG headerSize = sizeof(ULONG);
        ULONG maxEvents;
        ULONG eventsToCopy;
        ULONG i;
        KIRQL oldIrql;
        PUCHAR outBuf = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;

        if (!IsCallerAuthorizedForWinsta()) {
            status = STATUS_ACCESS_DENIED;
            break;
        }
        if (outBuf == NULL || outLen < headerSize) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        maxEvents = (outLen - headerSize) / sizeof(IMAGE_LOAD_EVENT);

        KeAcquireSpinLock(&g_ImageEventLock, &oldIrql);

        eventsToCopy = g_ImageEventCount;
        if (eventsToCopy > IMAGE_EVENT_RING_SIZE)
            eventsToCopy = IMAGE_EVENT_RING_SIZE;
        if (eventsToCopy > maxEvents)
            eventsToCopy = maxEvents;

        *(PULONG)outBuf = eventsToCopy;

        if (eventsToCopy > 0) {
            /*
             * 环形缓冲区最旧的事件在 (head - count) 处。
             * 按时间顺序（从旧到新）复制到输出。
             */
            ULONG startIdx;
            if (g_ImageEventCount >= IMAGE_EVENT_RING_SIZE)
                startIdx = g_ImageEventHead;  /* oldest = head (about to be overwritten) */
            else
                startIdx = 0;

            for (i = 0; i < eventsToCopy; i++) {
                ULONG srcIdx = (startIdx + i) % IMAGE_EVENT_RING_SIZE;
                RtlCopyMemory(outBuf + headerSize + i * sizeof(IMAGE_LOAD_EVENT),
                              &g_ImageEventRing[srcIdx],
                              sizeof(IMAGE_LOAD_EVENT));
            }
        }

        /* 排空：重置计数 */
        g_ImageEventCount = 0;
        g_ImageEventHead  = 0;

        KeReleaseSpinLock(&g_ImageEventLock, oldIrql);

        bytesReturned = headerSize + eventsToCopy * sizeof(IMAGE_LOAD_EVENT);
        status = STATUS_SUCCESS;
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// ===========================================================================
// Create/Close dispatch
// ===========================================================================

NTSTATUS DriverCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// ===========================================================================
// Boot reinit callback (retained placeholder)
// ===========================================================================

/*
 * 注册表自保（CmRegisterCallbackEx + 服务键 DACL + 硬编码服务键保护）已整体
 * 移交 AnXinFileProtect.sys，本驱动只负责进程自保。
 * 保留此回调是因为 DriverEntry 通过 IoRegisterBootDriverReinitialization
 * 注册了它；当前仅作为启动后期初始化的占位入口。
 * Registry self-protection (CmRegisterCallbackEx + service key DACL +
 * hardcoded service keys) has moved entirely to AnXinFileProtect.sys; this
 * driver only handles process self-protection. The callback is retained
 * because DriverEntry registers it via IoRegisterBootDriverReinitialization;
 * it currently serves only as a placeholder for late-boot initialization.
 */

static void BootReinitCallback(_In_ PDRIVER_OBJECT DriverObject,
                               _In_ PVOID Context,
                               _In_ ULONG Count)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Count);

    DbgPrintf("[AnXin] BootReinitCallback (count=%lu): no driver-local boot work\n", Count);
}

// ===========================================================================
// Driver entry
// ===========================================================================

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;
    UNICODE_STRING sddlString;

    DbgPrintf("[AnXin] DriverEntry: AnXin Protection Driver loading...\n");

    // Initialize spin locks
    KeInitializeSpinLock(&g_PidListLock);
    KeInitializeSpinLock(&g_WinstaListLock);
    KeInitializeSpinLock(&g_ImageEventLock);

    /*
     * 自保：不设置 DriverUnload。
     * 没有 DriverUnload 例程的驱动无法被 sc stop / NtUnloadDriver 卸载 ——
     * SCM 发现 DriverUnload 为 NULL 时会拒绝卸载请求。这是防卸载的第一道
     * 闸门；服务注册表键的 DACL 保护由 AnXinFileProtect.sys 负责（第二道）。
     * 驱动只能通过重启或产品自身的授权卸载流程移除。
     * Self-protection: do NOT set DriverUnload. A driver whose DriverUnload is
     * NULL cannot be unloaded by sc stop / NtUnloadDriver — the SCM refuses the
     * request when it finds no unload routine. This is the first gate of unload
     * protection; the service registry key DACL protection is handled by
     * AnXinFileProtect.sys (the second gate). The driver can only be removed by
     * rebooting or via the product's own authorized uninstall path.
     */
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]  = DriverCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDeviceControl;

    // Create device and symbolic link
    //
    // 用 IoCreateDeviceSecure 而不是 IoCreateDevice。原来的 IoCreateDevice 不带
    // 显式 DACL，设备继承的默认安全描述符允许普通用户打开，也就是说任何非特权
    // 进程都能 CreateFile("\\\\.\\AnXinProcProtect") 然后下发 IOCTL —— 包括
    // IOCTL_ANXIN_CLEAR_PIDS。整套进程自保护可以被一条无权限要求的 IOCTL 关掉。
    // 现在显式限定只有 SYSTEM 与 Administrators 能打开，
    // FILE_DEVICE_SECURE_OPEN 让这套 DACL 同样覆盖以设备名为前缀的相对打开路径。
    //  IoCreateDeviceSecure rather than IoCreateDevice. The former call carried no
    //  explicit DACL, so the device inherited a default security descriptor that
    //  lets ordinary users open it — meaning any unprivileged process could
    //  CreateFile("\\\\.\\AnXinProcProtect") and issue IOCTLs, including
    //  IOCTL_ANXIN_CLEAR_PIDS. The entire process self-protection could be
    //  switched off with a single unprivileged IOCTL. Access is now restricted to
    //  SYSTEM and Administrators, and FILE_DEVICE_SECURE_OPEN extends that DACL to
    //  relative opens beneath the device name.
    RtlInitUnicodeString(&g_DeviceName, DEVICE_NAME);
    RtlInitUnicodeString(&sddlString, DEVICE_SDDL);
    status = IoCreateDeviceSecure(DriverObject, 0, &g_DeviceName,
                                  FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE,
                                  &sddlString, NULL, &g_DeviceObject);
    if (!NT_SUCCESS(status)) {
        DbgPrintf("[AnXin] IoCreateDeviceSecure failed: 0x%08lX\n", status);
        return status;
    }

    RtlInitUnicodeString(&g_SymLinkName, SYMBOLIC_LINK_NAME);
    status = IoCreateSymbolicLink(&g_SymLinkName, &g_DeviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrintf("[AnXin] IoCreateSymbolicLink failed: 0x%08lX\n", status);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return status;
    }

    g_DeviceObject->Flags |= DO_BUFFERED_IO;

    // -----------------------------------------------------------------------
    // 1. Register process notification callback
    // -----------------------------------------------------------------------
    status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrintf("[AnXin] PsSetCreateProcessNotifyRoutineEx failed: 0x%08lX\n", status);
        goto CleanupDevices;
    }
    g_ProcessNotifyReg = (PVOID)ProcessNotifyCallback;

    // -----------------------------------------------------------------------
    // 2. Register thread notification callback
    // -----------------------------------------------------------------------
    status = PsSetCreateThreadNotifyRoutine(ThreadNotifyCallback);
    if (!NT_SUCCESS(status)) {
        DbgPrintf("[AnXin] PsSetCreateThreadNotifyRoutine failed: 0x%08lX\n", status);
        // Non-fatal: thread callback is auxiliary
    } else {
        g_ThreadNotifyReg = (PVOID)ThreadNotifyCallback;
    }

    // -----------------------------------------------------------------------
    // 2b. Register image load notification callback (VUL-019)
    // -----------------------------------------------------------------------
    status = PsSetLoadImageNotifyRoutine(LoadImageNotifyCallback);
    if (!NT_SUCCESS(status)) {
        DbgPrintf("[AnXin] PsSetLoadImageNotifyRoutine failed: 0x%08lX\n", status);
        // Non-fatal: image load monitoring is an enhancement
    } else {
        g_LoadImageNotifyReg = (PVOID)LoadImageNotifyCallback;
        DbgPrintf("[AnXin] Image load notify callback registered (VUL-019)\n");
    }

    // -----------------------------------------------------------------------
    // 3. Register ObCallback for process handle protection
    // -----------------------------------------------------------------------
    {
        OB_OPERATION_REGISTRATION opReg;
        OB_CALLBACK_REGISTRATION cbReg;
        RtlZeroMemory(&opReg, sizeof(opReg));
        RtlZeroMemory(&cbReg, sizeof(cbReg));

        opReg.ObjectType = PsProcessType;
        opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
        opReg.PreOperation = ObPreProcessHandleCreate;
        opReg.PostOperation = ObPostProcessHandleCreate;

        cbReg.Version = OB_FLT_REGISTRATION_VERSION;
        cbReg.OperationRegistrationCount = 1;
        RtlInitUnicodeString(&cbReg.Altitude, L"325800");
        cbReg.RegistrationContext = NULL;
        cbReg.OperationRegistration = &opReg;

        status = ObRegisterCallbacks(&cbReg, &g_ObProcessRegistration);
        if (!NT_SUCCESS(status)) {
            DbgPrintf("[AnXin] ObRegisterCallbacks(Process) failed: 0x%08lX\n", status);
            goto CleanupProcessNotify;
        }
    }

    // -----------------------------------------------------------------------
    // 4. Register ObCallback for thread handle protection
    // -----------------------------------------------------------------------
    {
        OB_OPERATION_REGISTRATION opReg;
        OB_CALLBACK_REGISTRATION cbReg;
        RtlZeroMemory(&opReg, sizeof(opReg));
        RtlZeroMemory(&cbReg, sizeof(cbReg));

        opReg.ObjectType = PsThreadType;
        opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
        opReg.PreOperation = ObPreThreadHandleCreate;
        opReg.PostOperation = ObPostThreadHandleCreate;

        cbReg.Version = OB_FLT_REGISTRATION_VERSION;
        cbReg.OperationRegistrationCount = 1;
        RtlInitUnicodeString(&cbReg.Altitude, L"325801");  // Same altitude as WinSta
        cbReg.RegistrationContext = NULL;
        cbReg.OperationRegistration = &opReg;

        status = ObRegisterCallbacks(&cbReg, &g_ObThreadRegistration);
        if (!NT_SUCCESS(status)) {
            DbgPrintf("[AnXin] ObRegisterCallbacks(Thread) failed: 0x%08lX\n", status);
            // Non-fatal: thread protection is an enhancement
        } else {
            DbgPrintf("[AnXin] Thread ObCallback registered\n");
        }
    }

    // -----------------------------------------------------------------------
    // 5. Register ObCallback for WindowStation handle protection
    //    默认禁用：ExWindowStationObjectType 在非标准导出，在部分内核版本上
    //    会导致 ObRegisterCallbacks 在 DISPATCH_LEVEL 下解引用无效指针 (BSOD 0x0A)。
    //    如需启用，定义 ANXIN_ENABLE_WINSTA_OBCALLBACK 并在目标内核上验证。
    //    Disabled by default: ExWindowStationObjectType is a non-standard export
    //    that causes ObRegisterCallbacks to dereference an invalid pointer at
    //    DISPATCH_LEVEL on some kernel versions (BSOD 0x0A). Define
    //    ANXIN_ENABLE_WINSTA_OBCALLBACK to re-enable after verifying the target kernel.
    // -----------------------------------------------------------------------
#ifdef ANXIN_ENABLE_WINSTA_OBCALLBACK
    if (ExWindowStationObjectType != NULL && *ExWindowStationObjectType != NULL) {
        OB_OPERATION_REGISTRATION opReg;
        OB_CALLBACK_REGISTRATION cbReg;
        RtlZeroMemory(&opReg, sizeof(opReg));
        RtlZeroMemory(&cbReg, sizeof(cbReg));

        g_WinstaObjType = *ExWindowStationObjectType;

        opReg.ObjectType = ExWindowStationObjectType;
        opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
        opReg.PreOperation = ObPreWindowStationCreate;
        opReg.PostOperation = ObPostWindowStationCreate;

        cbReg.Version = OB_FLT_REGISTRATION_VERSION;
        cbReg.OperationRegistrationCount = 1;
        RtlInitUnicodeString(&cbReg.Altitude, L"325801");
        cbReg.RegistrationContext = NULL;
        cbReg.OperationRegistration = &opReg;

        status = ObRegisterCallbacks(&cbReg, &g_ObWinstaRegistration);
        if (!NT_SUCCESS(status)) {
            DbgPrintf("[AnXin] ObRegisterCallbacks(WinSta) failed: 0x%08lX (non-fatal)\n", status);
        } else {
            DbgPrintf("[AnXin] WindowStation ObCallback registered\n");
        }
    } else {
        DbgPrintf("[AnXin] ExWindowStationObjectType is NULL, skipping WinSta ObCallback\n");
    }
#else
    DbgPrintf("[AnXin] WinSta ObCallback disabled (ANXIN_ENABLE_WINSTA_OBCALLBACK not defined)\n");
#endif

    // -----------------------------------------------------------------------
    // 6. Desktop ObCallback is NOT registered separately; Desktop handles
    //    are typically opened after their parent WinSta is opened, and the
    //    caller authorization check (IsCallerAuthorizedForWinsta) is applied
    //    via the WinSta callback. Adding a separate Desktop callback would
    //    double-fire on every Desktop handle open with minimal gain.
    //    If needed in the future, add it following the same pattern as WinSta.
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // 7. Boot reinit 回调。注册表自保（CmCallback + 服务键 DACL）已移交
    //    AnXinFileProtect.sys，本驱动不再在 boot reinit 阶段做注册表保护。
    //    保留 BootReinitCallback 作为启动后期初始化的占位入口。
    //    Registry self-protection (CmCallback + service key DACL) has moved to
    //    AnXinFileProtect.sys. BootReinitCallback is retained as a placeholder
    //    for any future boot-time initialization.
    // -----------------------------------------------------------------------
    IoRegisterBootDriverReinitialization(DriverObject, BootReinitCallback, NULL);

    DbgPrintf("[AnXin] Driver loaded successfully (boot-start).\n");
    return STATUS_SUCCESS;

    // --- Error cleanup paths ---
CleanupProcessNotify:
    if (g_LoadImageNotifyReg != NULL) {
        PsRemoveLoadImageNotifyRoutine(LoadImageNotifyCallback);
        g_LoadImageNotifyReg = NULL;
    }
    PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, TRUE);
    g_ProcessNotifyReg = NULL;

CleanupDevices:
    if (g_SymLinkName.Buffer != NULL) {
        IoDeleteSymbolicLink(&g_SymLinkName);
        RtlZeroMemory(&g_SymLinkName, sizeof(g_SymLinkName));
    }
    if (g_DeviceObject != NULL) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }
    return status;
}

// ===========================================================================
// Driver unload
// ===========================================================================

void DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    DbgPrintf("[AnXin] DriverUnload: unloading driver...\n");

    // Unregister WinSta ObCallback
    if (g_ObWinstaRegistration != NULL) {
        ObUnRegisterCallbacks(g_ObWinstaRegistration);
        g_ObWinstaRegistration = NULL;
    }

    // Unregister thread ObCallback
    if (g_ObThreadRegistration != NULL) {
        ObUnRegisterCallbacks(g_ObThreadRegistration);
        g_ObThreadRegistration = NULL;
    }

    // Unregister process ObCallback
    if (g_ObProcessRegistration != NULL) {
        ObUnRegisterCallbacks(g_ObProcessRegistration);
        g_ObProcessRegistration = NULL;
    }

    // Unregister thread notify
    if (g_ThreadNotifyReg != NULL) {
        PsRemoveCreateThreadNotifyRoutine(ThreadNotifyCallback);
        g_ThreadNotifyReg = NULL;
    }

    // Unregister image load notify (VUL-019)
    if (g_LoadImageNotifyReg != NULL) {
        PsRemoveLoadImageNotifyRoutine(LoadImageNotifyCallback);
        g_LoadImageNotifyReg = NULL;
    }

    // Unregister process notify
    if (g_ProcessNotifyReg != NULL) {
        PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, TRUE);
        g_ProcessNotifyReg = NULL;
    }

    // Release all referenced WinSta objects
    ClearProtectedWinstas();

    // Clear PID list
    ClearProtectedPids();

    // Remove devices
    if (g_SymLinkName.Buffer != NULL) {
        IoDeleteSymbolicLink(&g_SymLinkName);
        RtlZeroMemory(&g_SymLinkName, sizeof(g_SymLinkName));
    }
    if (g_DeviceObject != NULL) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }

    DbgPrintf("[AnXin] Driver unloaded successfully.\n");
}
