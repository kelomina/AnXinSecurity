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

// Thread access rights (values match winnt.h)
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
/*
 * VUL-103：补上 THREAD_QUERY_INFORMATION(0x0040)。此前本驱动把它误定义为
 * THREAD_SET_THREAD_TOKEN(0x0040)——真正值是 0x0080，见下——导致掩码在剥权时
 * 把 QUERY_INFORMATION 当 SET_THREAD_TOKEN 剥，却不剥真正的 SET_THREAD_TOKEN。
 * 修正后 0x0040=QUERY_INFORMATION、0x0080=SET_THREAD_TOKEN 均被剥离，只有
 * THREAD_QUERY_LIMITED_INFORMATION 兜底可保留（信息泄露面关闭）。
 */
#ifndef THREAD_QUERY_INFORMATION
#define THREAD_QUERY_INFORMATION           (0x0040)
#endif
#ifndef THREAD_SET_THREAD_TOKEN
#define THREAD_SET_THREAD_TOKEN            (0x0080)
#endif
#ifndef THREAD_IMPERSONATE
#define THREAD_IMPERSONATE                 (0x0100)
#endif
#ifndef THREAD_DIRECT_IMPERSONATION
#define THREAD_DIRECT_IMPERSONATION        (0x0200)
#endif
#ifndef THREAD_SET_LIMITED_INFORMATION
#define THREAD_SET_LIMITED_INFORMATION     (0x0400)
#endif
#ifndef THREAD_QUERY_LIMITED_INFORMATION
#define THREAD_QUERY_LIMITED_INFORMATION   (0x0800)
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
/*
 * 三进程拆分（2026-08，见 docs/three-process-split.md）后的产品家族镜像名。
 * 名称匹配的语义边界（VUL-100 原则不变）：
 *  - 仅用于「自动保护的快速纳入」与 IsAnxinProcess 的 Stage 1 预筛；
 *  - 绝不单独授予信任/授权——Trusted 身份仍只能由 Stage 2 完整路径 +
 *    TRUSTED_INSTALL_DIR 校验（ADD_PID IOCTL 路径）授予。
 * Family image names after the three-process split (2026-08). Matching is used
 * ONLY for auto-protection admission and the IsAnxinProcess stage-1 prefilter;
 * it never grants trust by itself — Trusted still requires the stage-2 full
 * path + trusted-install-dir verification via the ADD_PID path.
 */
static const CHAR * const ANXIN_FAMILY_ANSI[] = {
    "anxin-security.exe",
    "anxinsecurity.exe",
    "anxinservice.exe",
    "anxintray.exe",
};
static const WCHAR * const ANXIN_FAMILY_WIDE[] = {
    L"anxin-security.exe",
    L"anxinsecurity.exe",
    L"anxinservice.exe",
    L"anxintray.exe",
};
#define MAX_PROTECTED_PIDS      64
#define MAX_PROTECTED_WINSTA    8
/*
 * Deferred auto-protect. A newly created process whose name matches (or whose
 * parent is protected) is NOT added to g_ProtectedPids immediately. It is queued
 * and promoted after PROMOTION_DELAY_MS by a periodic DPC. Rationale:
 *
 *  - Boot BSOD 0x139 root cause: adding the PID during ProcessNotify means the
 *    ObCallbacks (registered below the process-creation critical path) strip
 *    the access on handles that trusted system components (services.exe, csrss,
 *    smss, wininit) open against the still-initializing process. Stripping those
 *    creation handles corrupts the duplicate/insert path (LIST_ENTRY corruption),
 *    so full-protection builds (DiagFlags=0) BSOD ~5s after boot exactly when the
 *    auto-start service is created.
 *  - Deferring promotion until after creation/initialization completes means the
 *    creation handles are opened while the PID is still unprotected, so nothing
 *    gets stripped. By the time any attacker can act, the process is protected.
 *    The ~2s window at boot is safe because no untrusted code runs that early;
 *    the service additionally self-registers its own PID + UI PIDs via IOCTL.
 */
#define MAX_PENDING_PROTECT_PIDS 64
#define PROMOTION_DELAY_MS       2000
#define PROMOTION_PERIOD_MS      1000

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
#define IOCTL_ANXIN_SET_DIAG     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80A, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_ANXIN_QUERY_TRACE  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80B, METHOD_BUFFERED, FILE_READ_DATA)

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
// impersonation, security descriptor manipulation, and info disclosure)
// THREAD_TERMINATE            - TerminateThread
// THREAD_SUSPEND_RESUME       - SuspendThread / ResumeThread
// THREAD_SET_CONTEXT          - SetThreadContext (hijack execution)
// THREAD_SET_INFORMATION      - NtSetInformationThread
// THREAD_GET_CONTEXT          - GetThreadContext (read register state)
// THREAD_QUERY_INFORMATION    - NtQueryInformationThread (info leak; VUL-103)
// THREAD_SET_THREAD_TOKEN     - replace thread token (privilege escalation)
// THREAD_IMPERSONATE          - impersonate
// THREAD_DIRECT_IMPERSONATION - direct impersonation
#define PROTECTED_THREAD_ACCESS_MASK  (THREAD_TERMINATE           | \
                                       THREAD_SUSPEND_RESUME      | \
                                       THREAD_SET_CONTEXT         | \
                                       THREAD_SET_INFORMATION     | \
                                       THREAD_GET_CONTEXT         | \
                                       THREAD_QUERY_INFORMATION   | \
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

/*
 * VUL-100 修复：受保护 PID 条目携带 Trusted 标志。
 *  - Trusted=TRUE  ：完整路径已验证为本产品核心进程（安装目录下的
 *                    anxin-security.exe，ADD_PID 时在全路径校验通过后置位）。
 *  - Trusted=FALSE ：仅受保护（自动保护链上的 webview 子进程、或按名前缀
 *                    伪装的进程）。是否可代表"族系"由 IsCallerFamilyTry
 *                    的辅助进程名判定；仅凭受保护身份不再授权（VUL-100）。
 *
 * VUL-100 fix: each protected PID entry carries a Trusted flag.
 *  - Trusted=TRUE  : full path verified as a core product process
 *                    (anxin-security.exe under the install dir; set by ADD_PID
 *                    after the blocking full-path check).
 *  - Trusted=FALSE : protected only (webview children on the auto-protect chain,
 *                    or name-spoofed processes). Family membership is decided by
 *                    IsCallerFamilyTry; protected status alone no longer
 *                    authorizes (VUL-100).
 */
typedef struct _PROTECTED_PID_ENTRY {
    HANDLE  Pid;
    BOOLEAN Trusted;
} PROTECTED_PID_ENTRY;

typedef struct _PROTECTED_PID_LIST {
    ULONG  Count;
    PROTECTED_PID_ENTRY Entries[MAX_PROTECTED_PIDS];
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

/*
 * Deferred auto-protect state. PIDs queued by ProcessNotifyCallback on process
 * creation are promoted to g_ProtectedPids by g_PromoteDpc once they are older
 * than PROMOTION_DELAY_MS. See MAX_PENDING_PROTECT_PIDS comment for rationale.
 */
typedef struct _PENDING_PROTECT_PID {
    HANDLE       Pid;
    LARGE_INTEGER AddedTime;    /* 100ns units, KeQuerySystemTime */
} PENDING_PROTECT_PID;

static PENDING_PROTECT_PID     g_PendingProtect[MAX_PENDING_PROTECT_PIDS] = {0};
static ULONG                   g_PendingProtectCount = 0;
static KSPIN_LOCK              g_PendingLock          = {0};
static KTIMER                  g_PromoteTimer;
static KDPC                    g_PromoteDpc;

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

/*
 * 调试输出宏。Release 构建（未定义 DBG）为空实现，因此不产生任何 DbgPrint 开销。
 * Debug output macro. Empty in Release builds (DBG undefined) so no DbgPrint cost.
 */
#ifdef DBG
#define DbgPrintf(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, __VA_ARGS__)
#else
#define DbgPrintf(...)
#endif

static IMAGE_LOAD_EVENT        g_ImageEventRing[IMAGE_EVENT_RING_SIZE] = {0};
static ULONG                   g_ImageEventHead  = 0;   /* next write slot */
static ULONG                   g_ImageEventCount = 0;   /* total events (may exceed ring size) */
static KSPIN_LOCK              g_ImageEventLock  = {0};
static PVOID                   g_LoadImageNotifyReg = NULL;

/*
 * 诊断开关（注册表控制，仅供故障排查）。从服务的 Parameters\DiagFlags 读取，
 * 每个位禁用一条进程创建关键路径上的功能。默认全 0（所有功能开启）。
 * 由于本驱动是 boot-start 且不可热卸载，改位后需重启生效。
 *
 * Diagnostic feature switches (registry-controlled, for troubleshooting only).
 * Read from the service's Parameters\DiagFlags; each bit disables one feature
 * on the process-creation critical path. Default 0 = all features enabled.
 * Because this driver is boot-start and cannot be unloaded live, changing a
 * bit requires a reboot to take effect.
 */
#define DIAG_DISABLE_AUTOPROTECT   0x00000001   /* ProcessNotify: skip auto-protect add */
#define DIAG_DISABLE_LOADIMAGE     0x00000002   /* LoadImage: skip trust check + ring write */
#define DIAG_DISABLE_OBPROCESS     0x00000004   /* ObProcess: do not strip handle access */
#define DIAG_DISABLE_OBTHREAD      0x00000008   /* ObThread:  do not strip handle access */
static ULONG g_DiagFlags = 0;

/*
 * 故障排查跟踪缓冲。回调在关键路径上（DISPATCH_LEVEL 以内），不能写文件，
 * 只把短标记追加进这个内存缓冲；测试脚本在复现挂起后通过
 * IOCTL_ANXIN_QUERY_TRACE 读取，精确定位挂起发生在哪个回调的哪一步。
 * 追加式写入，不做加锁（诊断用，允许极端并发下少量标记交错）。
 *
 * Troubleshooting trace buffer. Callbacks run on critical paths (up to
 * DISPATCH_LEVEL) and cannot write files; they only append short markers to
 * this memory buffer. After reproducing a hang, the test script reads it via
 * IOCTL_ANXIN_QUERY_TRACE to pinpoint which callback/step stalled.
 * Append-only, no locking (acceptable for diagnostics; rare interleaving ok).
 */
static char      g_Trace[16384];
static volatile ULONG g_TracePos = 0;

static void Trace(const char* s)
{
    ULONG pos = (ULONG)g_TracePos;
    ULONG i = 0;

    /*
     * 缓冲已满就直接放弃本条，绝不让结尾的 '\n' 与 '\0' 写出界。
     * 原始实现没有这道防线：g_TracePos 到达 16383（缓冲写满）后，下一次调用仍会
     * 执行 g_Trace[pos++] = '\n'; g_Trace[pos] = '\0'; —— 后者写入 index 16384，
     * 越过 16384 字节数组末尾。编译器 /sdl 越界检查在此触发
     * __report_rangecheckfailure -> __fastfail(FAST_FAIL_RANGE_CHECK_FAILURE)，
     * 表现为 0x139 蓝屏（实测 2026-08-12：安装后约 90 秒回调密集期，RuntimeBroker
     * 上下文中崩溃；寄存器 rdx=0x4000=16384 正是越界下标）。
     * 诊断追踪是 best-effort 遥测，写满后丢弃是安全的。
     *
     * When the buffer is full, drop the entry instead of letting the trailing
     * '\n'/' \0' writes run past the end. The original code reached index 16384
     * (one past a 16384-byte array) once g_TracePos hit 16383, tripping the /sdl
     * range check (__report_rangecheckfailure) and BSOD 0x139. Diagnostics are
     * best-effort telemetry, so dropping when full is acceptable.
     */
    if (pos >= sizeof(g_Trace) - 2)
        return;

    while (s[i] != '\0' && pos < sizeof(g_Trace) - 2) {
        g_Trace[pos++] = s[i++];
    }
    g_Trace[pos++] = '\n';
    g_Trace[pos] = '\0';
    g_TracePos = pos;
}

/*
 * 从 HKLM\SOFTWARE\AnXinSecurity\DiagFlags 读取诊断位（诊断专用路径，测试账号
 * 可写；服务注册表键有 DACL 自保，不可用于调试）。DriverEntry 在 PASSIVE_LEVEL
 * 调用，Zw* 同步 I/O 安全。值不存在 = 全部功能开启。
 * Reads the diagnostic bits from HKLM\SOFTWARE\AnXinSecurity\DiagFlags (a diag-only
 * path the test account can write; the service registry key is DACL-protected and
 * unusable for debugging). DriverEntry runs at PASSIVE_LEVEL so Zw* synchronous I/O
 * is safe. Missing value = all features enabled.
 */
static void ReadDiagFlags(void)
{
    g_DiagFlags = 0;

    UNICODE_STRING subKey;
    RtlInitUnicodeString(&subKey, L"\\Registry\\Machine\\SOFTWARE\\AnXinSecurity\\DiagFlags");

    HANDLE hKey = NULL;
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &subKey, OBJ_KERNEL_HANDLE, NULL, NULL);
    NTSTATUS status = ZwOpenKey(&hKey, KEY_QUERY_VALUE, &oa);
    if (!NT_SUCCESS(status))
        return;   /* no diag value -> all features enabled */

    UNICODE_STRING valueName = RTL_CONSTANT_STRING(L"DiagFlags");
    ULONG value = 0;
    ULONG size = sizeof(value);
    status = ZwQueryValueKey(hKey, &valueName, KeyValuePartialInformation,
                             NULL, 0, &size);
    if (status == STATUS_BUFFER_TOO_SMALL && size >= sizeof(KEY_VALUE_PARTIAL_INFORMATION)) {
        PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'gaiD');
        if (info != NULL) {
            status = ZwQueryValueKey(hKey, &valueName, KeyValuePartialInformation,
                                     info, size, &size);
            if (NT_SUCCESS(status) && info->DataLength >= sizeof(ULONG))
                RtlCopyMemory(&value, info->Data, sizeof(ULONG));
            ExFreePoolWithTag(info, 'gaiD');
        }
    }
    ZwClose(hKey);

    g_DiagFlags = value;
    DbgPrintf("[AnXin] DiagFlags = 0x%08lX\n", g_DiagFlags);
}

// ---------------------------------------------------------------------------
// Forward declarations
// ---------------------------------------------------------------------------

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD     DriverUnload;
DRIVER_DISPATCH   DriverCreateClose;
DRIVER_DISPATCH   DriverDeviceControl;

// Process
NTSTATUS     ProcessNotifyCallback(_Inout_ PEPROCESS Process, _In_ HANDLE ProcessId, _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);
void       ThreadNotifyCallback(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId, _In_ BOOLEAN Create);

/* Family-name matcher (three-process split); definition below IsCallerFamilyTry. */
static BOOLEAN AnxinNamePrefixMatch(PCHAR ansiName);
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
BOOLEAN    IsProtectedPidTry(HANDLE Pid);
BOOLEAN    IsProtectedPidTrustedTry(HANDLE Pid);
BOOLEAN    IsAnxinProcess(HANDLE Pid);
NTSTATUS   AddProtectedPid(HANDLE Pid, BOOLEAN Trusted);
NTSTATUS   AddProtectedPidTry(HANDLE Pid, BOOLEAN Trusted);
NTSTATUS   RemoveProtectedPid(HANDLE Pid);
NTSTATUS   RemoveProtectedPidTry(HANDLE Pid);
void       ClearProtectedPids(void);

// Deferred auto-protect
NTSTATUS   AddPendingProtectPidTry(HANDLE Pid);
NTSTATUS   RemovePendingProtectPidTry(HANDLE Pid);
BOOLEAN    IsPendingProtectPidTry(HANDLE Pid);
void       PromotePendingPidsDpc(_In_ struct _KDPC *Dpc, _In_opt_ PVOID Context, _In_opt_ PVOID Arg1, _In_opt_ PVOID Arg2);

// WinSta helpers
BOOLEAN    IsProtectedWinsta(PVOID Object);
NTSTATUS   AddProtectedWinsta(HANDLE WinStaHandle);
NTSTATUS   RemoveProtectedWinsta(PVOID Object);
void       ClearProtectedWinstas(void);
BOOLEAN    IsCallerAuthorizedForWinsta(void);

/*
 * VUL-099/VUL-100：IOCTL 分发上下文（PASSIVE_LEVEL）的授权校验，可阻塞。
 * 与 IsCallerAuthorizedForWinsta（ObCallback 非阻塞变体）分开。
 * Blocking authorization check for IOCTL dispatch context (PASSIVE_LEVEL).
 * Distinct from the non-blocking IsCallerAuthorizedForWinsta (ObCallbacks).
 */
BOOLEAN    IsCallerAuthorizedForIoControl(void);

/*
 * 可信安装目录校验（VUL-046 重构 / VUL-097 根因修复）。
 * 定义在本文件后部，但 IsAnxinProcess 与 DriverEntry 会先调用，故前向声明。
 */
static USHORT  AnxinCountSeparators(_In_ PCWSTR buf, _In_ USHORT len);
static BOOLEAN AnxinIsValidVolumeRoot(_In_ PCWSTR buf, _In_ USHORT len);
static BOOLEAN AnxinIsInTrustedInstallDir(_In_ PUNICODE_STRING fullPath, _In_ USHORT tailChars);
static BOOLEAN AnxinPathInTrustedDir(_In_ PUNICODE_STRING fullPath);
static VOID    AnxinLoadTrustedInstallDir(VOID);

/*
 * 非阻塞自旋锁获取/释放（WDK 10.0.28000 已移除旧的 KeTryToAcquireSpinLock，
 * 只保留 KeTryToAcquireSpinLockAtDpcLevel——它要求调用者已处于 DISPATCH_LEVEL）。
 * 这里手动恢复旧语义：IRQL 低于 DISPATCH 时先提升，再尝试获取；失败则恢复 IRQL。
 * 成功时锁在 DISPATCH_LEVEL 持有，释放用 KeReleaseSpinLockFromDpcLevel 并恢复 IRQL。
 * 供进程/线程/映像通知回调使用——这些回调运行在关键路径上，绝不能被锁争用阻塞。
 *
 * Non-blocking spinlock acquire/release. WDK 10.0.28000 removed the plain
 * KeTryToAcquireSpinLock, leaving only KeTryToAcquireSpinLockAtDpcLevel (which
 * requires the caller to already be at DISPATCH_LEVEL). These helpers restore
 * the old semantics: raise to DISPATCH if below, then try-acquire; on failure
 * restore the IRQL. On success the lock is held at DISPATCH_LEVEL and released
 * with KeReleaseSpinLockFromDpcLevel before restoring the saved IRQL. Used by
 * the process/thread/image notify callbacks, which run on critical paths and
 * must never block on lock contention.
 */
static BOOLEAN AnxinTryAcquireSpinLock(PKSPIN_LOCK SpinLock, PKIRQL OldIrql)
{
    *OldIrql = KeGetCurrentIrql();
    if (*OldIrql < DISPATCH_LEVEL) {
        KeRaiseIrql(DISPATCH_LEVEL, OldIrql);
    }
    if (KeTryToAcquireSpinLockAtDpcLevel(SpinLock)) {
        return TRUE;
    }
    KeLowerIrql(*OldIrql);
    return FALSE;
}

static VOID AnxinReleaseSpinLockAtDpc(PKSPIN_LOCK SpinLock, KIRQL OldIrql)
{
    KeReleaseSpinLockFromDpcLevel(SpinLock);
    KeLowerIrql(OldIrql);
}

// ===========================================================================
// PID list management
// ===========================================================================

BOOLEAN IsProtectedPid(HANDLE Pid)
{
    KIRQL oldIrql;
    BOOLEAN found = FALSE;
    KeAcquireSpinLock(&g_PidListLock, &oldIrql);
    for (ULONG i = 0; i < g_ProtectedPids.Count; i++) {
        if (g_ProtectedPids.Entries[i].Pid == Pid) { found = TRUE; break; }
    }
    KeReleaseSpinLock(&g_PidListLock, oldIrql);
    return found;
}

NTSTATUS AddProtectedPid(HANDLE Pid, BOOLEAN Trusted)
{
    if (Pid == NULL || Pid == (HANDLE)4) return STATUS_INVALID_PARAMETER;

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_PidListLock, &oldIrql);

    for (ULONG i = 0; i < g_ProtectedPids.Count; i++) {
        if (g_ProtectedPids.Entries[i].Pid == Pid) {
            /* Already registered. VUL-100: allow a late full-path confirmation
               to upgrade an auto-protected (untrusted) entry to trusted. */
            if (Trusted)
                g_ProtectedPids.Entries[i].Trusted = TRUE;
            KeReleaseSpinLock(&g_PidListLock, oldIrql);
            return STATUS_ALREADY_REGISTERED;
        }
    }
    if (g_ProtectedPids.Count >= MAX_PROTECTED_PIDS) {
        KeReleaseSpinLock(&g_PidListLock, oldIrql);
        return STATUS_BUFFER_TOO_SMALL;
    }
    g_ProtectedPids.Entries[g_ProtectedPids.Count].Pid     = Pid;
    g_ProtectedPids.Entries[g_ProtectedPids.Count].Trusted = Trusted;
    g_ProtectedPids.Count++;
    KeReleaseSpinLock(&g_PidListLock, oldIrql);

    DbgPrintf("[AnXin] PID %lu added to protected list (trusted=%d)\n", (ULONG)(ULONG_PTR)Pid, Trusted);
    return STATUS_SUCCESS;
}

/*
 * 非阻塞变体，供进程创建通知回调使用。
 *
 * 进程创建回调运行在 CreateProcessW 的关键路径上，绝不能自旋等待任何可能被
 * 其他线程持久的锁 —— 一旦 g_PidListLock 被占用（例如某个 IOCTL 处理线程正在
 * 临界区内，或锁状态异常），在回调里 KeAcquireSpinLock 会让整个系统的进程创建
 * 永久挂起，连驱动自己的服务进程都无法启动。这里用 KeTryToAcquireSpinLock，
 * 锁忙就跳过本次自动保护（best-effort，回调注释已声明）；进程创建因此永不阻塞。
 *
 * Non-blocking variants for the process-creation notify callback.
 *
 * The process-creation callback runs on CreateProcessW's critical path and must
 * never spin on a lock another thread might hold. If g_PidListLock is busy
 * (e.g. an IOCTL thread is inside a critical section), KeAcquireSpinLock here
 * would hang process creation system-wide — even the driver's own service could
 * not start. We use KeTryToAcquireSpinLock and skip the auto-protect on
 * contention (best-effort, as the callback's comment states); process creation
 * therefore never blocks.
 */
BOOLEAN IsProtectedPidTry(HANDLE Pid)
{
    KIRQL oldIrql;
    BOOLEAN found = FALSE;
    if (!AnxinTryAcquireSpinLock(&g_PidListLock, &oldIrql)) {
        return FALSE;  /* lock busy — treat as not protected, never block */
    }
    for (ULONG i = 0; i < g_ProtectedPids.Count; i++) {
        if (g_ProtectedPids.Entries[i].Pid == Pid) { found = TRUE; break; }
    }
    AnxinReleaseSpinLockAtDpc(&g_PidListLock, oldIrql);
    return found;
}

/*
 * 查询 PID 是否既受保护又是受信核心进程（完整路径已校验）。非阻塞，供
 * ObCallback / 授权判定使用。VUL-100：仅受保护（含按名自动保护的伪装进程）
 * 不再获得授权，授权要求 Trusted 或辅助进程族系身份。
 *
 * Non-blocking query: is the PID protected AND trusted (full-path verified)?
 * Used by authorization decisions. VUL-100: protected status alone (which a
 * name-spoofed process also attains via auto-protect) no longer authorizes.
 */
BOOLEAN IsProtectedPidTrustedTry(HANDLE Pid)
{
    KIRQL oldIrql;
    BOOLEAN trusted = FALSE;
    if (!AnxinTryAcquireSpinLock(&g_PidListLock, &oldIrql)) {
        return FALSE;  /* lock busy — treat as not trusted, never block */
    }
    for (ULONG i = 0; i < g_ProtectedPids.Count; i++) {
        if (g_ProtectedPids.Entries[i].Pid == Pid) {
            trusted = g_ProtectedPids.Entries[i].Trusted;
            break;
        }
    }
    AnxinReleaseSpinLockAtDpc(&g_PidListLock, oldIrql);
    return trusted;
}

NTSTATUS AddProtectedPidTry(HANDLE Pid, BOOLEAN Trusted)
{
    if (Pid == NULL || Pid == (HANDLE)4) return STATUS_INVALID_PARAMETER;

    KIRQL oldIrql;
    if (!AnxinTryAcquireSpinLock(&g_PidListLock, &oldIrql)) {
        Trace("AP:busy");
        return STATUS_UNSUCCESSFUL;  /* lock busy — skip, never block process creation */
    }
    Trace("AP:locked");

    for (ULONG i = 0; i < g_ProtectedPids.Count; i++) {
        if (g_ProtectedPids.Entries[i].Pid == Pid) {
            /* Already registered. VUL-100: upgrade to trusted if a full-path
               confirmation arrives after an earlier untrusted auto-protect. */
            if (Trusted)
                g_ProtectedPids.Entries[i].Trusted = TRUE;
            AnxinReleaseSpinLockAtDpc(&g_PidListLock, oldIrql);
            Trace("AP:dup");
            return STATUS_ALREADY_REGISTERED;
        }
    }
    if (g_ProtectedPids.Count >= MAX_PROTECTED_PIDS) {
        AnxinReleaseSpinLockAtDpc(&g_PidListLock, oldIrql);
        Trace("AP:full");
        return STATUS_BUFFER_TOO_SMALL;
    }
    g_ProtectedPids.Entries[g_ProtectedPids.Count].Pid     = Pid;
    g_ProtectedPids.Entries[g_ProtectedPids.Count].Trusted = Trusted;
    g_ProtectedPids.Count++;
    AnxinReleaseSpinLockAtDpc(&g_PidListLock, oldIrql);
    Trace("AP:added");

    DbgPrintf("[AnXin] PID %lu added to protected list (try, trusted=%d)\n", (ULONG)(ULONG_PTR)Pid, Trusted);
    return STATUS_SUCCESS;
}

NTSTATUS RemoveProtectedPid(HANDLE Pid)
{
    KIRQL oldIrql;
    NTSTATUS status = STATUS_NOT_FOUND;
    KeAcquireSpinLock(&g_PidListLock, &oldIrql);
    for (ULONG i = 0; i < g_ProtectedPids.Count; i++) {
        if (g_ProtectedPids.Entries[i].Pid == Pid) {
            for (ULONG j = i; j < g_ProtectedPids.Count - 1; j++)
                g_ProtectedPids.Entries[j] = g_ProtectedPids.Entries[j + 1];
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

/*
 * 非阻塞删除变体，供进程删除通知回调使用。锁忙则跳过——进程终止路径同样
 * 不能因锁争用而阻塞（与 AddProtectedPidTry 理由一致）。跳过的代价是受保护
 * 列表里留下一个已终止 PID 的残留项；下一个同号 PID 重用时会短暂受保护，
 * 但 ObCallback 的 IsCallerFamilyTry 兜底仍然保证非受信族系进程即使被误保护
 * 也无法攻击其他受保护进程（VUL-100：仅受保护身份不再授权），因此这个残留
 * 是可接受的。
 * Non-blocking removal variant for the process-deletion notify callback. On
 * lock contention the removal is skipped — the termination path must not block
 * either (same rationale as AddProtectedPidTry). The cost of skipping is a stale
 * PID left in the protected list; on PID reuse the new process is briefly
 * protected, but the ObCallback IsCallerFamilyTry backstop still ensures a
 * process outside the trusted family cannot attack other protected processes
 * (VUL-100: protected status alone no longer authorizes), so the stale entry
 * is acceptable.
 */
NTSTATUS RemoveProtectedPidTry(HANDLE Pid)
{
    KIRQL oldIrql;
    NTSTATUS status = STATUS_NOT_FOUND;
    if (!AnxinTryAcquireSpinLock(&g_PidListLock, &oldIrql)) {
        return STATUS_UNSUCCESSFUL;  /* lock busy — skip, never block process termination */
    }
    for (ULONG i = 0; i < g_ProtectedPids.Count; i++) {
        if (g_ProtectedPids.Entries[i].Pid == Pid) {
            for (ULONG j = i; j < g_ProtectedPids.Count - 1; j++)
                g_ProtectedPids.Entries[j] = g_ProtectedPids.Entries[j + 1];
            g_ProtectedPids.Count--;
            status = STATUS_SUCCESS;
            break;
        }
    }
    AnxinReleaseSpinLockAtDpc(&g_PidListLock, oldIrql);
    if (NT_SUCCESS(status))
        DbgPrintf("[AnXin] PID %lu removed from protected list (try)\n", (ULONG)(ULONG_PTR)Pid);
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
// Deferred auto-protect (pending promotion)
// ===========================================================================

/*
 * Queue a PID for deferred protection. Runs from ProcessNotifyCallback on the
 * process-creation critical path, so it must never block: the pending list uses
 * try-acquire and drops the queue on contention (same best-effort philosophy as
 * AddProtectedPidTry). The PID is promoted to the real protected list by
 * PromotePendingPidsDpc once it is older than PROMOTION_DELAY_MS, by which point
 * the process has finished creation/initialization and trusted system components
 * are no longer opening its creation handles.
 */
NTSTATUS AddPendingProtectPidTry(HANDLE Pid)
{
    if (Pid == NULL || Pid == (HANDLE)4) return STATUS_INVALID_PARAMETER;

    /* Already fully protected — nothing to defer. */
    if (IsProtectedPidTry(Pid))
        return STATUS_ALREADY_REGISTERED;

    KIRQL oldIrql;
    if (!AnxinTryAcquireSpinLock(&g_PendingLock, &oldIrql)) {
        Trace("PP:busy");
        return STATUS_UNSUCCESSFUL;   /* lock busy — skip, never block process creation */
    }
    Trace("PP:locked");

    for (ULONG i = 0; i < g_PendingProtectCount; i++) {
        if (g_PendingProtect[i].Pid == Pid) {
            AnxinReleaseSpinLockAtDpc(&g_PendingLock, oldIrql);
            Trace("PP:dup");
            return STATUS_ALREADY_REGISTERED;
        }
    }
    if (g_PendingProtectCount >= MAX_PENDING_PROTECT_PIDS) {
        /* Pending list full — promote immediately so protection is never lost.
         * Release the pending lock first to avoid nesting two spinlocks. */
        AnxinReleaseSpinLockAtDpc(&g_PendingLock, oldIrql);
        Trace("PP:full");
        return AddProtectedPidTry(Pid, FALSE);
    }

    g_PendingProtect[g_PendingProtectCount].Pid = Pid;
    KeQuerySystemTime(&g_PendingProtect[g_PendingProtectCount].AddedTime);
    g_PendingProtectCount++;
    AnxinReleaseSpinLockAtDpc(&g_PendingLock, oldIrql);
    Trace("PP:queued");

    DbgPrintf("[AnXin] PID %lu queued for deferred auto-protect\n", (ULONG)(ULONG_PTR)Pid);
    return STATUS_SUCCESS;
}

/*
 * Remove a PID from the pending list. Called from the process-delete notify path
 * so a process that exits before its grace period elapses does not leave a stale
 * pending entry that would later protect a reused PID.
 */
NTSTATUS RemovePendingProtectPidTry(HANDLE Pid)
{
    NTSTATUS status = STATUS_NOT_FOUND;
    KIRQL oldIrql;
    if (!AnxinTryAcquireSpinLock(&g_PendingLock, &oldIrql))
        return STATUS_UNSUCCESSFUL;   /* lock busy — skip, never block termination */

    for (ULONG i = 0; i < g_PendingProtectCount; i++) {
        if (g_PendingProtect[i].Pid == Pid) {
            for (ULONG j = i; j + 1 < g_PendingProtectCount; j++)
                g_PendingProtect[j] = g_PendingProtect[j + 1];
            g_PendingProtectCount--;
            status = STATUS_SUCCESS;
            break;
        }
    }
    AnxinReleaseSpinLockAtDpc(&g_PendingLock, oldIrql);
    return status;
}

/*
 * 非阻塞查询：PID 是否已在待提升（pending）队列中。VUL-096 修复——判断某进程
 * 是否"受保护进程的子进程"时，不仅要看已提升的受保护列表，还要看 pending 队列：
 * 否则父进程（如 webview browser，经自动保护 pending 后 2s 才提升）在提升窗口内
 * 产生的子进程（renderer/GPU）会被永久漏保护。
 *
 * Non-blocking query: is the PID in the pending-promotion queue? VUL-096 fix —
 * the "child of a protected process" test must consider the pending queue, not
 * just the fully-promoted list, or children spawned while the parent (e.g. the
 * webview browser process, pending for 2s before promotion) is still pending
 * would never be protected.
 */
BOOLEAN IsPendingProtectPidTry(HANDLE Pid)
{
    KIRQL oldIrql;
    BOOLEAN found = FALSE;
    if (!AnxinTryAcquireSpinLock(&g_PendingLock, &oldIrql)) {
        return FALSE;  /* lock busy — treat as not pending, never block */
    }
    for (ULONG i = 0; i < g_PendingProtectCount; i++) {
        if (g_PendingProtect[i].Pid == Pid) { found = TRUE; break; }
    }
    AnxinReleaseSpinLockAtDpc(&g_PendingLock, oldIrql);
    return found;
}

/*
 * Periodic DPC that promotes queued PIDs once their grace period has elapsed.
 * Runs at DISPATCH_LEVEL. Uses try-acquire on the pending lock (skip this tick
 * on contention) and AddProtectedPidTry (itself non-blocking) so nothing here
 * can stall the system. Promotion is deliberately blind — verifying the process
 * still exists would require PsLookupProcessByProcessId at PASSIVE_LEVEL. If a
 * queued PID exits before promotion and its PID is reused, the stale entry
 * briefly protects the reused process; the ObCallback IsCallerFamilyTry
 * backstop still prevents a process outside the trusted family from attacking
 * other protected processes (same accepted trade-off as the existing stale-PID
 * removal path). VUL-100: promotion here adds the PID as untrusted, so a
 * name-spoofed process gains protection but never authorization by itself.
 */
void PromotePendingPidsDpc(_In_ struct _KDPC *Dpc,
                           _In_opt_ PVOID Context,
                           _In_opt_ PVOID Arg1,
                           _In_opt_ PVOID Arg2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Arg1);
    UNREFERENCED_PARAMETER(Arg2);

    HANDLE toPromote[MAX_PENDING_PROTECT_PIDS];
    ULONG  toPromoteCount = 0;

    LARGE_INTEGER now;
    KeQuerySystemTime(&now);

    KIRQL oldIrql;
    if (!AnxinTryAcquireSpinLock(&g_PendingLock, &oldIrql)) {
        return;   /* try again next tick */
    }

    ULONG i = 0;
    while (i < g_PendingProtectCount) {
        LONGLONG elapsed = now.QuadPart - g_PendingProtect[i].AddedTime.QuadPart;
        if (elapsed >= (LONGLONG)(PROMOTION_DELAY_MS * 10000LL)) {
            if (toPromoteCount < MAX_PENDING_PROTECT_PIDS)
                toPromote[toPromoteCount++] = g_PendingProtect[i].Pid;
            /* Remove entry i (shift down). */
            for (ULONG j = i; j + 1 < g_PendingProtectCount; j++)
                g_PendingProtect[j] = g_PendingProtect[j + 1];
            g_PendingProtectCount--;
        } else {
            i++;
        }
    }
    AnxinReleaseSpinLockAtDpc(&g_PendingLock, oldIrql);

    for (ULONG k = 0; k < toPromoteCount; k++) {
        /* Auto-protect never marks a PID trusted (VUL-100): full-path trust is
           only established by ADD_PID's blocking verification. WebView2 children
           stay protected-but-untrusted and are covered by the family check. */
        NTSTATUS s = AddProtectedPidTry(toPromote[k], FALSE);
        Trace(NT_SUCCESS(s) ? "PP:promote-ok" : "PP:promote-fail");
        if (NT_SUCCESS(s))
            DbgPrintf("[AnXin] Deferred auto-protect promoted PID %lu\n",
                      (ULONG)(ULONG_PTR)toPromote[k]);
    }
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
    USHORT          tailChars = 0;

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
     * Stage-1 prefilter now uses the family table (four image names after the
     * three-process split). Semantics unchanged: fast reject only - trusted
     * authorization is still decided by the stage-2 full-path check.
     */
    if (!AnxinNamePrefixMatch(ansiName)) {
        ObDereferenceObject(processObj);
        return FALSE;
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

    /*
     * Must end with one of the family image names preceded by a path separator.
     * Authorization is still gated below by the trusted-install-dir check, so
     * extending the name set does not widen the trust boundary (VUL-038/046/097
     * semantics preserved).
     */
    for (ULONG f = 0; f < RTL_NUMBER_OF(ANXIN_FAMILY_WIDE); f++) {
        RtlInitUnicodeString(&targetName, (PWSTR)ANXIN_FAMILY_WIDE[f]);

        if (fullPath->Length > targetName.Length) {
            tailChars = (USHORT)((fullPath->Length - targetName.Length) / sizeof(WCHAR));
            WCHAR  separator = fullPath->Buffer[tailChars - 1];

            if (separator == L'\\' || separator == L'/') {
                tail.Buffer        = &fullPath->Buffer[tailChars];
                tail.Length        = targetName.Length;
                tail.MaximumLength = targetName.Length;
                result = (BOOLEAN)(RtlCompareUnicodeString(&tail, &targetName, TRUE) == 0);
                if (result) {
                    break;
                }
            }
        }
    }

    /*
     * VUL-038 / VUL-046 / VUL-097：文件名匹配后，还须验证路径落在可信安装
     * 目录内。
     *
     * 旧实现（VUL-046 修复）在路径中搜索 "\anxinsecurity\" 组件并要求匹配
     * 位置前一字符是分隔符。但 TRUSTED_INSTALL_DIR 本身以 '\' 开头，匹配
     * 起点已经在组件边界上，检查 Buffer[pos-1] 相当于检查分隔符之前那个
     * 字符——对 "...\Program Files\AnXinSecurity\..." 而言它是 's'（Files
     * 的末尾），永远不通过。因此所有合法 anxin-security.exe（含服务进程）
     * 都被拒绝。
     *
     * 新实现改为全路径相等（仅卷前缀可变）：
     *   完整路径必须 == <卷根> + <可信安装目录> + "\anxin-security.exe"
     *   可信安装目录从服务 ImagePath 注册表值得出（默认
     *   "\Program Files\AnXinSecurity"），<卷根> 必须是白名单中的卷根形态
     *   （\Device\... / \??\... / \Volume{...}）。
     * 攻击者即使在任意处创建 "anxinsecurity" 子目录（VUL-046），其完整路径
     * 在 <卷根> 之后会多出额外目录组件，无法与完整结构相等，被拒绝。
     */
    if (result) {
        result = AnxinIsInTrustedInstallDir(fullPath, tailChars);
        if (!result) {
            DbgPrintf("[AnXin] IsAnxinProcess: name matched but path not in trusted install dir\n");
        }
    }

    ExFreePool(fullPath);
    return result;
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
 * 映像路径是否位于可信安装目录内（LoadImage 分类用）：
 *   路径 == <合法卷根> + <可信目录> + '\' + 任意内容
 * 可信目录必须紧跟卷根（中间不得夹带攻击者可控的目录组件），其后是分隔符
 * 再接文件。卷根未知，遍历候选分界点——路径很短，代价可忽略；且只有卷根
 * 校验（0 内嵌分隔符）与目录精确相等同时成立才算命中。
 *
 * Is an image path inside the trusted install dir (LoadImage classification):
 * the trusted dir must immediately follow a valid volume root (no attacker
 * component in between); the scan is cheap because paths are short and both
 * the volume-root and directory equality must hold.
 */
static BOOLEAN AnxinPathInTrustedDir(_In_ PUNICODE_STRING fullPath)
{
    USHORT tdirLen = g_TrustedInstallDirLen;
    if (tdirLen == 0 || fullPath == NULL || fullPath->Buffer == NULL) return FALSE;

    USHORT pathLen = (USHORT)(fullPath->Length / sizeof(WCHAR));
    /* 结构：<卷根(>=2)><可信目录(>=1)><'\'><至少 1 字符> */
    if (pathLen < tdirLen + 4) return FALSE;

    USHORT maxVol = (USHORT)(pathLen - tdirLen - 1);
    for (USHORT volLen = 2; volLen <= maxVol; volLen++) {
        if (fullPath->Buffer[volLen + tdirLen] != L'\\') continue;

        UNICODE_STRING tail;
        tail.Buffer        = &fullPath->Buffer[volLen];
        tail.Length        = (USHORT)(tdirLen * sizeof(WCHAR));
        tail.MaximumLength = tail.Length;

        UNICODE_STRING tdir;
        tdir.Buffer        = g_TrustedInstallDir;
        tdir.Length        = (USHORT)(tdirLen * sizeof(WCHAR));
        tdir.MaximumLength = (USHORT)sizeof(g_TrustedInstallDir);

        if (RtlCompareUnicodeString(&tail, &tdir, TRUE) != 0) continue;
        if (AnxinIsValidVolumeRoot(fullPath->Buffer, volLen)) return TRUE;
    }
    return FALSE;
}

/*
 * DriverEntry 时读取服务 ImagePath，覆盖默认可信安装目录（支持自定义安装）。
 * 解析：去掉引号（引号内空格允许）→ 取 exe 路径 token → 去掉 exe 文件名 →
 * 去掉盘符根。失败时保持默认值（fail-closed：目录为空则不授权）。
 *
 * Reads the service ImagePath at DriverEntry to override the default trusted
 * install dir (custom install support). Keeps the default on failure.
 */
static VOID AnxinLoadTrustedInstallDir(VOID)
{
    UNICODE_STRING keyName;
    RtlInitUnicodeString(&keyName,
        L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\AnXinSecurityService");
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
        DbgPrintf("[AnXin] Trusted install dir from ImagePath: %wZ\n", &dirUs);
    }
}

/*
 * 名称前缀匹配辅助。EPROCESS.ImageFileName 是 15 字节 ANSI 且长名会被截断，
 * 因此这里比较前 ANSI_NAME_COMPARE_LEN 个字符，忽略大小写。
 * ！！仅作快速排除 / 自动保护筛选，绝不可作为授权依据（VUL-100）！！
 *
 * Shared name-prefix matcher. EPROCESS.ImageFileName is a truncated 15-byte ANSI
 * field, so only the first ANSI_NAME_COMPARE_LEN chars are compared,
 * case-insensitively. !! Fast-reject ONLY — must never authorize (VUL-100) !!
 */
static BOOLEAN AnxinNamePrefixMatch(PCHAR ansiName)
{
    if (ansiName == NULL)
        return FALSE;

    for (ULONG f = 0; f < RTL_NUMBER_OF(ANXIN_FAMILY_ANSI); f++) {
        const CHAR *expected = ANXIN_FAMILY_ANSI[f];
        ULONG expectedLen = 0;
        while (expected[expectedLen] != '\0' && expectedLen < ANSI_NAME_COMPARE_LEN)
            expectedLen++;

        BOOLEAN matched = TRUE;
        for (ULONG i = 0; i < expectedLen; i++) {
            CHAR actual   = ansiName[i];
            CHAR exp      = expected[i];
            if (actual == '\0') {          /* truncated 15-byte field ran out */
                matched = FALSE;
                break;
            }
            if (actual >= 'A' && actual <= 'Z')
                actual = (CHAR)(actual - 'A' + 'a');
            if (exp >= 'A' && exp <= 'Z')
                exp = (CHAR)(exp - 'A' + 'a');
            if (actual != exp) {
                matched = FALSE;
                break;
            }
        }
        if (matched)
            return TRUE;
    }
    return FALSE;
}

/*
 * 对任意 PID 做名称前缀匹配（PASSIVE_LEVEL 可用：ADD_PID 分发上下文）。
 * 仅快速排除，不能授权。
 * Name-prefix match for an arbitrary PID (safe at PASSIVE_LEVEL: ADD_PID
 * dispatch context). Fast-reject only, never authorization.
 */
static BOOLEAN AnxinNamePrefixMatchOfPid(HANDLE Pid)
{
    PEPROCESS processObj = NULL;
    BOOLEAN match = FALSE;

    if (!NT_SUCCESS(PsLookupProcessByProcessId(Pid, &processObj)))
        return FALSE;
    match = AnxinNamePrefixMatch(PsGetProcessImageFileName(processObj));
    ObDereferenceObject(processObj);
    return match;
}

/*
 * VUL-100 修复：ObCallback（非阻塞上下文）的族系授权判定。
 *
 * 仅凭"受保护"身份不再授权——按名自动保护会把任意目录下的伪装进程
 * anxin-security.exe 也加入受保护列表。授权必须额外要求：
 *   1. 受信核心进程（完整路径已由 ADD_PID 校验）；或
 *   2. 辅助进程（webview 子进程：受保护但名称不是 anxin-security.exe，
 *      因此是产品族系而非名称伪装）。
 * 名称伪装进程（受保护但名为 anxin-security.exe，未被完整路径确认）被拒绝。
 *
 * 非阻塞：只读当前进程名 + 受保护列表（try-acquire），无 I/O、无进程表查找，
 * 可安全用于 ObPreProcessHandleCreate / ObPreThreadHandleCreate 等句柄打开回调。
 *
 * VUL-100 fix: family authorization for non-blocking ObCallbacks.
 * Protected status alone no longer authorizes — auto-protect also admits a
 * spoofed "anxin-security.exe" from any directory. Authorization additionally
 * requires either (1) a trusted core process (full path confirmed by ADD_PID),
 * or (2) an auxiliary process (protected but NOT named anxin-security.exe, i.e.
 * a genuine webview child rather than a name spoof). A spoofed name-matching
 * process that is protected but untrusted is denied.
 * Non-blocking: only reads the current process name + the protected list
 * (try-acquire). No I/O, no process-table lookup — safe in handle-open callbacks.
 */
static BOOLEAN IsCallerFamilyTry(void)
{
    HANDLE callerPid = PsGetCurrentProcessId();
    if (callerPid == (HANDLE)4) return TRUE;            /* SYSTEM always allowed */
    if (!IsProtectedPidTry(callerPid)) return FALSE;    /* not in family at all */
    if (IsProtectedPidTrustedTry(callerPid)) return TRUE;

    /* Protected but untrusted: genuine auxiliary (webview child) or spoof. */
    if (AnxinNamePrefixMatch(PsGetProcessImageFileName(PsGetCurrentProcess())))
        return FALSE;   /* name-spoofed "anxin-security.exe" — deny (VUL-100) */
    return TRUE;        /* auxiliary process (e.g. msedgewebview2.exe) — allow */
}

/*
 * VUL-099/VUL-100 修复：IOCTL 分发上下文（PASSIVE_LEVEL）的阻塞式授权校验。
 * 允许：SYSTEM、受保护 PID（服务/UI 显式注册）、完整路径校验通过的本产品进程
 * （卸载器 anxin-security.exe --uninstall-drivers 等未注册 PID 的合法调用者）。
 * 拒绝：名称伪装进程（C:\Windows\Temp\anxin-security.exe 之类），因为其完整
 * 路径不包含 \anxinsecurity\ 组件。
 *
 * Blocking authorization for IOCTL dispatch (PASSIVE_LEVEL). Allows: SYSTEM,
 * any protected PID (service/UI explicitly registered), and any process whose
 * full path verifies as the product binary (e.g. the uninstaller's
 * --uninstall-drivers). Denies name-spoofed processes whose full path lacks the
 * \anxinsecurity\ component.
 */
BOOLEAN IsCallerAuthorizedForIoControl(void)
{
    HANDLE callerPid = PsGetCurrentProcessId();
    if (callerPid == (HANDLE)4) return TRUE;
    if (IsProtectedPidTry(callerPid)) return TRUE;
    if (IsAnxinProcess(callerPid)) return TRUE;   /* blocking full-path check */
    return FALSE;
}

// ===========================================================================
// Is the caller one of our protected processes? (non-blocking, ObCallbacks)
// ===========================================================================

/*
 * VUL-100 修复：WinSta/Desktop ObCallback 的授权改为族系判定（SYSTEM / 受信
 * 核心 / 辅助进程），不再用名称前缀直接授权。非阻塞，可安全用于句柄打开回调。
 * 该函数只保留给 ObPreWindowStationCreate / ObPreDesktopCreate 使用；IOCTL
 * 分发上下文改用阻塞版 IsCallerAuthorizedForIoControl。
 *
 * VUL-100 fix: WinSta/Desktop ObCallback authorization now uses the family
 * check (SYSTEM / trusted core / auxiliary process) instead of granting by
 * name prefix. Non-blocking — safe in handle-open callbacks. This function is
 * kept only for the WinSta/Desktop ObCallbacks; IOCTL dispatch uses the
 * blocking IsCallerAuthorizedForIoControl.
 */
BOOLEAN IsCallerAuthorizedForWinsta(void)
{
    return IsCallerFamilyTry();
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

/*
 * VUL-108 根因修复：本回调注册于 PsSetCreateProcessNotifyRoutineEx，
 * 该 API 要求 NTSTATUS 返回原型（PCREATE_PROCESS_NOTIFY_ROUTINE_EX）。
 * 旧实现为 void——内核从 RAX 读取"返回值"作为创建决策，读到的是本函数
 * 执行路径残留的寄存器垃圾；非零时 NtCreateUserProcess 以任意状态码失败
 * （实测表现为 0xC00000A1 → 用户态 0x80070542 BAD_IMPERSONATION_LEVEL）。
 * 受影响场景：家族名匹配的新进程创建（即服务拉起 Tray 的合法路径）。
 * 现改为显式 NTSTATUS 并在所有出口返回 STATUS_SUCCESS。
 *
 * VUL-108 root-cause fix: this callback is registered with
 * PsSetCreateProcessNotifyRoutineEx, which requires the NTSTATUS-returning
 * PCREATE_PROCESS_NOTIFY_ROUTINE_EX prototype. The old implementation was
 * void - the kernel read leftover RAX garbage as the creation verdict, and any
 * nonzero leftover failed NtCreateUserProcess with an arbitrary status
 * (observed as 0xC00000A1 -> user-mode 0x80070542 BAD_IMPERSONATION_LEVEL).
 * Affected path: creation of family-matched processes, i.e. exactly the
 * service->tray legitimate launch. Now explicitly returns STATUS_SUCCESS on
 * every exit.
 */
NTSTATUS ProcessNotifyCallback(_Inout_ PEPROCESS Process, _In_ HANDLE ProcessId, _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    if (CreateInfo != NULL) {
        Trace("PN:create");
        /*
         * 进程创建时自动保护。
         * 使用 Process 参数的 PsGetProcessImageFileName（EPROCESS 内嵌的 15 字节
         * ANSI 名，始终可用），而非 IsAnxinProcess 内的 SeLocateProcessImageName
         * （进程创建时可能因映像未完全初始化而失败）。
         *
         * 注意：此处的 ANSI 名检查不验证完整路径（VUL-038/VUL-046）。VUL-100
         * 修复后，自动保护只授予"受保护"身份、绝不授予"授权"身份——按名伪装的
         * 进程即使被自动保护也无法在 ObCallback 里通过族系校验。服务进程同时
         * 通过 IOCTL 显式注册 UI 进程 PID（完整路径校验）作为受信主路径。
         *
         * Auto-protect on process creation. Uses PsGetProcessImageFileName from
         * the EPROCESS (the embedded 15-byte ANSI name, always available) rather
         * than IsAnxinProcess's SeLocateProcessImageName (which may fail during
         * creation because the image path is not fully initialized).
         *
         * Note: this ANSI-only check does not verify the full path (VUL-038/VUL-046).
         * Since the VUL-100 fix, auto-protect grants only *protection* — never
         * *authorization*. A name-spoofed process that gets auto-protected still
         * fails the ObCallback IsCallerFamilyTry check and cannot open handles on
         * other protected processes. The service explicitly registers the UI PID
         * via IOCTL (full-path verified) as the primary trusted path.
         */
        PCHAR ansiName = PsGetProcessImageFileName(Process);
        if (ansiName != NULL) {
            BOOLEAN match = AnxinNamePrefixMatch(ansiName);
            BOOLEAN isChildOfProtected = FALSE;
            /*
             * VUL-096 修复：子进程判定要同时看已提升的受保护列表和 pending 队列。
             * webview browser 进程经自动保护 pending 后约 2s 才提升，若 renderer/
             * GPU 子进程恰在该窗口内创建，其父进程不在受保护列表中，导致这些子
             * 进程永远不被保护。纳入 pending 判定后，提升窗口内产生的子进程也会
             * 被排队保护。
             *
             * VUL-096 fix: the "child of a protected process" test must also cover
             * the pending queue. The webview browser process stays pending ~2s
             * before promotion; children spawned inside that window would otherwise
             * never be protected.
             */
            if (CreateInfo->ParentProcessId != NULL &&
                (IsProtectedPidTry(CreateInfo->ParentProcessId) ||
                 IsPendingProtectPidTry(CreateInfo->ParentProcessId))) {
                isChildOfProtected = TRUE;
            }

            if (match || isChildOfProtected) {
                Trace("PN:autoprotect");
                if (!(g_DiagFlags & DIAG_DISABLE_AUTOPROTECT)) {
                    /*
                     * Deferred: queue the PID and promote it only after creation
                     * completes (see MAX_PENDING_PROTECT_PIDS). This stops the
                     * ObCallbacks from stripping the creation handles opened by
                     * trusted system components, which is the boot BSOD 0x139
                     * root cause on full-protection builds (DiagFlags=0).
                     */
                    NTSTATUS s = AddPendingProtectPidTry(ProcessId);
                    Trace(s ? "PN:queue-ok" : "PN:queue-fail");
                    if (NT_SUCCESS(s))
                        DbgPrintf("[AnXin] Deferred auto-protect queued PID %lu (created, child=%d)\n", (ULONG)(ULONG_PTR)ProcessId, isChildOfProtected);
                }
            }
        }
    } else {
        // Process is being deleted
        RemovePendingProtectPidTry(ProcessId);   // in case it was queued but not yet promoted
        if (IsProtectedPidTry(ProcessId)) {
            RemoveProtectedPidTry(ProcessId);
            DbgPrintf("[AnXin] PID %lu removed from protection (terminated)\n", (ULONG)(ULONG_PTR)ProcessId);
        }
    }

    return STATUS_SUCCESS;
}

// ===========================================================================
// Thread notification callback (track UI threads of protected processes)
// ===========================================================================

void ThreadNotifyCallback(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create)
{
    UNREFERENCED_PARAMETER(ThreadId);

    Trace("TN");
    if (Create && IsProtectedPidTry(ProcessId)) {
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
 * 检查映像路径是否位于可信安装目录内。
 * VUL-046 / VUL-097：旧实现子串搜索 "\anxinsecurity\" 且要求前置分隔符——
 * 匹配起点与前置分隔符重叠，合法路径 "...\Program Files\AnXinSecurity\..."
 * 永远匹配不上；且子串搜索可被任意目录下的 "anxinsecurity" 子目录绕过。
 * 改为结构化校验：<合法卷根> + <可信安装目录> + '\' + 文件，可信目录必须
 * 紧跟卷根（中间不得夹带攻击者可控目录组件）。
 *
 * VUL-046/VUL-097: structural check — the trusted install dir must immediately
 * follow a validated volume root; no attacker-controlled component in between.
 */
static BOOLEAN IsTrustedImagePath(PCUNICODE_STRING ImagePath)
{
    UNICODE_STRING path;
    if (ImagePath == NULL || ImagePath->Buffer == NULL || ImagePath->Length == 0)
        return FALSE;
    path = *ImagePath;
    return AnxinPathInTrustedDir(&path);
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

    /* 只关注受保护进程（非阻塞——映像加载回调也绝不能因锁争用阻塞） */
    Trace("LI:enter");
    if (!IsProtectedPidTry(ProcessId)) {
        Trace("LI:notprot");
        return;
    }
    Trace("LI:prot");

    /* 系统映像（驱动等）跳过——驱动加载有独立的签名验证链路 */
    if (ImageInfo->SystemModeImage)
        return;

    /* 诊断：跳过信任检查与环形缓冲写入，隔离 LoadImage 路径是否阻塞创建 */
    if (g_DiagFlags & DIAG_DISABLE_LOADIMAGE) {
        Trace("LI:gated");
        return;
    }

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

    /*
     * 非阻塞获取自旋锁：如果锁忙，直接丢弃本条事件。映像加载回调运行在
     * 关键路径上，环形缓冲写入只是 best-effort 遥测，绝不值得为了写入
     * 而阻塞进程/线程创建或映像加载。
     * Non-blocking lock acquisition: if the lock is busy, drop this event.
     * The image-load callback runs on critical paths; the ring write is
     * best-effort telemetry and never worth blocking on.
     */
    if (!AnxinTryAcquireSpinLock(&g_ImageEventLock, &oldIrql)) {
        return;
    }
    Trace("LI:ring");

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

    AnxinReleaseSpinLockAtDpc(&g_ImageEventLock, oldIrql);
    Trace("LI:done");
}

// ===========================================================================
// ObCallback pre-operation: protect process handles
// ===========================================================================

/*
 * Strip dangerous access rights from a handle being created or duplicated on a
 * protected object. Handles OB_OPERATION_HANDLE_CREATE and
 * OB_OPERATION_HANDLE_DUPLICATE separately: PreInfo->Parameters is a union, and
 * in a DUPLICATE op the offset-0 member is OriginalDesiredAccess, not
 * DesiredAccess. The old code always wrote through
 * CreateHandleInformation.DesiredAccess, which in a DUPLICATE op clobbered
 * OriginalDesiredAccess (offset 0) and left the real DesiredAccess (offset 4)
 * untouched — corrupting the duplicate operation (boot BSOD 0x139, LIST_ENTRY
 * corruption). Returns the final (stripped) access mask for logging.
 */
static ACCESS_MASK StripProtectedAccess(POB_PRE_OPERATION_INFORMATION PreInfo,
                                        ACCESS_MASK mask,
                                        ACCESS_MASK fallback)
{
    ACCESS_MASK original;
    ACCESS_MASK stripped;

    if (PreInfo->Operation == OB_OPERATION_HANDLE_CREATE)
        original = PreInfo->Parameters->CreateHandleInformation.DesiredAccess;
    else
        original = PreInfo->Parameters->DuplicateHandleInformation.DesiredAccess;

    stripped = original & ~mask;
    if (stripped == 0 && original != 0)
        stripped = fallback;

    if (PreInfo->Operation == OB_OPERATION_HANDLE_CREATE)
        PreInfo->Parameters->CreateHandleInformation.DesiredAccess = stripped;
    else
        PreInfo->Parameters->DuplicateHandleInformation.DesiredAccess = stripped;

    return stripped;
}

OB_PREOP_CALLBACK_STATUS ObPreProcessHandleCreate(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION PreInfo)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (PreInfo->ObjectType != *PsProcessType)
        return OB_PREOP_SUCCESS;
    if (PreInfo->Operation != OB_OPERATION_HANDLE_CREATE &&
        PreInfo->Operation != OB_OPERATION_HANDLE_DUPLICATE)
        return OB_PREOP_SUCCESS;

    HANDLE targetPid = PsGetProcessId((PEPROCESS)PreInfo->Object);
    Trace("OP:enter");
    if (!IsProtectedPidTry(targetPid)) {               // try: never block a handle-open callback
        Trace("OP:notprot");
        return OB_PREOP_SUCCESS;
    }
    Trace("OP:prot");

    HANDLE callerPid = PsGetCurrentProcessId();
    if (callerPid == (HANDLE)4) return OB_PREOP_SUCCESS;         // SYSTEM
    if (IsCallerFamilyTry()) {                                   // trusted core / auxiliary (VUL-100)
        Trace("OP:auth");
        return OB_PREOP_SUCCESS;
    }

    if (PreInfo->Parameters == NULL)
        return OB_PREOP_SUCCESS;

    if (g_DiagFlags & DIAG_DISABLE_OBPROCESS) {
        Trace("OP:gated");
        return OB_PREOP_SUCCESS;
    }

    ACCESS_MASK stripped = StripProtectedAccess(PreInfo, PROTECTED_PROCESS_ACCESS_MASK, PROCESS_QUERY_LIMITED_INFORMATION);
    Trace("OP:strip");
    UNREFERENCED_PARAMETER(stripped);   /* Release: DbgPrintf is empty */

    DbgPrintf("[AnXin] Stripped process access to PID %lu: caller=%lu, access=%08lX\n",
        (ULONG)(ULONG_PTR)targetPid, (ULONG)(ULONG_PTR)callerPid,
        (ULONG)stripped);

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
    Trace("OT:enter");
    if (!IsProtectedPidTry(threadPid)) {               // try: never block a handle-open callback
        Trace("OT:notprot");
        return OB_PREOP_SUCCESS;
    }
    Trace("OT:prot");

    // Check caller authorization
    HANDLE callerPid = PsGetCurrentProcessId();
    if (callerPid == (HANDLE)4) return OB_PREOP_SUCCESS;         // SYSTEM
    if (IsCallerFamilyTry()) {                                   // trusted core / auxiliary (VUL-100)
        Trace("OT:auth");
        return OB_PREOP_SUCCESS;
    }

    if (PreInfo->Parameters == NULL)
        return OB_PREOP_SUCCESS;

    if (g_DiagFlags & DIAG_DISABLE_OBTHREAD) {
        Trace("OT:gated");
        return OB_PREOP_SUCCESS;
    }

    // Strip dangerous thread access rights
    ACCESS_MASK stripped = StripProtectedAccess(PreInfo, PROTECTED_THREAD_ACCESS_MASK, THREAD_QUERY_LIMITED_INFORMATION);
    Trace("OT:strip");
    UNREFERENCED_PARAMETER(stripped);   /* Release: DbgPrintf is empty */

    DbgPrintf("[AnXin] Stripped thread access to PID %lu: caller=%lu, access=%08lX\n",
        (ULONG)(ULONG_PTR)threadPid, (ULONG)(ULONG_PTR)callerPid,
        (ULONG)stripped);

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
         * VUL-100 修复：注册的 PID 是否获得"受信"身份，取决于其完整路径是否
         * 校验为安装目录下的 anxin-security.exe（阻塞式 IsAnxinProcess）。
         * 因此管理员用 ADD_PID 注册一个按名伪装的进程时，该进程只受保护、不
         * 受信，仍无法在 ObCallback 里打开其他受保护进程的句柄。
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
         *
         * VUL-100 fix: a registered PID only gains *trusted* status when its full
         * path verifies as anxin-security.exe under the install dir (blocking
         * IsAnxinProcess). Registering a name-spoofed process therefore leaves it
         * protected-but-untrusted — it still cannot open handles on other
         * protected processes via the ObCallbacks.
         */
        if (irpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(HANDLE)) {
            HANDLE pid = *(PHANDLE)Irp->AssociatedIrp.SystemBuffer;
            BOOLEAN trusted = FALSE;

            if (IsAnxinProcess(pid)) {
                trusted = TRUE;
            } else if (IsProtectedPidTrustedTry(PsGetCurrentProcessId()) &&
                       AnxinNamePrefixMatchOfPid(pid)) {
                /*
                 * 兜底：一个已受信的核心进程（SYSTEM 服务）注册自己刚创建、映像
                 * 路径尚未完全就绪的 UI 进程时，IsAnxinProcess 可能瞬时失败。只
                 * 有"调用者已是受信核心"且目标名称匹配时才放行——伪装进程自己调用
                 * ADD_PID 永远无法通过（调用者不受信）。
                 *
                 * Fallback: a trusted core process (the SYSTEM service) registering
                 * its own freshly-created UI process, when SeLocateProcessImageName
                 * may be transiently unavailable. Only a caller that is ALREADY a
                 * trusted core process may vouch for a name-matching target; a
                 * spoof calling ADD_PID on itself never passes.
                 */
                trusted = TRUE;
            }

            status = AddProtectedPid(pid, trusted);
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    }

    case IOCTL_ANXIN_REMOVE_PID: {
        /* 自保：只有 SYSTEM 或本产品进程能移除受保护 PID（VUL-100：阻塞式全路径校验） */
        if (!IsCallerAuthorizedForIoControl()) {
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
        /* 自保：只有 SYSTEM 或本产品进程能清空受保护 PID 列表（VUL-100：阻塞式全路径校验） */
        if (!IsCallerAuthorizedForIoControl()) {
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
                for (ULONG i = 0; i < copyCount; i++) {
                    outBuf[1 + i] = (ULONG)(ULONG_PTR)g_ProtectedPids.Entries[i].Pid;
                }
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
        /* 自保：只有 SYSTEM 或本产品进程能清除窗口站保护（VUL-100：阻塞式全路径校验） */
        if (!IsCallerAuthorizedForIoControl()) {
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

        if (!IsCallerAuthorizedForIoControl()) {
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

    case IOCTL_ANXIN_SET_DIAG: {
        /*
         * VUL-099 修复：运行时切换诊断位必须做调用方授权校验。置位
         * DIAG_DISABLE_OBPROCESS(0x4)/DIAG_DISABLE_OBTHREAD(0x8) 会直接关闭
         * Ob 进程/线程自保护，任何管理员（含按名伪装进程）都能据此一键瘫痪
         * 全部自保。现在要求 SYSTEM、受保护 PID 或完整路径校验通过的本产品进程
         * （IsCallerAuthorizedForIoControl，阻塞式全路径校验）。
         *
         * VUL-099 fix: toggling diagnostic bits now requires caller authorization.
         * Setting DIAG_DISABLE_OBPROCESS(0x4)/DIAG_DISABLE_OBTHREAD(0x8) disables
         * the Ob process/thread self-protection entirely; any admin (including a
         * name-spoofed process) could otherwise switch off all self-protection.
         * Authorization now requires SYSTEM, a protected PID, or a full-path-
         * verified product process (IsCallerAuthorizedForIoControl).
         */
        if (!IsCallerAuthorizedForIoControl()) {
            status = STATUS_ACCESS_DENIED;
            break;
        }
        if (irpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(ULONG)) {
            g_DiagFlags = *(PULONG)Irp->AssociatedIrp.SystemBuffer;
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    }

    case IOCTL_ANXIN_QUERY_TRACE: {
        ULONG outLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
        PUCHAR outBuf = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
        if (outBuf == NULL || outLen == 0) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        ULONG len = (ULONG)g_TracePos;
        if (len >= outLen)
            len = outLen - 1;
        RtlCopyMemory(outBuf, g_Trace, len);
        outBuf[len] = '\0';
        bytesReturned = len + 1;
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
    KeInitializeSpinLock(&g_PendingLock);

    // Read diagnostic feature switches (0 = all enabled)
    ReadDiagFlags();

    /* VUL-097 根因修复：先加载可信安装目录（从服务 ImagePath 读取，默认
     * "\Program Files\AnXinSecurity"），IsAnxinProcess / IsTrustedImagePath
     * 依赖它做全路径相等校验。 */
    AnxinLoadTrustedInstallDir();

    /*
     * Initialize the deferred auto-protect promotion timer. The DPC promotes
     * queued PIDs once their grace period elapses, so the ObCallbacks never
     * strip the creation handles of a still-initializing process (boot BSOD
     * 0x139 root cause). See MAX_PENDING_PROTECT_PIDS for rationale.
     */
    KeInitializeTimer(&g_PromoteTimer);
    KeInitializeDpc(&g_PromoteDpc, PromotePendingPidsDpc, NULL);
    {
        LARGE_INTEGER due;
        due.QuadPart = -(LONGLONG)(PROMOTION_DELAY_MS * 10000LL);  /* relative, 100ns units */
        KeSetTimerEx(&g_PromoteTimer, due, PROMOTION_PERIOD_MS, &g_PromoteDpc);
    }

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

    // Stop the deferred auto-protect promotion timer.
    KeCancelTimer(&g_PromoteTimer);

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
