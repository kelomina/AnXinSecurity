/*++
Copyright (c) AnXin Security. All rights reserved.

Module Name:
    driver.c

Abstract:
    AnXinProcMon.sys 入口：驱动初始化、设备创建、IOCTL 分发、接管握手、
    授权模型、卸载清理。
    Driver entry: init, device creation, IOCTL dispatch, takeover handshake,
    authorization model, unload cleanup.

    授权模型（契约 v6 §5.1，net_filter 同构）：
    - 设备 DACL 只允许 SYSTEM / Administrators 打开（IoCreateDeviceSecure）。
    - 未接管（UserModeAttached == 0）：驱动 fail-safe，任何回调事件直接丢弃，
      不产生队列占用（无消费者场景零开销）。
    - 接管：用户态先 GET_VERSION 握手校验协议版本；成功后驱动记录
      AttachedProcessId 并开始采集。
    - 写类 IOCTL（SET_FILTER / CLEAR_STATS / SET_DIAG）：仅已接管客户端可执行；
      未接管时返回 STATUS_ACCESS_DENIED（fail-closed）。
    - SYSTEM 始终允许（设备 DACL 已保证；内核回调路径不涉及授权）。

    Authorization model (contract v6 §5.1, isomorphic to net_filter):
    - Device DACL allows only SYSTEM / Administrators (IoCreateDeviceSecure).
    - Not attached (UserModeAttached == 0): fail-safe, every callback event is
      dropped; zero queue overhead without a consumer.
    - Takeover: user mode handshakes via GET_VERSION; on success the driver
      records AttachedProcessId and starts collecting.
    - Write IOCTLs (SET_FILTER / CLEAR_STATS / SET_DIAG) require an attached
      client; otherwise STATUS_ACCESS_DENIED (fail-closed).
    - SYSTEM is always allowed (guaranteed by the device DACL; the kernel
      callback path never involves authorization).

    卸载策略（契约 v6 §6.2）：普通 DriverUnload，不注册卸载保护；
    StartType = 3，与 AnXinProcProtect 的自我保护互不影响。
    Unload strategy (contract v6 §6.2): plain DriverUnload, no self-protection.

Environment:
    Kernel mode only.

--*/

#include "anx_proc_internal.h"

ANX_PROC_GLOBALS g_AnxProc = { 0 };

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
                     _In_ PUNICODE_STRING RegistryPath);
VOID AnxProcDriverUnload(_In_ PDRIVER_OBJECT DriverObject);

/* ==========================================================================
 * IOCTL 分发 / IOCTL dispatch
 * ========================================================================== */

/*
 * 函数名称：AnxProcGetRequestingPid
 * 函数作用：获取请求进程 PID（验证 AttachedProcessId 用）。
 * CLEANUP 与 IOCTL 均在请求进程上下文中执行，PsGetCurrentProcessId
 * 比 IoGetRequestorProcess 更可靠（后者在请求者已退出时可能为 NULL）。
 * Purpose: Returns the requesting process PID (for AttachedProcessId checks).
 *          CLEANUP and IOCTLs run in the requester's context, so
 *          PsGetCurrentProcessId is more reliable than IoGetRequestorProcess.
 * IRQL：<= DISPATCH_LEVEL
 */
static ULONG AnxProcGetRequestingPid(_In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(Irp);
    return (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
}

/*
 * 函数名称：AnxProcIsAuthorizedCaller
 * 函数作用：写类 IOCTL 的调用方校验：必须已接管且是接管进程（或 SYSTEM）。
 * 设备 DACL 已挡住非管理员，此处只做"接管者唯一性"约束。
 * Purpose: Write-IOCTL caller check: must be the attached client (or SYSTEM).
 *          The device DACL already excludes non-admins; this only enforces
 *          single-owner semantics.
 * IRQL：PASSIVE_LEVEL
 */
static BOOLEAN AnxProcIsAuthorizedCaller(_In_ PIRP Irp)
{
    PVOID pid = UlongToPtr(AnxProcGetRequestingPid(Irp));

    if (pid == NULL) {
        return FALSE;
    }
    if (pid == UlongToPtr(4) || pid == UlongToPtr(8)) {
        return TRUE;   /* SYSTEM / Registry */
    }
    return InterlockedCompareExchangePointer(&g_AnxProc.AttachedProcessId,
                                             NULL, NULL) == pid;
}

/*
 * 函数名称：AnxProcIoctlGetVersion
 * 函数作用：GET_VERSION —— 协议版本握手；成功后标记接管。
 * 仅记录 AttachedProcessId（可被更新的连接覆盖），本身不拒绝。
 * Purpose: GET_VERSION — protocol handshake; marks takeover on success.
 *          Only records AttachedProcessId (overridable), never denies.
 * IRQL：PASSIVE_LEVEL
 */
static NTSTATUS AnxProcIoctlGetVersion(_In_ PIRP Irp, _In_ ULONG OutputLen)
{
ULONG pid;
    ANX_PROC_VERSION* version;

    if (OutputLen < sizeof(ANX_PROC_VERSION)) {
        Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
        Irp->IoStatus.Information = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    version = (ANX_PROC_VERSION*)Irp->AssociatedIrp.SystemBuffer;
    RtlZeroMemory(version, sizeof(ANX_PROC_VERSION));

    version->ProtocolVersion = ANX_PROC_PROTOCOL_VERSION;
    version->DriverMajor = 1;
    version->DriverMinor = 0;
    version->DriverPatch = 0;
    version->Capabilities =
        ANX_PROC_CAP_LIFECYCLE | ANX_PROC_CAP_IMAGE | ANX_PROC_CAP_REMOTE_THREAD |
        ANX_PROC_CAP_FILE | ANX_PROC_CAP_REGISTRY | ANX_PROC_CAP_NETWORK |
        ANX_PROC_CAP_IPC;
    version->MaxFilterRules = ANX_PROC_MAX_FILTER_RULES;
    version->MaxCommandLineChars = ANX_PROC_MAX_CMD_CHARS;

    Irp->IoStatus.Information = sizeof(ANX_PROC_VERSION);

    /* 接管握手：版本有效即标记接管（记录接管进程） */
    pid = AnxProcGetRequestingPid(Irp);
    if (pid != 0) {
        InterlockedExchangePointer(&g_AnxProc.AttachedProcessId, UlongToPtr(pid));
        InterlockedExchange(&g_AnxProc.UserModeAttached, 1);
        AnxProcTrace("client attached (pid %lu), version %lu\n",
                     pid, (ULONG)version->ProtocolVersion);
    }

    return STATUS_SUCCESS;
}

/*
 * 函数名称：AnxProcIoctlGetEvents
 * 函数作用：GET_LIFECYCLE_EVENTS / GET_BEHAVIOR_EVENTS —— 预投 IRP 至 CSQ，
 * 由 events.c 在事件到来时配对完成。缓冲必须至少容纳 48 字节事件头。
 * Purpose: GET_*_EVENTS — pends the IRP on the CSQ; events.c pairs & completes
 *          it when events arrive. Buffer must hold >= 48-byte header.
 * IRQL：PASSIVE_LEVEL
 */
static NTSTATUS AnxProcIoctlGetEvents(_In_ PIRP Irp, _In_ ULONG OutputLen,
                                      _In_ PANX_PROC_QUEUE Queue)
{
    if (OutputLen < sizeof(ANX_PROC_EVENT_HDR)) {
        Irp->IoStatus.Information = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (!AnxProcIsAttached()) {
        Irp->IoStatus.Information = 0;
        return STATUS_DEVICE_NOT_READY;
    }

    Irp->IoStatus.Status = STATUS_PENDING;
    IoMarkIrpPending(Irp);
    IoCsqInsertIrp(&Queue->Csq, Irp, NULL);

    /* 队列中可能已有事件：立即尝试配对 */
    AnxProcDrainToIrps(Queue);
    return STATUS_PENDING;
}

/*
 * 函数名称：AnxProcIoctlSetFilter
 * 函数作用：SET_FILTER —— 整表原子替换（校验与交换在 rules.c）。
 * Purpose: SET_FILTER — whole-table atomic replace (validation & swap in rules.c).
 * IRQL：PASSIVE_LEVEL
 */
static NTSTATUS AnxProcIoctlSetFilter(_In_ PIRP Irp, _In_ ULONG InputLen)
{
    NTSTATUS status;

    if (!AnxProcIsAuthorizedCaller(Irp)) {
        Irp->IoStatus.Information = 0;
        return STATUS_ACCESS_DENIED;
    }

    status = AnxProcRulesSetTable(Irp->AssociatedIrp.SystemBuffer, InputLen);
    Irp->IoStatus.Information = 0;
    return status;
}

/*
 * 函数名称：AnxProcIoctlGetHealth
 * 函数作用：GET_HEALTH —— 回调活性心跳（§13.7）。只读，任何人可查。
 * Purpose: GET_HEALTH — callback activity heartbeat (contract §13.7).
 *          Read-only; anyone may query.
 * IRQL：PASSIVE_LEVEL
 */
static NTSTATUS AnxProcIoctlGetHealth(_In_ PIRP Irp, _In_ ULONG OutputLen)
{
    ANX_PROC_HEALTH* health;

    if (OutputLen < sizeof(ANX_PROC_HEALTH)) {
        Irp->IoStatus.Information = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    health = (ANX_PROC_HEALTH*)Irp->AssociatedIrp.SystemBuffer;
    RtlZeroMemory(health, sizeof(ANX_PROC_HEALTH));

    health->LastCallbackTickMs =
        (UINT64)InterlockedCompareExchange64(&g_AnxProc.LastCallbackTickMs, 0, 0);
    health->EventsLifecycleQueued =
        (UINT64)InterlockedCompareExchange64(&g_AnxProc.LifecycleQueue.EventsQueued, 0, 0);
    health->EventsLifecycleDropped =
        (UINT64)InterlockedCompareExchange64(&g_AnxProc.LifecycleQueue.EventsDropped, 0, 0);
    health->EventsBehaviorQueued =
        (UINT64)InterlockedCompareExchange64(&g_AnxProc.BehaviorQueue.EventsQueued, 0, 0);
    health->EventsBehaviorDropped =
        (UINT64)InterlockedCompareExchange64(&g_AnxProc.BehaviorQueue.EventsDropped, 0, 0);
    health->LifecycleDepth =
        (UINT32)InterlockedCompareExchange(&g_AnxProc.LifecycleQueue.EventCount, 0, 0);
    health->BehaviorDepth =
        (UINT32)InterlockedCompareExchange(&g_AnxProc.BehaviorQueue.EventCount, 0, 0);
    health->Attached =
        (UINT32)InterlockedCompareExchange(&g_AnxProc.UserModeAttached, 0, 0);
    health->DiagFlags =
        (UINT32)InterlockedCompareExchange(&g_AnxProc.DiagFlags, 0, 0);
    /* 回调注册状态并入诊断位（bit16/17/18，见 AnxProcLifecycleCallbackStatus） */
    health->DiagFlags |= AnxProcLifecycleCallbackStatus();

    Irp->IoStatus.Information = sizeof(ANX_PROC_HEALTH);
    return STATUS_SUCCESS;
}

/*
 * 函数名称：AnxProcIoctlClearStats
 * 函数作用：CLEAR_STATS —— 清零计数（供测试与诊断）。
 * Purpose: CLEAR_STATS — zeroes counters (tests & diagnostics).
 * IRQL：PASSIVE_LEVEL
 */
static NTSTATUS AnxProcIoctlClearStats(_In_ PIRP Irp)
{
    if (!AnxProcIsAuthorizedCaller(Irp)) {
        Irp->IoStatus.Information = 0;
        return STATUS_ACCESS_DENIED;
    }

    InterlockedExchange64(&g_AnxProc.LifecycleQueue.EventsQueued, 0);
    InterlockedExchange64(&g_AnxProc.LifecycleQueue.EventsDropped, 0);
    InterlockedExchange64(&g_AnxProc.BehaviorQueue.EventsQueued, 0);
    InterlockedExchange64(&g_AnxProc.BehaviorQueue.EventsDropped, 0);
    InterlockedExchange(&g_AnxProc.LifecycleQueue.DroppedSinceLast, 0);
    InterlockedExchange(&g_AnxProc.BehaviorQueue.DroppedSinceLast, 0);

    Irp->IoStatus.Information = 0;
    return STATUS_SUCCESS;
}

/*
 * 函数名称：AnxProcIoctlSetDiag
 * 函数作用：SET_DIAG —— 设置诊断开关（ANX_PROC_DIAG_*）。
 * Purpose: SET_DIAG — sets diagnostic flags (ANX_PROC_DIAG_*).
 * IRQL：PASSIVE_LEVEL
 */
static NTSTATUS AnxProcIoctlSetDiag(_In_ PIRP Irp, _In_ ULONG InputLen)
{
    ANX_PROC_DIAG* diag;

    if (!AnxProcIsAuthorizedCaller(Irp)) {
        Irp->IoStatus.Information = 0;
        return STATUS_ACCESS_DENIED;
    }
    if (InputLen < sizeof(ANX_PROC_DIAG)) {
        Irp->IoStatus.Information = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    diag = (ANX_PROC_DIAG*)Irp->AssociatedIrp.SystemBuffer;
    InterlockedExchange(&g_AnxProc.DiagFlags, diag->Flags);

    Irp->IoStatus.Information = 0;
    return STATUS_SUCCESS;
}

/* ==========================================================================
 * 分发例程 / Dispatch routines
 * ========================================================================== */

static NTSTATUS AnxProcDefault(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_INVALID_DEVICE_REQUEST;
}

static NTSTATUS AnxProcCreateClose(_In_ PDEVICE_OBJECT DeviceObject,
                                   _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS AnxProcDeviceControl(_In_ PDEVICE_OBJECT DeviceObject,
                                     _In_ PIRP Irp)
{
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG              code = irpSp->Parameters.DeviceIoControl.IoControlCode;
    ULONG              inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG              outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    NTSTATUS           status;

    UNREFERENCED_PARAMETER(DeviceObject);

    switch (code) {
    case IOCTL_ANX_PROC_GET_VERSION:
        status = AnxProcIoctlGetVersion(Irp, outputLen);
        break;

    case IOCTL_ANX_PROC_GET_LIFECYCLE_EVENTS:
        status = AnxProcIoctlGetEvents(Irp, outputLen, &g_AnxProc.LifecycleQueue);
        break;

    case IOCTL_ANX_PROC_GET_BEHAVIOR_EVENTS:
        status = AnxProcIoctlGetEvents(Irp, outputLen, &g_AnxProc.BehaviorQueue);
        break;

    case IOCTL_ANX_PROC_SET_FILTER:
        status = AnxProcIoctlSetFilter(Irp, inputLen);
        break;

    case IOCTL_ANX_PROC_GET_HEALTH:
        status = AnxProcIoctlGetHealth(Irp, outputLen);
        break;

    case IOCTL_ANX_PROC_CLEAR_STATS:
        status = AnxProcIoctlClearStats(Irp);
        break;

    case IOCTL_ANX_PROC_SET_DIAG:
        status = AnxProcIoctlSetDiag(Irp, inputLen);
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        Irp->IoStatus.Information = 0;
        break;
    }

    if (status != STATUS_PENDING) {
        Irp->IoStatus.Status = status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
    }
    return status;
}

static NTSTATUS AnxProcCleanup(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    /*
     * 句柄关闭（含客户端崩溃，内核仍会发 CLEANUP）：若关闭者就是接管者，
     * 解除接管，回到 fail-safe（事件直接丢弃）状态。
     *
     * 注意：这里不 flush CSQ —— I/O 管理器在 IRP_MJ_CLEANUP 之前已通过
     * CSQ 取消例程（AnxProcCsqCompleteCanceledIrp）取消了该文件对象关联
     * 的全部挂起 IRP。全量 AnxProcCsqFlushAll 会误杀其他进程的挂起 IRP，
     * 这是 VUL-049 的同类错误（net_filter 已移除该分支）。
     */
    if (AnxProcIsAuthorizedCaller(Irp)) {
        InterlockedExchange(&g_AnxProc.UserModeAttached, 0);
        InterlockedExchangePointer(&g_AnxProc.AttachedProcessId, NULL);
        AnxProcTrace("client detached\n");
    }

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/* ==========================================================================
 * 入口与卸载 / Entry & unload
 * ========================================================================== */

/*
 * 函数名称：DriverEntry
 * 函数作用：驱动入口。创建设备（SDDL SYSTEM/BA + FILE_DEVICE_SECURE_OPEN）、
 * 符号链接、分发例程，初始化各子系统（events/rules/lifecycle/file/registry/
 * network），并注册内核回调（ProcessNotify/ThreadNotify/LoadImage/Flt/Cm/WFP）。
 * 任一子系统初始化失败即回滚并返回失败。
 * Purpose: Driver entry. Device (SDDL SYSTEM/BA + FILE_DEVICE_SECURE_OPEN),
 *          symlink, dispatch, subsystem init (events/rules/lifecycle/file/
 *          registry/network), kernel callback registration. Rolls back on any
 *          subsystem failure.
 * IRQL：PASSIVE_LEVEL
 */
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
                     _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS           status;
    UNICODE_STRING     deviceName;
    UNICODE_STRING     symlinkName;
    UNICODE_STRING     sddlString;
    ULONG              i;

    UNREFERENCED_PARAMETER(RegistryPath);

    RtlZeroMemory(&g_AnxProc, sizeof(g_AnxProc));
    g_AnxProc.DriverObject = DriverObject;

    /*
     * 生命周期采集默认开启（接管后才真正入队，未接管时回调直接丢弃）。
     * 用户态后续可通过 SET_FILTER 附带开关细粒度控制（保留接口）。
     * Lifecycle collection defaults ON; events only queue once attached.
     */
    InterlockedExchange(&g_AnxProc.CollectLifecycle, 1);
    InterlockedExchange(&g_AnxProc.Enabled, 1);

    /* 分发例程：未实现的 major function 拒绝；PnP/Power 不接受 */
    for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
        DriverObject->MajorFunction[i] = AnxProcDefault;
    }
    DriverObject->MajorFunction[IRP_MJ_CREATE] = AnxProcCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = AnxProcCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = AnxProcCleanup;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = AnxProcDeviceControl;
    DriverObject->DriverUnload = AnxProcDriverUnload;

    /* 设备 */
    RtlInitUnicodeString(&deviceName, ANX_PROC_DEVICE_NAME);
    RtlInitUnicodeString(&sddlString, ANX_PROC_DEVICE_SDDL);
    status = IoCreateDeviceSecure(DriverObject,
                                  0,
                                  &deviceName,
                                  FILE_DEVICE_UNKNOWN,
                                  FILE_DEVICE_SECURE_OPEN,
                                  FALSE,
                                  &sddlString,
                                  NULL,
                                  &g_AnxProc.DeviceObject);
    if (!NT_SUCCESS(status)) {
        AnxProcError("IoCreateDeviceSecure failed 0x%08X\n", status);
        return status;
    }

    if (g_AnxProc.DeviceObject->Flags & DO_DIRECT_IO) {
        g_AnxProc.DeviceObject->Flags &= ~DO_DIRECT_IO;
    }
    g_AnxProc.DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    /* 符号链接 */
    RtlInitUnicodeString(&symlinkName, ANX_PROC_SYMLINK_NAME);
    status = IoCreateSymbolicLink(&symlinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        AnxProcError("IoCreateSymbolicLink failed 0x%08X\n", status);
        IoDeleteDevice(g_AnxProc.DeviceObject);
        g_AnxProc.DeviceObject = NULL;
        return status;
    }
    g_AnxProc.SymlinkCreated = TRUE;

    /* 子系统初始化：任一失败回滚 */
    status = AnxProcEventsInitialize();
    if (!NT_SUCCESS(status)) {
        goto rollback;
    }
    status = AnxProcRulesInitialize();
    if (!NT_SUCCESS(status)) {
        goto rollback;
    }
    status = AnxProcLifecycleInitialize();
    if (!NT_SUCCESS(status)) {
        goto rollback;
    }
    status = AnxProcFileInitialize(DriverObject);
    if (!NT_SUCCESS(status)) {
        goto rollback;
    }
    status = AnxProcRegistryInitialize();
    if (!NT_SUCCESS(status)) {
        goto rollback;
    }
    status = AnxProcNetworkInitialize(g_AnxProc.DeviceObject);
    if (!NT_SUCCESS(status)) {
        goto rollback;
    }

    /* 回调注册（在接管前注册；未接管时不采集，fail-safe） */
    AnxProcLifecycleRegisterCallbacks();

    AnxProcTrace("AnXinProcMon loaded\n");
    return STATUS_SUCCESS;

rollback:
    AnxProcError("AnXinProcMon init rollback (0x%08X)\n", status);
    AnxProcLifecycleUnregisterCallbacks();
    AnxProcNetworkShutdown();
    AnxProcRegistryShutdown();
    AnxProcFileShutdown();
    AnxProcRulesShutdown();
    AnxProcEventsShutdown();

    if (g_AnxProc.SymlinkCreated) {
        IoDeleteSymbolicLink(&g_AnxProc.SymlinkName);
        g_AnxProc.SymlinkCreated = FALSE;
    }
    if (g_AnxProc.DeviceObject != NULL) {
        IoDeleteDevice(g_AnxProc.DeviceObject);
        g_AnxProc.DeviceObject = NULL;
    }
    return status;
}

/*
 * 函数名称：AnxProcDriverUnload
 * 函数作用：驱动卸载：置 ShuttingDown、注销回调、清理各子系统、
 * 删除符号链接与设备。
 * Purpose: Driver unload: set ShuttingDown, unregister callbacks, tear down
 *          subsystems, delete symlink & device.
 * IRQL：PASSIVE_LEVEL
 */
VOID AnxProcDriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    InterlockedExchange(&g_AnxProc.ShuttingDown, 1);
    InterlockedExchange(&g_AnxProc.UserModeAttached, 0);

    AnxProcLifecycleUnregisterCallbacks();
    AnxProcNetworkShutdown();
    AnxProcRegistryShutdown();
    AnxProcFileShutdown();
    AnxProcRulesShutdown();
    AnxProcEventsShutdown();

    if (g_AnxProc.SymlinkCreated) {
        IoDeleteSymbolicLink(&g_AnxProc.SymlinkName);
        g_AnxProc.SymlinkCreated = FALSE;
    }
    if (g_AnxProc.DeviceObject != NULL) {
        IoDeleteDevice(g_AnxProc.DeviceObject);
        g_AnxProc.DeviceObject = NULL;
    }

    AnxProcTrace("AnXinProcMon unloaded\n");
}