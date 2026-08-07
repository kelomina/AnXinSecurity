/*++
Copyright (c) AnXin Security. All rights reserved.

Module Name:
    driver.c

Abstract:
    AnXinNetFilter.sys 入口：设备对象、派发例程、IOCTL 处理与卸载。
    AnXinNetFilter.sys entry point: device object, dispatch routines, IOCTL
    handling and unload.

    安全模型 / Security model:
    - 设备用 IoCreateDeviceSecure 创建并绑定显式 DACL，只有 SYSTEM 与
      Administrators 能打开。任何进程都能下发规则或伪造裁决将是灾难性的。
      The device is created with IoCreateDeviceSecure and an explicit DACL so
      only SYSTEM and Administrators can open it. Letting any process push rules
      or forge verdicts would be catastrophic.
    - 同一时刻只接受一个「已接管」的客户端，由版本握手确立，句柄关闭即解除。
      Exactly one attached client at a time, established by the version
      handshake and released when the handle closes.
    - 未接管时驱动全放行（fail-open），服务崩溃不会导致机器断网。
      While unattached the driver permits everything, so a crashed service never
      cuts the machine off the network.

Environment:
    Kernel mode only.

--*/

#include "anx_net_internal.h"
#include <wdmsec.h>

/* 全局状态的唯一定义 / the one and only definition of the global state */
ANX_GLOBALS g_Anx = { 0 };

DRIVER_INITIALIZE DriverEntry;
static DRIVER_UNLOAD   AnxDriverUnload;
static DRIVER_DISPATCH AnxDispatchCreate;
static DRIVER_DISPATCH AnxDispatchClose;
static DRIVER_DISPATCH AnxDispatchCleanup;
static DRIVER_DISPATCH AnxDispatchDeviceControl;
static void            AnxWfpInitThread(_In_ PVOID Context);

/* ==========================================================================
 * 接管状态 / Attachment state
 * ========================================================================== */

/*
 * 函数名称：AnxDetachUserMode
 * 函数作用：解除用户态接管，清空事件队列与挂起决策，回到全放行状态。
 * Purpose: Detaches user mode, drains the event queue and pended decisions, and
 *          returns to the fully permissive state.
 *
 * 挂起的连接一律按放行完成：此刻已经没有人能回答「允许还是阻止」，
 * 让它们永远挂着等同于把应用挂死。
 * Pended connections are all completed as permit: nobody is left to answer
 * allow-or-block, and leaving them pended would hang the applications forever.
 *
 * 调用方：IRP_MJ_CLEANUP、DriverUnload
 * Called by: IRP_MJ_CLEANUP and DriverUnload
 * IRQL：PASSIVE_LEVEL
 * 中文关键词：解除接管，兜底放行，恢复旁路
 * English keywords: detach, fail-open, bypass restore
 */
static void AnxDetachUserMode(void)
{
    if (InterlockedExchange(&g_Anx.UserModeAttached, 0) == 0) {
        return;
    }

    g_Anx.AttachedProcessId = NULL;

    AnxTrace("User mode detached, reverting to permissive mode\n");

    AnxPendingAbortAll(ANX_NET_ACTION_ALLOW);
    AnxCsqFlushAll(STATUS_CANCELLED);
    AnxCacheFlush(ANX_NET_FLUSH_ALL, 0, 0);
}

/* ==========================================================================
 * IOCTL 处理 / IOCTL handlers
 * ========================================================================== */

static NTSTATUS AnxIoctlGetVersion(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION IrpSp,
                                   _Out_ ULONG* BytesReturned)
{
    ANX_NET_VERSION* out;

    *BytesReturned = 0;

    if (IrpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(ANX_NET_VERSION)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    out = (ANX_NET_VERSION*)Irp->AssociatedIrp.SystemBuffer;
    RtlZeroMemory(out, sizeof(*out));

    out->ProtocolVersion = ANX_NET_PROTOCOL_VERSION;
    out->DriverMajor     = 1;
    out->DriverMinor     = 0;
    out->DriverPatch     = 0;
    out->Capabilities    = g_Anx.Capabilities;
    out->MaxRules        = ANX_NET_MAX_RULES;
    out->MaxDomainRules  = ANX_NET_MAX_DOMAIN_RULES;
    out->MaxPending      = ANX_NET_MAX_PENDING;

    /*
     * 版本握手即接管。记录调用方 PID，只有同一个进程关闭句柄时才解除接管。
     * The version handshake is the attach. The caller's PID is recorded so only
     * that process closing its handle performs the detach.
     */
    if (InterlockedExchange(&g_Anx.UserModeAttached, 1) == 0) {
        g_Anx.AttachedProcessId = PsGetCurrentProcessId();
        AnxTrace("User mode attached (pid %lu)\n",
                 (ULONG)(ULONG_PTR)g_Anx.AttachedProcessId);
    }

    *BytesReturned = sizeof(ANX_NET_VERSION);
    return STATUS_SUCCESS;
}

static NTSTATUS AnxIoctlSetConfig(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION IrpSp)
{
    const ANX_NET_CONFIG* input;
    ANX_NET_CONFIG        sanitized;
    KIRQL                 oldIrql;

    if (IrpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(ANX_NET_CONFIG)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    input = (const ANX_NET_CONFIG*)Irp->AssociatedIrp.SystemBuffer;
    RtlCopyMemory(&sanitized, input, sizeof(sanitized));

    /*
     * 逐项收敛到合法取值。非法输入绝不能变成「未定义行为」，
     * 尤其是默认动作 —— 一个越界的枚举值如果被当成拦截，会把机器断网。
     * Every field is clamped to a legal value. Invalid input must never become
     * undefined behaviour, especially for the default actions: an out-of-range
     * enum treated as "block" would cut the machine off the network.
     */
    if (sanitized.Mode > ANX_NET_MODE_LEARN) {
        sanitized.Mode = ANX_NET_MODE_SILENT;
    }
    if (sanitized.DefaultOutbound > ANX_NET_ACTION_PROMPT) {
        sanitized.DefaultOutbound = ANX_NET_ACTION_ALLOW;
    }
    if (sanitized.DefaultInbound > ANX_NET_ACTION_PROMPT) {
        sanitized.DefaultInbound = ANX_NET_ACTION_ALLOW;
    }
    if (sanitized.TimeoutAction != ANX_NET_ACTION_BLOCK) {
        sanitized.TimeoutAction = ANX_NET_ACTION_ALLOW;
    }
    if (sanitized.PromptTimeoutMs == 0 || sanitized.PromptTimeoutMs > 300000) {
        sanitized.PromptTimeoutMs = ANX_DEFAULT_PROMPT_MS;
    }

    oldIrql = ExAcquireSpinLockExclusive(&g_Anx.ConfigLock);
    RtlCopyMemory(&g_Anx.Config, &sanitized, sizeof(ANX_NET_CONFIG));
    ExReleaseSpinLockExclusive(&g_Anx.ConfigLock, oldIrql);

    /* 配置变了，旧裁决可能不再适用 / the old verdicts may no longer apply */
    AnxCacheFlush(ANX_NET_FLUSH_ALL, 0, 0);

    AnxTrace("Config updated: enabled=%u mode=%u out=%u in=%u timeout=%ums\n",
             sanitized.Enabled, sanitized.Mode, sanitized.DefaultOutbound,
             sanitized.DefaultInbound, sanitized.PromptTimeoutMs);

    return STATUS_SUCCESS;
}

static NTSTATUS AnxIoctlSetVerdict(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION IrpSp)
{
    const ANX_NET_VERDICT* verdict;

    if (IrpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(ANX_NET_VERDICT)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    verdict = (const ANX_NET_VERDICT*)Irp->AssociatedIrp.SystemBuffer;

    return AnxPendingResolve(verdict->DecisionId, verdict->Action,
                             verdict->Flags, verdict->CacheTtlMs);
}

static NTSTATUS AnxIoctlGetStats(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION IrpSp,
                                 _Out_ ULONG* BytesReturned)
{
    return AnxStatSnapshot(Irp->AssociatedIrp.SystemBuffer,
                           IrpSp->Parameters.DeviceIoControl.OutputBufferLength,
                           BytesReturned);
}

static NTSTATUS AnxIoctlFlushCache(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION IrpSp)
{
    const ANX_NET_FLUSH* flush;

    if (IrpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(ANX_NET_FLUSH)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    flush = (const ANX_NET_FLUSH*)Irp->AssociatedIrp.SystemBuffer;

    if (flush->Scope > ANX_NET_FLUSH_BY_APPID) {
        return STATUS_INVALID_PARAMETER;
    }

    AnxCacheFlush(flush->Scope, flush->ProcessId, flush->AppIdHash);
    return STATUS_SUCCESS;
}

/* ==========================================================================
 * 派发例程 / Dispatch routines
 * ========================================================================== */

static NTSTATUS AnxDispatchCreate(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS AnxDispatchClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/*
 * 函数名称：AnxDispatchCleanup
 * 函数作用：句柄被关闭时解除接管，保证不会有挂起的连接或 IRP 遗留。
 * Purpose: Detaches on handle close so no pended connection or IRP is left over.
 *
 * 这条路径同时覆盖服务进程正常退出与异常崩溃两种情况 —— 崩溃时内核也会
 * 走 CLEANUP，这正是「服务挂了不能断网」这条保证得以成立的原因。
 * This path covers both a clean exit and a crash of the service — the kernel
 * still issues CLEANUP on crash, which is exactly what makes the "a dead
 * service must not cut networking" guarantee hold.
 *
 * 调用方：I/O 管理器
 * Called by: the I/O manager
 * IRQL：PASSIVE_LEVEL
 * 中文关键词：句柄清理，解除接管，崩溃恢复
 * English keywords: handle cleanup, detach, crash recovery
 */
static NTSTATUS AnxDispatchCleanup(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    if (g_Anx.AttachedProcessId == PsGetCurrentProcessId()) {
        AnxDetachUserMode();
    }
    /*
     * VUL-049: 移除非接管者分支的 AnxCsqFlushAll(STATUS_CANCELLED)。
     * 旧代码在任意进程关闭句柄时清空 CSQ 中的全部 IRP，而非仅当前进程的
     * IRP，导致服务进程所有挂起的 GET_EVENT IRP 被误杀，网络事件收集中断。
     * I/O 管理器在 IRP_MJ_CLEANUP 前已通过 CSQ 取消例程处理了该文件对象
     * 关联的 IRP，此处的全量清理是多余的。
     *
     * VUL-049: Removed AnxCsqFlushAll(STATUS_CANCELLED) from the non-owner
     * branch. The old code flushed ALL pending IRPs in the CSQ whenever any
     * non-owner process closed its handle, instead of only that process's
     * IRPs. This killed the service's pending GET_EVENT IRPs and broke
     * network event collection. The I/O manager already cancels IRPs
     * associated with this file object via the CSQ cancel routine before
     * IRP_MJ_CLEANUP, so the full flush was redundant.
     */

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/*
 * 函数名称：AnxDispatchDeviceControl
 * 函数作用：IOCTL 总入口，校验长度后分派到各处理函数。
 * Purpose: The IOCTL entry point; validates lengths and dispatches.
 *
 * GET_EVENT 是唯一会返回 STATUS_PENDING 的分支：它把 IRP 挂进取消安全队列，
 * 等有事件时再完成。挂入之后绝不能再碰这个 IRP —— 它可能已经在另一个 CPU 上
 * 被完成并释放了。
 * GET_EVENT is the only branch returning STATUS_PENDING: it parks the IRP in
 * the cancel-safe queue for later completion. After insertion the IRP must
 * never be touched again — another CPU may already have completed and freed it.
 *
 * 调用方：I/O 管理器
 * Called by: the I/O manager
 * IRQL：PASSIVE_LEVEL
 * 中文关键词：IOCTL 分派，挂起请求，取消安全队列
 * English keywords: IOCTL dispatch, pending request, cancel-safe queue
 */
static NTSTATUS AnxDispatchDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    PIO_STACK_LOCATION irpSp;
    NTSTATUS           status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG              bytesReturned = 0;
    ULONG              controlCode;

    UNREFERENCED_PARAMETER(DeviceObject);

    irpSp = IoGetCurrentIrpStackLocation(Irp);
    controlCode = irpSp->Parameters.DeviceIoControl.IoControlCode;

    if (AnxIsShuttingDown()) {
        status = STATUS_DEVICE_REMOVED;
        goto Complete;
    }

    switch (controlCode) {

    case IOCTL_ANX_NET_GET_VERSION:
        status = AnxIoctlGetVersion(Irp, irpSp, &bytesReturned);
        break;

    case IOCTL_ANX_NET_SET_CONFIG:
        /* BYOVD 防护：仅已接管客户端可修改配置 */
        if (!AnxIsAttached()) { status = STATUS_DEVICE_NOT_READY; break; }
        status = AnxIoctlSetConfig(Irp, irpSp);
        break;

    case IOCTL_ANX_NET_SET_RULES:
        if (!AnxIsAttached()) { status = STATUS_DEVICE_NOT_READY; break; }
        status = AnxRulesSetTable(Irp->AssociatedIrp.SystemBuffer,
                                  irpSp->Parameters.DeviceIoControl.InputBufferLength);
        break;

    case IOCTL_ANX_NET_SET_DOMAINS:
        if (!AnxIsAttached()) { status = STATUS_DEVICE_NOT_READY; break; }
        status = AnxDomainsSetTable(Irp->AssociatedIrp.SystemBuffer,
                                    irpSp->Parameters.DeviceIoControl.InputBufferLength);
        break;

    case IOCTL_ANX_NET_SET_LIMITS:
        if (!AnxIsAttached()) { status = STATUS_DEVICE_NOT_READY; break; }
        status = AnxLimitsSetTable(Irp->AssociatedIrp.SystemBuffer,
                                   irpSp->Parameters.DeviceIoControl.InputBufferLength);
        break;

    case IOCTL_ANX_NET_SET_VERDICT:
        if (!AnxIsAttached()) { status = STATUS_DEVICE_NOT_READY; break; }
        status = AnxIoctlSetVerdict(Irp, irpSp);
        break;

    case IOCTL_ANX_NET_GET_STATS:
        status = AnxIoctlGetStats(Irp, irpSp, &bytesReturned);
        break;

    case IOCTL_ANX_NET_FLUSH_CACHE:
        if (!AnxIsAttached()) { status = STATUS_DEVICE_NOT_READY; break; }
        status = AnxIoctlFlushCache(Irp, irpSp);
        break;

    case IOCTL_ANX_NET_GET_EVENT:
        if (irpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(ANX_NET_EVENT)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        if (!AnxIsAttached()) {
            status = STATUS_DEVICE_NOT_READY;
            break;
        }

        IoMarkIrpPending(Irp);
        IoCsqInsertIrp(&g_Anx.Csq, Irp, NULL);

        /* 关闭「事件先到、IRP 后到」的竞态 / close the event-before-IRP race */
        AnxEventDrainToIrps();

        /* Irp 已交给队列，此后不得再访问 / the IRP now belongs to the queue */
        return STATUS_PENDING;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

Complete:
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

/* ==========================================================================
 * 卸载 / Unload
 * ========================================================================== */

/*
 * 函数名称：AnxDriverUnload
 * 函数作用：按安全顺序拆除驱动的全部资源。
 * Purpose: Tears down every driver resource in the safe order.
 *
 * 顺序至关重要 / The order matters:
 *   1. 置卸载标志，让分类回调立刻走旁路
 *      Set the shutdown flag so classify callbacks immediately bypass
 *   2. 停超时定时器并等 DPC 退场
 *      Stop the timeout timer and drain the DPC
 *   3. 拆 WFP（内部会先完成所有挂起分类，再注销 callout）
 *      Tear down WFP (which completes pended classifications before
 *      unregistering the callouts)
 *   4. 收事件队列与 IRP
 *      Drain the event queue and the IRPs
 *   5. 释放表与缓存
 *      Free tables and caches
 *   6. 删符号链接与设备
 *      Delete the symlink and the device
 *
 * 调用方：I/O 管理器
 * Called by: the I/O manager
 * IRQL：PASSIVE_LEVEL
 * 中文关键词：卸载顺序，资源拆除，安全退出
 * English keywords: unload ordering, teardown, safe exit
 */
static void AnxDriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    AnxTrace("Unloading...\n");

    InterlockedExchange(&g_Anx.ShuttingDown, 1);

    AnxPendingShutdown();
    AnxWfpShutdown();
    AnxDetachUserMode();
    AnxEventsShutdown();
    AnxRulesShutdown();

    if (g_Anx.SymlinkCreated) {
        (void)IoDeleteSymbolicLink(&g_Anx.SymlinkName);
        g_Anx.SymlinkCreated = FALSE;
    }

    if (g_Anx.DeviceObject != NULL) {
        IoDeleteDevice(g_Anx.DeviceObject);
        g_Anx.DeviceObject = NULL;
    }

    AnxTrace("Unloaded\n");
}

/* ==========================================================================
 * 入口 / Entry point
 * ========================================================================== */

/*
 * 函数名称：AnxWfpInitThread
 * 函数作用：boot-start 延迟 WFP 初始化的系统线程。
 * Purpose: System thread for deferred WFP initialization under boot-start.
 *
 * boot-start 驱动的 DriverEntry 在内核 Phase 1 执行，此时 tcpip.sys 和 BFE
 * 尚未加载，FwpsCalloutRegister / FwpmEngineOpen0 必然失败。本线程等待
 * 网络栈就绪后重试 WFP 初始化，最多 12 次（每次间隔 5 秒，共 60 秒）。
 * Boot-start DriverEntry runs during kernel Phase 1, before tcpip.sys and
 * BFE are loaded. This thread waits and retries WFP initialization up to
 * 12 times at 5-second intervals (60 seconds total).
 *
 * 调用方：PsCreateSystemThread（由 DriverEntry 创建）
 * Called by: PsCreateSystemThread (created by DriverEntry)
 * IRQL：PASSIVE_LEVEL
 */
static void AnxWfpInitThread(_In_ PVOID Context)
{
    NTSTATUS       status;
    int            retries;
    LARGE_INTEGER  delay;

    UNREFERENCED_PARAMETER(Context);

    /* 5 秒（负值 = 相对时间，100ns 单位）/ 5 seconds relative */
    delay.QuadPart = -50000000LL;

    for (retries = 0; retries < 12; retries++) {
        KeDelayExecutionThread(KernelMode, FALSE, &delay);

        if (AnxIsShuttingDown())
            break;

        status = AnxWfpInitialize(g_Anx.DeviceObject);
        if (NT_SUCCESS(status)) {
            AnxTrace("WFP initialized (attempt %d)\n", retries + 1);
            break;
        }
        AnxWarn("WFP init attempt %d failed: 0x%08X\n", retries + 1, status);
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

/*
 * 函数名称：DriverEntry
 * 函数作用：创建受保护的设备对象、初始化各子系统并注册 WFP callout。
 * Purpose: Creates the secured device object, initializes the subsystems and
 *          registers the WFP callouts.
 *
 * 初始配置刻意是「全放行 + 未接管」：驱动加载完成到服务下发配置之间的这段窗口
 * 里，网络必须完全正常。
 * The initial configuration is deliberately "permit everything, not attached":
 * during the window between load and the service pushing a configuration the
 * network must behave exactly as if we were not there.
 *
 * 调用方：I/O 管理器
 * Called by: the I/O manager
 * IRQL：PASSIVE_LEVEL
 * 中文关键词：驱动入口，安全设备，初始旁路
 * English keywords: driver entry, secure device, initial bypass
 */
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS       status;
    UNICODE_STRING deviceName;
    UNICODE_STRING sddlString;

    UNREFERENCED_PARAMETER(RegistryPath);

    AnxTrace("Loading AnXinNetFilter...\n");

    RtlZeroMemory(&g_Anx, sizeof(g_Anx));
    g_Anx.DriverObject = DriverObject;

    /* 初始状态：不启用、不接管、全放行 */
    /* Initial state: disabled, unattached, fully permissive */
    g_Anx.Config.Enabled          = 0;
    g_Anx.Config.Mode             = ANX_NET_MODE_SILENT;
    g_Anx.Config.DefaultOutbound  = ANX_NET_ACTION_ALLOW;
    g_Anx.Config.DefaultInbound   = ANX_NET_ACTION_ALLOW;
    g_Anx.Config.PromptTimeoutMs  = ANX_DEFAULT_PROMPT_MS;
    g_Anx.Config.TimeoutAction    = ANX_NET_ACTION_ALLOW;
    g_Anx.Config.AllowLoopback    = 1;

    /*
     * 自保：不设置 DriverUnload。
     * 没有 DriverUnload 例程的驱动无法被 sc stop / NtUnloadDriver 卸载。
     * AnxDriverUnload 保留在源码中，供未来产品自身的授权卸载流程使用。
     * Self-protection: do NOT set DriverUnload. A driver whose DriverUnload
     * is NULL cannot be unloaded by sc stop / NtUnloadDriver. AnxDriverUnload
     * remains in the source for a future authorized uninstall path.
     */
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = AnxDispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = AnxDispatchClose;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP]        = AnxDispatchCleanup;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = AnxDispatchDeviceControl;

    RtlInitUnicodeString(&deviceName, ANX_NET_DEVICE_NAME);
    RtlInitUnicodeString(&sddlString, ANX_NET_DEVICE_SDDL);

    /*
     * IoCreateDeviceSecure 而非 IoCreateDevice：显式 DACL 把设备限制给
     * SYSTEM 与 Administrators。FILE_DEVICE_SECURE_OPEN 让这套 DACL 同样
     * 覆盖以设备名为前缀的相对打开路径。
     * IoCreateDeviceSecure rather than IoCreateDevice: the explicit DACL limits
     * the device to SYSTEM and Administrators, and FILE_DEVICE_SECURE_OPEN
     * makes that DACL apply to relative opens under the device name too.
     */
    status = IoCreateDeviceSecure(DriverObject,
                                  0,
                                  &deviceName,
                                  FILE_DEVICE_NETWORK,
                                  FILE_DEVICE_SECURE_OPEN,
                                  FALSE,
                                  &sddlString,
                                  NULL,
                                  &g_Anx.DeviceObject);
    if (!NT_SUCCESS(status)) {
        AnxError("IoCreateDeviceSecure failed 0x%08X\n", status);
        return status;
    }

    g_Anx.DeviceObject->Flags |= DO_BUFFERED_IO;

    RtlInitUnicodeString(&g_Anx.SymlinkName, ANX_NET_SYMLINK_NAME);
    status = IoCreateSymbolicLink(&g_Anx.SymlinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        AnxError("IoCreateSymbolicLink failed 0x%08X\n", status);
        goto CleanupDevice;
    }
    g_Anx.SymlinkCreated = TRUE;

    status = AnxRulesInitialize();
    if (!NT_SUCCESS(status)) {
        goto CleanupSymlink;
    }

    status = AnxEventsInitialize();
    if (!NT_SUCCESS(status)) {
        goto CleanupRules;
    }

    status = AnxPendingInitialize();
    if (!NT_SUCCESS(status)) {
        goto CleanupEvents;
    }

    /*
     * boot-start 适配：WFP 初始化延迟到系统线程。
     * boot-start 驱动的 DriverEntry 在内核 Phase 1 执行，此时 tcpip.sys
     * 和 BFE 尚未加载，FwpsCalloutRegister / FwpmEngineOpen0 必然失败。
     * 系统线程等待网络栈就绪后重试（最多 60 秒）。
     * 设备在 WFP 就绪前即可接受 IOCTL（配置下发、状态查询），
     * 网络过滤功能在 WFP 初始化完成后自动生效。
     * Boot-start adaptation: WFP initialization is deferred to a system
     * thread. The device accepts IOCTLs immediately; network filtering
     * activates once WFP initialization completes.
     */
    g_Anx.DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    {
        HANDLE threadHandle = NULL;
        status = PsCreateSystemThread(&threadHandle, THREAD_ALL_ACCESS,
                                      NULL, NULL, NULL,
                                      AnxWfpInitThread, NULL);
        if (NT_SUCCESS(status)) {
            ZwClose(threadHandle);
            AnxTrace("WFP init thread started (boot-start deferred)\n");
        } else {
            /*
             * 线程创建失败不致命：驱动保持加载，设备可用，
             * 但网络过滤不会生效。记录错误供诊断。
             * Thread creation failure is not fatal: the driver stays
             * loaded and the device is usable, but filtering won't
             * activate. Log for diagnostics.
             */
            AnxError("PsCreateSystemThread(WfpInit) failed 0x%08X\n", status);
        }
    }

    AnxTrace("Loaded (boot-start, WFP pending)\n");
    return STATUS_SUCCESS;

CleanupEvents:
    AnxEventsShutdown();
CleanupRules:
    AnxRulesShutdown();
CleanupSymlink:
    (void)IoDeleteSymbolicLink(&g_Anx.SymlinkName);
    g_Anx.SymlinkCreated = FALSE;
CleanupDevice:
    IoDeleteDevice(g_Anx.DeviceObject);
    g_Anx.DeviceObject = NULL;
    return status;
}
