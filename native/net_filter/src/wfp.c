/*++
Copyright (c) AnXin Security. All rights reserved.

Module Name:
    wfp.c

Abstract:
    WFP 对象生命周期：GUID 定义、引擎会话、提供者与子层、以及 BFE 状态订阅。
    WFP object lifecycle: GUID definitions, the engine session, the provider and
    sublayer, and the BFE state subscription.

    为什么需要订阅 BFE 状态 / Why the BFE subscription is required:
    驱动可能早于基础筛选引擎（BFE）启动。此时 FwpmEngineOpen0 必然失败，
    如果在 DriverEntry 里当成致命错误返回，驱动在开机启动配置下就永远起不来。
    正确做法是：FWPS 侧的 callout 先注册好（不依赖 BFE），FWPM 侧的对象等到
    BFE 就绪的回调里再补上。
    The driver can load before the Base Filtering Engine. FwpmEngineOpen0 is
    guaranteed to fail then, and treating that as fatal in DriverEntry would
    make a boot-start driver never come up. The correct approach: register the
    FWPS-side callouts immediately (they do not need BFE) and add the FWPM-side
    objects from the BFE-ready notification.

Environment:
    Kernel mode only.

--*/

#include "anx_net_internal.h"

/* ==========================================================================
 * GUID 定义 / GUID definitions
 *
 * 这些 GUID 是本产品的持久标识，一旦发布就不得更改：升级版本若换了 GUID，
 * 旧版本残留的 WFP 对象将无人认领，只能重启清理。
 * These GUIDs are the product's durable identity and must never change once
 * shipped: if an upgrade uses new GUIDs, the previous version's WFP objects are
 * orphaned and only a reboot clears them.
 * ========================================================================== */

/* {A7E9C1D4-3F82-4B16-9E5A-2C7D10000001} */
const GUID ANX_NET_PROVIDER_KEY =
    { 0xa7e9c1d4, 0x3f82, 0x4b16, { 0x9e, 0x5a, 0x2c, 0x7d, 0x10, 0x00, 0x00, 0x01 } };
/* {A7E9C1D4-3F82-4B16-9E5A-2C7D10000002} */
const GUID ANX_NET_SUBLAYER_KEY =
    { 0xa7e9c1d4, 0x3f82, 0x4b16, { 0x9e, 0x5a, 0x2c, 0x7d, 0x10, 0x00, 0x00, 0x02 } };

const GUID ANX_NET_CALLOUT_ALE_CONNECT_V4 =
    { 0xa7e9c1d4, 0x3f82, 0x4b16, { 0x9e, 0x5a, 0x2c, 0x7d, 0x10, 0x00, 0x00, 0x10 } };
const GUID ANX_NET_CALLOUT_ALE_CONNECT_V6 =
    { 0xa7e9c1d4, 0x3f82, 0x4b16, { 0x9e, 0x5a, 0x2c, 0x7d, 0x10, 0x00, 0x00, 0x11 } };
const GUID ANX_NET_CALLOUT_ALE_ACCEPT_V4 =
    { 0xa7e9c1d4, 0x3f82, 0x4b16, { 0x9e, 0x5a, 0x2c, 0x7d, 0x10, 0x00, 0x00, 0x12 } };
const GUID ANX_NET_CALLOUT_ALE_ACCEPT_V6 =
    { 0xa7e9c1d4, 0x3f82, 0x4b16, { 0x9e, 0x5a, 0x2c, 0x7d, 0x10, 0x00, 0x00, 0x13 } };
const GUID ANX_NET_CALLOUT_FLOW_V4 =
    { 0xa7e9c1d4, 0x3f82, 0x4b16, { 0x9e, 0x5a, 0x2c, 0x7d, 0x10, 0x00, 0x00, 0x14 } };
const GUID ANX_NET_CALLOUT_FLOW_V6 =
    { 0xa7e9c1d4, 0x3f82, 0x4b16, { 0x9e, 0x5a, 0x2c, 0x7d, 0x10, 0x00, 0x00, 0x15 } };
const GUID ANX_NET_CALLOUT_STREAM_V4 =
    { 0xa7e9c1d4, 0x3f82, 0x4b16, { 0x9e, 0x5a, 0x2c, 0x7d, 0x10, 0x00, 0x00, 0x16 } };
const GUID ANX_NET_CALLOUT_STREAM_V6 =
    { 0xa7e9c1d4, 0x3f82, 0x4b16, { 0x9e, 0x5a, 0x2c, 0x7d, 0x10, 0x00, 0x00, 0x17 } };
const GUID ANX_NET_CALLOUT_DATAGRAM_V4 =
    { 0xa7e9c1d4, 0x3f82, 0x4b16, { 0x9e, 0x5a, 0x2c, 0x7d, 0x10, 0x00, 0x00, 0x18 } };
const GUID ANX_NET_CALLOUT_DATAGRAM_V6 =
    { 0xa7e9c1d4, 0x3f82, 0x4b16, { 0x9e, 0x5a, 0x2c, 0x7d, 0x10, 0x00, 0x00, 0x19 } };

/* ==========================================================================
 * 模块内部状态 / Module-private state
 * ========================================================================== */

static HANDLE  g_BfeSubscription = NULL;
static BOOLEAN g_ObjectsAdded    = FALSE;

static PCWSTR ANX_PROVIDER_NAME = L"AnXin Security Network Filter";
static PCWSTR ANX_SUBLAYER_NAME = L"AnXin Security Network Filter SubLayer";

/*
 * 函数名称：AnxWfpAddObjects
 * 函数作用：打开引擎会话，在一个事务里添加提供者、子层、callout 定义与过滤器。
 * Purpose: Opens the engine session and adds the provider, sublayer, callout
 *          definitions and filters inside a single transaction.
 *
 * 全部对象放在一个事务里：要么整体生效，要么整体回滚，绝不留下「有子层没过滤器」
 * 这类半成品状态。
 * Everything lives in one transaction: either it all takes effect or it all
 * rolls back. A half-built state such as "sublayer but no filters" is never
 * left behind.
 *
 * 调用方：AnxWfpInitialize、BFE 就绪回调
 * Called by: AnxWfpInitialize and the BFE-ready notification
 * IRQL：PASSIVE_LEVEL
 * 中文关键词：引擎会话，事务，提供者，子层
 * English keywords: engine session, transaction, provider, sublayer
 */
static NTSTATUS AnxWfpAddObjects(void)
{
    NTSTATUS              status;
    FWPM_SESSION0         session;
    FWPM_PROVIDER0        provider;
    FWPM_SUBLAYER0        subLayer;
    BOOLEAN               inTransaction = FALSE;

    if (g_ObjectsAdded) {
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&session, sizeof(session));
    /*
     * 不使用 FWPM_SESSION_FLAG_DYNAMIC：动态会话在句柄关闭时自动清理对象，
     * 看似省事，但会让驱动在 BFE 重启后丢失全部过滤器且无法察觉。
     * 这里显式管理生命周期，卸载时自己删干净。
     * FWPM_SESSION_FLAG_DYNAMIC is deliberately not used: a dynamic session
     * discards objects when the handle closes, which silently loses every
     * filter across a BFE restart. Lifetime is managed explicitly instead and
     * cleaned up on unload.
     */
    session.displayData.name = (PWSTR)ANX_PROVIDER_NAME;

    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, &session, &g_Anx.EngineHandle);
    if (!NT_SUCCESS(status)) {
        AnxError("FwpmEngineOpen0 failed 0x%08X\n", status);
        g_Anx.EngineHandle = NULL;
        return status;
    }

    status = FwpmTransactionBegin0(g_Anx.EngineHandle, 0);
    if (!NT_SUCCESS(status)) {
        AnxError("FwpmTransactionBegin0 failed 0x%08X\n", status);
        goto Cleanup;
    }
    inTransaction = TRUE;

    RtlZeroMemory(&provider, sizeof(provider));
    provider.providerKey       = ANX_NET_PROVIDER_KEY;
    provider.displayData.name  = (PWSTR)ANX_PROVIDER_NAME;
    provider.flags             = 0;

    status = FwpmProviderAdd0(g_Anx.EngineHandle, &provider, NULL);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
        AnxError("FwpmProviderAdd0 failed 0x%08X\n", status);
        goto Cleanup;
    }

    RtlZeroMemory(&subLayer, sizeof(subLayer));
    subLayer.subLayerKey      = ANX_NET_SUBLAYER_KEY;
    subLayer.displayData.name = (PWSTR)ANX_SUBLAYER_NAME;
    subLayer.providerKey      = (GUID*)&ANX_NET_PROVIDER_KEY;
    subLayer.flags            = 0;
    subLayer.weight           = ANX_SUBLAYER_WEIGHT;

    status = FwpmSubLayerAdd0(g_Anx.EngineHandle, &subLayer, NULL);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
        AnxError("FwpmSubLayerAdd0 failed 0x%08X\n", status);
        goto Cleanup;
    }
    g_Anx.SubLayerKeySet = 1;

    status = AnxCalloutsAddFilters();
    if (!NT_SUCCESS(status)) {
        AnxError("AnxCalloutsAddFilters failed 0x%08X\n", status);
        goto Cleanup;
    }

    status = FwpmTransactionCommit0(g_Anx.EngineHandle);
    if (!NT_SUCCESS(status)) {
        AnxError("FwpmTransactionCommit0 failed 0x%08X\n", status);
        goto Cleanup;
    }
    inTransaction = FALSE;

    g_ObjectsAdded = TRUE;
    AnxTrace("WFP objects installed (capabilities 0x%08X)\n", g_Anx.Capabilities);
    return STATUS_SUCCESS;

Cleanup:
    if (inTransaction) {
        (void)FwpmTransactionAbort0(g_Anx.EngineHandle);
    }
    if (g_Anx.EngineHandle != NULL) {
        (void)FwpmEngineClose0(g_Anx.EngineHandle);
        g_Anx.EngineHandle = NULL;
    }
    g_Anx.SubLayerKeySet = 0;
    return status;
}

/*
 * BFE 状态变化通知。BFE 起来时补装 WFP 对象，BFE 停止时把句柄清掉。
 * BFE state-change notification: install the WFP objects when it comes up and
 * drop the handle when it stops.
 */
static void NTAPI AnxBfeStateChangeCallback(_In_opt_ void* Context, _In_ FWPM_SERVICE_STATE NewState)
{
    UNREFERENCED_PARAMETER(Context);

    if (AnxIsShuttingDown()) {
        return;
    }

    if (NewState == FWPM_SERVICE_RUNNING) {
        AnxTrace("BFE is running, installing WFP objects\n");
        (void)AnxWfpAddObjects();
    } else if (NewState == FWPM_SERVICE_STOP_PENDING) {
        AnxTrace("BFE is stopping, releasing engine handle\n");
        /*
         * BFE 停止时它会自行销毁我们添加的对象，这里只需要放掉句柄并复位标志，
         * 等它重新启动时再走一遍安装流程。
         * BFE destroys our objects itself when it stops; we only release the
         * handle and reset the flag so installation re-runs when it returns.
         */
        if (g_Anx.EngineHandle != NULL) {
            (void)FwpmEngineClose0(g_Anx.EngineHandle);
            g_Anx.EngineHandle = NULL;
        }
        g_ObjectsAdded = FALSE;
        g_Anx.SubLayerKeySet = 0;
    }
}

/*
 * 函数名称：AnxWfpInitialize
 * 函数作用：注册 callout，并在 BFE 可用时安装 WFP 对象；否则订阅状态等待。
 * Purpose: Registers the callouts and installs the WFP objects if BFE is up,
 *          otherwise subscribes and waits.
 * 调用方：DriverEntry
 * Called by: DriverEntry
 * IRQL：PASSIVE_LEVEL
 * 中文关键词：WFP 初始化，BFE 订阅，延迟安装
 * English keywords: WFP init, BFE subscription, deferred installation
 */
NTSTATUS AnxWfpInitialize(_In_ PDEVICE_OBJECT DeviceObject)
{
    NTSTATUS status;

    /* FWPS 侧的 callout 注册不依赖 BFE，先做 */
    /* FWPS-side callout registration does not need BFE — do it first */
    status = AnxCalloutsRegister(DeviceObject);
    if (!NT_SUCCESS(status)) {
        AnxError("AnxCalloutsRegister failed 0x%08X\n", status);
        return status;
    }

    if (FwpmBfeStateGet0() == FWPM_SERVICE_RUNNING) {
        status = AnxWfpAddObjects();
        if (!NT_SUCCESS(status)) {
            /*
             * 安装失败不回滚 callout 注册：BFE 可能只是暂时性故障，
             * 订阅回调还有机会补装。
             * A failed install does not roll back the callout registration:
             * BFE may be transiently unhealthy and the subscription can retry.
             */
            AnxWarn("Deferred WFP object install after failure 0x%08X\n", status);
        }
    } else {
        AnxTrace("BFE not running yet, deferring WFP object install\n");
    }

    status = FwpmBfeStateSubscribeChanges0(DeviceObject, AnxBfeStateChangeCallback,
                                           NULL, &g_BfeSubscription);
    if (!NT_SUCCESS(status)) {
        AnxError("FwpmBfeStateSubscribeChanges0 failed 0x%08X\n", status);
        g_BfeSubscription = NULL;
        /* 订阅失败不致命：BFE 已在运行时对象已经装好了 */
        /* Not fatal: if BFE was already running the objects are installed */
    }

    return STATUS_SUCCESS;
}

/*
 * 函数名称：AnxWfpShutdown
 * 函数作用：按安全顺序拆除全部 WFP 对象并关闭引擎会话。
 * Purpose: Tears down every WFP object in the safe order and closes the engine.
 *
 * 顺序：取消 BFE 订阅 → 完成所有挂起分类 → 删过滤器/callout → 删子层与提供者
 *      → 关闭引擎。
 * 挂起分类必须先完成，否则 callout 注销会返回 STATUS_DEVICE_BUSY。
 * Order: unsubscribe BFE, complete all pended classifications, delete filters
 * and callouts, delete sublayer and provider, close the engine. Pended
 * classifications must be completed first or callout unregistration returns
 * STATUS_DEVICE_BUSY.
 *
 * 调用方：DriverUnload
 * Called by: DriverUnload
 * IRQL：PASSIVE_LEVEL
 * 中文关键词：拆除顺序，设备忙，引擎关闭
 * English keywords: teardown order, device busy, engine close
 */
void AnxWfpShutdown(void)
{
    if (g_BfeSubscription != NULL) {
        (void)FwpmBfeStateUnsubscribeChanges0(g_BfeSubscription);
        g_BfeSubscription = NULL;
    }

    /* 必须先完成挂起分类，再注销 callout */
    /* Pended classifications must complete before callouts unregister */
    AnxPendingAbortAll(ANX_NET_ACTION_ALLOW);

    AnxCalloutsUnregister();

    if (g_Anx.EngineHandle != NULL) {
        if (g_Anx.SubLayerKeySet != 0) {
            (void)FwpmSubLayerDeleteByKey0(g_Anx.EngineHandle, &ANX_NET_SUBLAYER_KEY);
            g_Anx.SubLayerKeySet = 0;
        }
        (void)FwpmProviderDeleteByKey0(g_Anx.EngineHandle, &ANX_NET_PROVIDER_KEY);
        (void)FwpmEngineClose0(g_Anx.EngineHandle);
        g_Anx.EngineHandle = NULL;
    }

    g_ObjectsAdded = FALSE;
}
