/*++
Copyright (c) AnXin Security. All rights reserved.

Module Name:
    network.c

Abstract:
    AnXinProcMon.sys 网络行为采集（WFP ALE AUTH_CONNECT 只读 callout）。
    Network behavior collection (WFP ALE AUTH_CONNECT read-only callout).

    设计（契约 v6 §4.3）：
    - 只采集不拦截：callout 不调用 FwpsPendClassify0，不修改 classifyOut
      的 actionType（仅读取），返回默认动作（FWP_ACTION_CONTINUE）。
    - v4 / v6 各注册一个 ALE_AUTH_CONNECT callout（独立 GUID），
      与 AnXinNetFilter 的 WFP 防火墙 callout 共存（不同 GUID、不同行为）。
    - 优先级（契约 §3.7 踩坑对策 5）：WFP 同一 layer 的 filter 按 weight
      从高到低评估；若 Block filter（AnXinNetFilter 的 ALE 拦截，action 为
      FWP_ACTION_BLOCK）在 ProcMon 之前评估，分类立即终止，采集 callout
      根本不会被调用，被成功拦截的 C2 连接将无日志。因此 ProcMon 必须：
        1) 使用独立 sublayer，sublayer weight 高于 AnXinNetFilter（0x8000）；
        2) catch-all filter 显式使用远大于自动权重的 weight（FWP_UINT64
           0x0000FFFFFFFFFFFF），确保 ProcMon 先于一切 BLOCK filter 评估。
      只读采集（CALLOUT_INSPECTION）返回 CONTINUE，不影响后续裁决。
    - BFE 订阅：驱动可能早于 BFE 启动，FwpmEngineOpen0 会失败。FWPS 侧
      callout 先注册（不依赖 BFE），FWPM 侧对象在 BFE 就绪回调中补装
      （net_filter 已验证同款模式）。
    - 负载：ANX_PROC_NET_TUPLE（协议、地址族、本地/远端端口与地址）。
    - IRQL：WFP ALE classify 在 DISPATCH_LEVEL 运行；AnxProcPostEvent
      全程自旋锁 + 非分页池，DISPATCH 安全（net_filter 同路径已验证）。
    - 防呆：System PID（4/8）不采集；环回连接由用户态规则决定。

    Design (contract v6 §4.3):
    - Collect-only: never pends, never alters the action, returns the default
      action (FWP_ACTION_CONTINUE).
    - v4 and v6 each get an ALE_AUTH_CONNECT callout with distinct GUIDs,
      coexisting with AnXinNetFilter's WFP callouts.
    - Priority (§3.7 pitfall 5): filters in one layer are evaluated by
      descending weight; if AnXinNetFilter's BLOCK filter runs first the
      classification ends immediately and this collector is never invoked,
      leaving blocked C2 connections unlogged. ProcMon therefore:
        1) uses its own sublayer whose weight exceeds AnXinNetFilter (0x8000);
        2) the catch-all filter carries an explicit weight far above any
           auto-assigned one (FWP_UINT64 0x0000FFFFFFFFFFFF), so it evaluates
           before every BLOCK filter. Collect-only (CALLOUT_INSPECTION) keeps
           returning CONTINUE, never affecting later arbitration.
    - BFE subscription: the driver may load before BFE; FwpmEngineOpen0 then
      fails. FWPS-side callouts register first (no BFE needed) and the FWPM
      objects are installed from the BFE-ready callback (same proven pattern
      as net_filter).
    - Payload: ANX_PROC_NET_TUPLE (protocol, AF, local/remote port & address).
    - IRQL: WFP ALE classify runs at DISPATCH_LEVEL; AnxProcPostEvent uses
      spin locks + non-paged pool only, DISPATCH-safe (same path as net_filter).
    - Fail-safe: System PIDs (4/8) skipped; loopback left to user-mode rules.

Environment:
    Kernel mode only.

--*/

#include "anx_proc_internal.h"

typedef struct _ANX_PROC_NET_CALLOUT {
    PCWSTR      Name;
    GUID        Key;
    UINT32      CalloutId;   /* FwpsCalloutRegister 返回句柄 */
    UINT64      FilterId;    /* FwpmFilterAdd0 返回句柄 */
    BOOLEAN     Registered;  /* FWPS 侧已注册 */
    BOOLEAN     Added;       /* FWPM 侧 callout 定义已添加 */
    BOOLEAN     Filtered;    /* catch-all filter 已添加 */
} ANX_PROC_NET_CALLOUT;

/* ==========================================================================
 * WFP GUID（持久标识，发布后不得更改，同 net_filter 约定）
 * WFP GUIDs (durable identity, never change once shipped — net_filter rule)
 * ========================================================================== */

/* {C6A3E5F0-8B2D-4E1A-9C4F-0D7B2A6E9F01} AnXinProcMon Provider */
static const GUID AnxProcNetProviderGUID = { 0xC6A3E5F0, 0x8B2D, 0x4E1A,
    { 0x9C, 0x4F, 0x0D, 0x7B, 0x2A, 0x6E, 0x9F, 0x01 } };

/* {C6A3E5F0-8B2D-4E1A-9C4F-0D7B2A6E9F02} AnXinProcMon SubLayer */
static const GUID AnxProcNetSubLayerGUID = { 0xC6A3E5F0, 0x8B2D, 0x4E1A,
    { 0x9C, 0x4F, 0x0D, 0x7B, 0x2A, 0x6E, 0x9F, 0x02 } };

/* {C6A3E5F0-8B2D-4E1A-9C4F-0D7B2A6E9F11} AnXinProcNetV4 */
static const GUID AnxProcNetV4GUID = { 0xC6A3E5F0, 0x8B2D, 0x4E1A,
    { 0x9C, 0x4F, 0x0D, 0x7B, 0x2A, 0x6E, 0x9F, 0x11 } };

/* {D6A3E5F0-8B2D-4E1A-9C4F-0D7B2A6E9F22} AnXinProcNetV6 */
static const GUID AnxProcNetV6GUID = { 0xD6A3E5F0, 0x8B2D, 0x4E1A,
    { 0x9C, 0x4F, 0x0D, 0x7B, 0x2A, 0x6E, 0x9F, 0x22 } };

/*
 * sublayer weight 必须高于 AnXinNetFilter 的 ANX_SUBLAYER_WEIGHT(0x8000)。
 * FWPM_SUBLAYER0.weight 是 UINT16（范围 0..0xFFFF），取 0x9000。
 * Sublayer weight must exceed AnXinNetFilter's ANX_SUBLAYER_WEIGHT(0x8000);
 * FWPM_SUBLAYER0.weight is UINT16 (0..0xFFFF), use 0x9000.
 */
#define ANX_PROC_SUBLAYER_WEIGHT   0x9000u

/*
 * catch-all filter 显式权重：远超 WFP 自动分配权重（自动权重源自 sublayer
 * weight，量级通常 <= 0x10000），保证在同一 layer 中先于一切 BLOCK filter
 * 评估（WFP 分类按 filter weight 降序，BLOCK 会立即终止分类）。
 * Explicit filter weight: far above any auto-assigned weight (derived from
 * the sublayer weight), so classification reaches this collector before any
 * BLOCK filter (WFP evaluates by descending filter weight; a BLOCK ends the
 * classification immediately).
 */
static UINT64 AnxProcNetFilterWeight = 0x0000FFFFFFFFFFFFull;

static ANX_PROC_NET_CALLOUT g_NetCallouts[2];
static HANDLE  g_NetEngine = NULL;        /* FwpmEngineOpen0 会话 */
static HANDLE  g_NetBfeSubscription = NULL;
static BOOLEAN g_NetObjectsAdded = FALSE;
static PCWSTR  ANX_PROC_NET_PROVIDER_NAME = L"AnXin Security Process Monitor";
static PCWSTR  ANX_PROC_NET_SUBLAYER_NAME = L"AnXin Security Process Monitor SubLayer";

/*
 * 函数名称：AnxProcNetShouldCollect
 * 函数作用：网络事件采集前置检查（PID 防呆 + 接管状态）。
 * Purpose: Pre-checks for network collection (PID fail-safe + attached state).
 * IRQL：<= DISPATCH_LEVEL
 */
static BOOLEAN AnxProcNetShouldCollect(_In_ UINT32 Pid)
{
    if (Pid == 0 || AnxProcIsSystemPid(Pid)) {
        return FALSE;
    }
    if (AnxProcIsShuttingDown() || !AnxProcIsAttached()) {
        return FALSE;
    }
    return AnxProcIsCollectEnabled();
}

/*
 * 函数名称：AnxProcNetPostConnect
 * 函数作用：构造 ANX_PROC_NET_TUPLE 并投递 NET_CONNECT 事件。
 * Purpose: Builds an ANX_PROC_NET_TUPLE and posts a NET_CONNECT event.
 * IRQL：<= DISPATCH_LEVEL
 */
static void AnxProcNetPostConnect(_In_ UINT16 Protocol, _In_ UINT16 AddressFamily,
                                  _In_ const UINT8* LocalAddr,
                                  _In_ const UINT8* RemoteAddr,
                                  _In_ UINT16 LocalPort, _In_ UINT16 RemotePort,
                                  _In_ ULONG Pid)
{
    ANX_PROC_NET_TUPLE tuple;

    RtlZeroMemory(&tuple, sizeof(tuple));
    tuple.Protocol = Protocol;
    tuple.AddressFamily = AddressFamily;
    tuple.LocalPort = LocalPort;
    tuple.RemotePort = RemotePort;
    if (LocalAddr != NULL) {
        RtlCopyMemory(tuple.LocalAddress, LocalAddr, 16);
    }
    if (RemoteAddr != NULL) {
        RtlCopyMemory(tuple.RemoteAddress, RemoteAddr, 16);
    }

    AnxProcPostEvent(&g_AnxProc.BehaviorQueue, ANX_PROC_EVT_NET_CONNECT,
                     0, Pid, 0, 0, 0, 0, 0, &tuple, sizeof(tuple));
}

/* ==========================================================================
 * callout 分类例程 / Classify routines
 * ========================================================================== */

static VOID AnxProcNetClassifyV4(_In_ const FWPS_INCOMING_VALUES0* InFixedValues,
                                 _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
                                 _Inout_opt_ void* LayerData,
                                 _In_opt_ const void* ClassifyContext,
                                 _In_ const FWPS_FILTER3* Filter,
                                 _In_ UINT64 FlowContext,
                                 _Inout_ FWPS_CLASSIFY_OUT0* ClassifyOut)
{
    UINT16 protocol = 0;
    UINT16 localPort = 0;
    UINT16 remotePort = 0;
    UINT8  localAddr[16] = { 0 };
    UINT8  remoteAddr[16] = { 0 };
    UINT32 pid = 0;

    UNREFERENCED_PARAMETER(LayerData);
    UNREFERENCED_PARAMETER(ClassifyContext);
    UNREFERENCED_PARAMETER(Filter);
    UNREFERENCED_PARAMETER(FlowContext);

    if (ClassifyOut == NULL || InFixedValues == NULL) {
        return;
    }

    /* 只观察不阻断：沿用默认动作 */
    ClassifyOut->actionType = FWP_ACTION_CONTINUE;

    if (InMetaValues != NULL &&
        (InMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID)) {
        pid = (UINT32)InMetaValues->processId;
    }
    if (!AnxProcNetShouldCollect(pid)) {
        return;
    }

    protocol = (UINT16)InFixedValues->
        incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL].value.uint8;
    localPort = (UINT16)InFixedValues->
        incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT].value.uint16;
    remotePort = (UINT16)InFixedValues->
        incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16;
    RtlCopyMemory(localAddr,
                  &InFixedValues->
                      incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS].value.uint32,
                  4);
    RtlCopyMemory(remoteAddr,
                  &InFixedValues->
                      incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32,
                  4);

    AnxProcNetPostConnect(protocol, 4, localAddr, remoteAddr,
                          localPort, remotePort, pid);
}

static VOID AnxProcNetClassifyV6(_In_ const FWPS_INCOMING_VALUES0* InFixedValues,
                                 _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
                                 _Inout_opt_ void* LayerData,
                                 _In_opt_ const void* ClassifyContext,
                                 _In_ const FWPS_FILTER3* Filter,
                                 _In_ UINT64 FlowContext,
                                 _Inout_ FWPS_CLASSIFY_OUT0* ClassifyOut)
{
    UINT16 protocol = 0;
    UINT16 localPort = 0;
    UINT16 remotePort = 0;
    UINT8  localAddr[16] = { 0 };
    UINT8  remoteAddr[16] = { 0 };
    UINT32 pid = 0;

    UNREFERENCED_PARAMETER(LayerData);
    UNREFERENCED_PARAMETER(ClassifyContext);
    UNREFERENCED_PARAMETER(Filter);
    UNREFERENCED_PARAMETER(FlowContext);

    if (ClassifyOut == NULL || InFixedValues == NULL) {
        return;
    }

    ClassifyOut->actionType = FWP_ACTION_CONTINUE;

    if (InMetaValues != NULL &&
        (InMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID)) {
        pid = (UINT32)InMetaValues->processId;
    }
    if (!AnxProcNetShouldCollect(pid)) {
        return;
    }

    protocol = (UINT16)InFixedValues->
        incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL].value.uint8;
    localPort = (UINT16)InFixedValues->
        incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_PORT].value.uint16;
    remotePort = (UINT16)InFixedValues->
        incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT].value.uint16;
    RtlCopyMemory(localAddr,
                  InFixedValues->
                      incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_ADDRESS].value.byteArray16,
                  16);
    RtlCopyMemory(remoteAddr,
                  InFixedValues->
                      incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS].value.byteArray16,
                  16);

    AnxProcNetPostConnect(protocol, 6, localAddr, remoteAddr,
                          localPort, remotePort, pid);
}

/* ==========================================================================
 * Flow 通知例程（未使用，仅占位满足 callout 定义）
 * Flow notification routines (unused; required by the callout definition)
 * ========================================================================== */

static NTSTATUS NTAPI AnxProcNetNotify(_In_ FWPS_CALLOUT_NOTIFY_TYPE NotifyType,
                                       _In_ const GUID* FilterKey,
                                       _Inout_ FWPS_FILTER3* Filter)
{
    UNREFERENCED_PARAMETER(NotifyType);
    UNREFERENCED_PARAMETER(FilterKey);
    UNREFERENCED_PARAMETER(Filter);
    return STATUS_SUCCESS;
}

/*
 * 函数名称：AnxProcNetAddFilters
 * 函数作用：为每个 callout 添加一个无条件的 catch-all filter，权重显式
 *          指定且远高于 AnXinNetFilter 的自动权重，保证先于 BLOCK 评估。
 * Purpose: Adds one condition-less catch-all filter per callout with an
 *          explicit weight far above AnXinNetFilter's auto weight, so the
 *          collector evaluates before any BLOCK.
 * IRQL：PASSIVE_LEVEL
 */
static NTSTATUS AnxProcNetAddFilters(void)
{
    NTSTATUS status = STATUS_SUCCESS;
    UINT32   i;
    UINT32   added = 0;

    for (i = 0; i < 2; i++) {
        FWPM_CALLOUT0 mCallout;
        FWPM_FILTER0  filter;
        WCHAR         nameBuffer[64];

        if (!g_NetCallouts[i].Registered) {
            continue;
        }

        RtlZeroMemory(&mCallout, sizeof(mCallout));
        mCallout.calloutKey       = g_NetCallouts[i].Key;
        mCallout.displayData.name = (PWSTR)g_NetCallouts[i].Name;
        mCallout.applicableLayer  = (i == 0) ? FWPM_LAYER_ALE_AUTH_CONNECT_V4
                                             : FWPM_LAYER_ALE_AUTH_CONNECT_V6;
        mCallout.flags            = 0;

        status = FwpmCalloutAdd0(g_NetEngine, &mCallout, NULL, NULL);
        if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
            AnxProcError("FwpmCalloutAdd0(%ws) failed 0x%08X\n",
                         g_NetCallouts[i].Name, status);
            continue;
        }
        g_NetCallouts[i].Added = TRUE;

        RtlStringCchPrintfW(nameBuffer, RTL_NUMBER_OF(nameBuffer), L"%ws Filter",
                            g_NetCallouts[i].Name);

        RtlZeroMemory(&filter, sizeof(filter));
        filter.displayData.name  = nameBuffer;
        filter.layerKey          = mCallout.applicableLayer;
        filter.subLayerKey       = AnxProcNetSubLayerGUID;
        /* 显式高权重：先于 AnXinNetFilter 的一切自动权重 filter 评估 */
        filter.weight.type       = FWP_UINT64;
        filter.weight.uint64     = &AnxProcNetFilterWeight;
        filter.numFilterConditions = 0;
        filter.filterCondition   = NULL;
        filter.action.type       = FWP_ACTION_CALLOUT_INSPECTION;
        filter.action.calloutKey = g_NetCallouts[i].Key;

        status = FwpmFilterAdd0(g_NetEngine, &filter, NULL,
                                &g_NetCallouts[i].FilterId);
        if (!NT_SUCCESS(status)) {
            AnxProcError("FwpmFilterAdd0(%ws) failed 0x%08X\n",
                         g_NetCallouts[i].Name, status);
            continue;
        }
        g_NetCallouts[i].Filtered = TRUE;
        added++;
    }

    return (added > 0) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

/*
 * 函数名称：AnxProcNetAddObjects
 * 函数作用：打开引擎会话，在一个事务里添加 provider、sublayer、callout
 *          定义与 catch-all filter。
 * Purpose: Opens the engine session and adds the provider, sublayer, callout
 *          definitions and catch-all filters in one transaction.
 * IRQL：PASSIVE_LEVEL
 */
static NTSTATUS AnxProcNetAddObjects(void)
{
    NTSTATUS        status;
    FWPM_SESSION0   session;
    FWPM_PROVIDER0  provider;
    FWPM_SUBLAYER0  subLayer;
    BOOLEAN         inTransaction = FALSE;

    if (g_NetObjectsAdded) {
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&session, sizeof(session));
    /* 不用 FWPM_SESSION_FLAG_DYNAMIC：句柄关闭即丢对象，BFE 重启后过滤器
       静默消失且无法察觉；生命周期显式管理（net_filter 同决策）。 */
    session.displayData.name = (PWSTR)ANX_PROC_NET_PROVIDER_NAME;

    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, &session,
                             &g_NetEngine);
    if (!NT_SUCCESS(status)) {
        AnxProcError("FwpmEngineOpen0 failed 0x%08X\n", status);
        g_NetEngine = NULL;
        return status;
    }

    status = FwpmTransactionBegin0(g_NetEngine, 0);
    if (!NT_SUCCESS(status)) {
        AnxProcError("FwpmTransactionBegin0 failed 0x%08X\n", status);
        goto Cleanup;
    }
    inTransaction = TRUE;

    RtlZeroMemory(&provider, sizeof(provider));
    provider.providerKey       = AnxProcNetProviderGUID;
    provider.displayData.name  = (PWSTR)ANX_PROC_NET_PROVIDER_NAME;
    provider.flags             = 0;

    status = FwpmProviderAdd0(g_NetEngine, &provider, NULL);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
        AnxProcError("FwpmProviderAdd0 failed 0x%08X\n", status);
        goto Cleanup;
    }

    RtlZeroMemory(&subLayer, sizeof(subLayer));
    subLayer.subLayerKey      = AnxProcNetSubLayerGUID;
    subLayer.displayData.name = (PWSTR)ANX_PROC_NET_SUBLAYER_NAME;
    subLayer.providerKey      = (GUID*)&AnxProcNetProviderGUID;
    subLayer.flags            = 0;
    subLayer.weight           = ANX_PROC_SUBLAYER_WEIGHT;

    status = FwpmSubLayerAdd0(g_NetEngine, &subLayer, NULL);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
        AnxProcError("FwpmSubLayerAdd0 failed 0x%08X\n", status);
        goto Cleanup;
    }

    status = AnxProcNetAddFilters();
    if (!NT_SUCCESS(status)) {
        AnxProcError("AnxProcNetAddFilters failed 0x%08X\n", status);
        goto Cleanup;
    }

    status = FwpmTransactionCommit0(g_NetEngine);
    if (!NT_SUCCESS(status)) {
        AnxProcError("FwpmTransactionCommit0 failed 0x%08X\n", status);
        goto Cleanup;
    }
    inTransaction = FALSE;

    g_NetObjectsAdded = TRUE;
    AnxProcTrace("WFP provider/sublayer/filters installed\n");
    return STATUS_SUCCESS;

Cleanup:
    if (inTransaction) {
        (void)FwpmTransactionAbort0(g_NetEngine);
    }
    if (g_NetEngine != NULL) {
        (void)FwpmEngineClose0(g_NetEngine);
        g_NetEngine = NULL;
    }
    return status;
}

/*
 * BFE 状态变化通知：BFE 起来时补装 WFP 对象，停止时释放句柄并复位标志。
 * BFE state-change notification: install WFP objects on RUNNING, release the
 * handle and reset flags on STOP_PENDING.
 */
static void NTAPI AnxProcNetBfeStateChangeCallback(_In_opt_ void* Context,
                                                   _In_ FWPM_SERVICE_STATE NewState)
{
    UNREFERENCED_PARAMETER(Context);

    if (AnxProcIsShuttingDown()) {
        return;
    }

    if (NewState == FWPM_SERVICE_RUNNING) {
        AnxProcTrace("BFE running, installing WFP objects\n");
        (void)AnxProcNetAddObjects();
    } else if (NewState == FWPM_SERVICE_STOP_PENDING) {
        AnxProcTrace("BFE stopping, releasing engine handle\n");
        if (g_NetEngine != NULL) {
            (void)FwpmEngineClose0(g_NetEngine);
            g_NetEngine = NULL;
        }
        g_NetObjectsAdded = FALSE;
    }
}

/* ==========================================================================
 * 初始化 / Initialization
 * ========================================================================== */

/*
 * 函数名称：AnxProcNetworkInitialize
 * 函数作用：注册 v4/v6 ALE_AUTH_CONNECT 采集 callout（只读），并在 BFE
 *          可用时安装 FWPM 对象；否则订阅 BFE 状态等待补装。
 * Purpose: Registers the v4/v6 ALE_AUTH_CONNECT collect-only callouts and
 *          installs FWPM objects if BFE is up, else subscribes and waits.
 * IRQL：PASSIVE_LEVEL
 */
NTSTATUS AnxProcNetworkInitialize(_In_ PDEVICE_OBJECT DeviceObject)
{
    FWPS_CALLOUT callout;
    NTSTATUS     status;
    ULONG        i;

    g_NetCallouts[0].Name = L"AnXinProcNetV4";
    g_NetCallouts[0].Key = AnxProcNetV4GUID;
    g_NetCallouts[1].Name = L"AnXinProcNetV6";
    g_NetCallouts[1].Key = AnxProcNetV6GUID;

    /* FWPS 侧 callout 注册不依赖 BFE，先做 */
    for (i = 0; i < 2; i++) {
        RtlZeroMemory(&callout, sizeof(callout));
        callout.calloutKey = g_NetCallouts[i].Key;
        callout.flags = 0;
        callout.classifyFn = (i == 0) ? AnxProcNetClassifyV4 : AnxProcNetClassifyV6;
        callout.notifyFn = AnxProcNetNotify;
        callout.flowDeleteFn = NULL;

        status = FwpsCalloutRegister((void*)DeviceObject, &callout,
                                     &g_NetCallouts[i].CalloutId);
        if (!NT_SUCCESS(status)) {
            AnxProcError("FwpsCalloutRegister(%ws) failed 0x%08X\n",
                         g_NetCallouts[i].Name, status);
            /* 回滚已注册的 v4 */
            if (i == 1 && g_NetCallouts[0].Registered) {
                FwpsCalloutUnregisterById0(g_NetCallouts[0].CalloutId);
                g_NetCallouts[0].Registered = FALSE;
            }
            return status;
        }
        g_NetCallouts[i].Registered = TRUE;
        AnxProcTrace("WFP callout %ws id %lu\n",
                     g_NetCallouts[i].Name, g_NetCallouts[i].CalloutId);
    }

    if (FwpmBfeStateGet0() == FWPM_SERVICE_RUNNING) {
        status = AnxProcNetAddObjects();
        if (!NT_SUCCESS(status)) {
            /* 安装失败不回滚 callout 注册：BFE 可能暂时性故障，订阅回调
               还有机会补装（net_filter 同策略）。 */
            AnxProcWarn("Deferred WFP object install after failure 0x%08X\n",
                        status);
        }
    } else {
        AnxProcTrace("BFE not running yet, deferring WFP object install\n");
    }

    status = FwpmBfeStateSubscribeChanges0(DeviceObject,
                                           AnxProcNetBfeStateChangeCallback,
                                           NULL, &g_NetBfeSubscription);
    if (!NT_SUCCESS(status)) {
        AnxProcError("FwpmBfeStateSubscribeChanges0 failed 0x%08X\n", status);
        g_NetBfeSubscription = NULL;
        /* 订阅失败不致命：BFE 已在运行时对象已经装好了 */
    }

    return STATUS_SUCCESS;
}

/*
 * 函数名称：AnxProcNetworkShutdown
 * 函数作用：按安全顺序拆除全部 WFP 对象并关闭引擎会话。
 * Purpose: Tears down every WFP object in the safe order and closes the engine.
 *
 * 顺序：取消 BFE 订阅 → 删 filter → 删 callout 定义 → 注销 FWPS callout
 *      → 删 sublayer 与 provider → 关闭引擎。
 * Order: unsubscribe BFE, delete filters, remove callout definitions,
 * unregister FWPS callouts, delete sublayer and provider, close the engine.
 *
 * IRQL：PASSIVE_LEVEL
 */
void AnxProcNetworkShutdown(void)
{
    UINT32   i;
    NTSTATUS status;

    if (g_NetBfeSubscription != NULL) {
        (void)FwpmBfeStateUnsubscribeChanges0(g_NetBfeSubscription);
        g_NetBfeSubscription = NULL;
    }

    /* 1. 删 filter / delete filters first */
    for (i = 0; i < 2; i++) {
        if (g_NetCallouts[i].Filtered && g_NetEngine != NULL) {
            (void)FwpmFilterDeleteById0(g_NetEngine, g_NetCallouts[i].FilterId);
            g_NetCallouts[i].Filtered = FALSE;
        }
    }

    /* 2. 删 callout 定义 / then remove the callout definitions */
    for (i = 0; i < 2; i++) {
        if (g_NetCallouts[i].Added && g_NetEngine != NULL) {
            (void)FwpmCalloutDeleteByKey0(g_NetEngine, &g_NetCallouts[i].Key);
            g_NetCallouts[i].Added = FALSE;
        }
    }

    /* 3. 注销 FWPS callout / finally unregister the callouts */
    for (i = 0; i < 2; i++) {
        if (g_NetCallouts[i].Registered) {
            status = FwpsCalloutUnregisterById0(g_NetCallouts[i].CalloutId);
            if (!NT_SUCCESS(status)) {
                AnxProcError("FwpsCalloutUnregisterById0(%ws) failed 0x%08X\n",
                             g_NetCallouts[i].Name, status);
            }
            g_NetCallouts[i].Registered = FALSE;
        }
    }

    /* 4. 删 sublayer / provider，关引擎 */
    if (g_NetEngine != NULL) {
        (void)FwpmSubLayerDeleteByKey0(g_NetEngine, &AnxProcNetSubLayerGUID);
        (void)FwpmProviderDeleteByKey0(g_NetEngine, &AnxProcNetProviderGUID);
        (void)FwpmEngineClose0(g_NetEngine);
        g_NetEngine = NULL;
    }

    g_NetObjectsAdded = FALSE;
}
