/*++
Copyright (c) AnXin Security. All rights reserved.

Module Name:
    callouts.c

Abstract:
    WFP callout 分类回调集合。
    The set of WFP callout classify callbacks.

    分层职责 / Layer responsibilities:
      ALE_AUTH_CONNECT_V4/V6      出站连接放行/拦截/挂起询问
                                  outbound connect: permit / block / pend-and-ask
      ALE_AUTH_RECV_ACCEPT_V4/V6  入站接受放行/拦截
                                  inbound accept: permit / block
      ALE_FLOW_ESTABLISHED_V4/V6  建流时挂上下文，供统计与内容检查使用
                                  attach a flow context for stats and inspection
      STREAM_V4/V6                TLS SNI 与明文 HTTP Host 提取、限速、字节统计
                                  TLS SNI / HTTP Host extraction, shaping, bytes
      DATAGRAM_DATA_V4/V6         DNS 查询名提取与域名管控
                                  DNS query-name extraction and domain control

    通用纪律 / Universal discipline:
    - 任何异常路径一律放行（fail-open）。安全软件让机器断网，比放过一条连接
      严重得多。
      Every abnormal path permits (fail-open). A security product that cuts the
      machine off the network is far worse than one that misses a connection.
    - 用户态未接管（服务未启动或已崩溃）时全部放行。
      While user mode is not attached (service not started, or crashed) we
      permit everything.
    - 不持锁调用 WFP、不在 DISPATCH_LEVEL 上做分页访问、不阻塞。
      Never call into WFP while holding a lock, never touch paged memory at
      DISPATCH_LEVEL, never block.

Environment:
    Kernel mode only.

--*/

#include "anx_net_internal.h"

/* ==========================================================================
 * GUID（定义在 wfp.c，此处引用） / GUIDs (defined in wfp.c)
 * ========================================================================== */

extern const GUID ANX_NET_CALLOUT_ALE_CONNECT_V4;
extern const GUID ANX_NET_CALLOUT_ALE_CONNECT_V6;
extern const GUID ANX_NET_CALLOUT_ALE_ACCEPT_V4;
extern const GUID ANX_NET_CALLOUT_ALE_ACCEPT_V6;
extern const GUID ANX_NET_CALLOUT_FLOW_V4;
extern const GUID ANX_NET_CALLOUT_FLOW_V6;
extern const GUID ANX_NET_CALLOUT_STREAM_V4;
extern const GUID ANX_NET_CALLOUT_STREAM_V6;
extern const GUID ANX_NET_CALLOUT_DATAGRAM_V4;
extern const GUID ANX_NET_CALLOUT_DATAGRAM_V6;
extern const GUID ANX_NET_SUBLAYER_KEY;

/* ==========================================================================
 * callout 注册表 / Callout registry
 * ========================================================================== */

typedef struct _ANX_CALLOUT_DEF {
    const GUID*                          CalloutKey;
    const GUID*                          LayerKey;
    PCWSTR                               Name;
    FWPS_CALLOUT_CLASSIFY_FN3            ClassifyFn;
    FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN0  FlowDeleteFn;
    UINT32                               CapabilityBit;
    BOOLEAN                              Terminating;
    /* --- 运行期填充 / filled at runtime --- */
    UINT32                               CalloutId;
    UINT64                               FilterId;
    BOOLEAN                              Registered;
    BOOLEAN                              Added;
    BOOLEAN                              Filtered;
} ANX_CALLOUT_DEF, *PANX_CALLOUT_DEF;

/* 分类回调前置声明 / classify callback forward declarations */
static void NTAPI AnxAleConnectClassify(
    _In_ const FWPS_INCOMING_VALUES0*,
    _In_ const FWPS_INCOMING_METADATA_VALUES0*,
    _Inout_opt_ void*,
    _In_opt_ const void*,
    _In_ const FWPS_FILTER3*,
    _In_ UINT64,
    _Inout_ FWPS_CLASSIFY_OUT0*);
static void NTAPI AnxAleAcceptClassify(
    _In_ const FWPS_INCOMING_VALUES0*,
    _In_ const FWPS_INCOMING_METADATA_VALUES0*,
    _Inout_opt_ void*,
    _In_opt_ const void*,
    _In_ const FWPS_FILTER3*,
    _In_ UINT64,
    _Inout_ FWPS_CLASSIFY_OUT0*);
static void NTAPI AnxFlowEstablishedClassify(
    _In_ const FWPS_INCOMING_VALUES0*,
    _In_ const FWPS_INCOMING_METADATA_VALUES0*,
    _Inout_opt_ void*,
    _In_opt_ const void*,
    _In_ const FWPS_FILTER3*,
    _In_ UINT64,
    _Inout_ FWPS_CLASSIFY_OUT0*);
static void NTAPI AnxStreamClassify(
    _In_ const FWPS_INCOMING_VALUES0*,
    _In_ const FWPS_INCOMING_METADATA_VALUES0*,
    _Inout_opt_ void*,
    _In_opt_ const void*,
    _In_ const FWPS_FILTER3*,
    _In_ UINT64,
    _Inout_ FWPS_CLASSIFY_OUT0*);
static void NTAPI AnxDatagramClassify(
    _In_ const FWPS_INCOMING_VALUES0*,
    _In_ const FWPS_INCOMING_METADATA_VALUES0*,
    _Inout_opt_ void*,
    _In_opt_ const void*,
    _In_ const FWPS_FILTER3*,
    _In_ UINT64,
    _Inout_ FWPS_CLASSIFY_OUT0*);
static NTSTATUS NTAPI AnxCalloutNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE,
    _In_ const GUID*,
    _Inout_ FWPS_FILTER3*);
static void NTAPI AnxFlowDelete(_In_ UINT16, _In_ UINT32, _In_ UINT64);

static ANX_CALLOUT_DEF g_Callouts[] = {
    { &ANX_NET_CALLOUT_ALE_CONNECT_V4, &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
      L"AnXin ALE Connect v4", AnxAleConnectClassify, NULL,
      ANX_NET_CAP_ALE_V4, TRUE, 0, 0, FALSE, FALSE, FALSE },

    { &ANX_NET_CALLOUT_ALE_CONNECT_V6, &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
      L"AnXin ALE Connect v6", AnxAleConnectClassify, NULL,
      ANX_NET_CAP_ALE_V6, TRUE, 0, 0, FALSE, FALSE, FALSE },

    { &ANX_NET_CALLOUT_ALE_ACCEPT_V4, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
      L"AnXin ALE Accept v4", AnxAleAcceptClassify, NULL,
      ANX_NET_CAP_ALE_V4, TRUE, 0, 0, FALSE, FALSE, FALSE },

    { &ANX_NET_CALLOUT_ALE_ACCEPT_V6, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
      L"AnXin ALE Accept v6", AnxAleAcceptClassify, NULL,
      ANX_NET_CAP_ALE_V6, TRUE, 0, 0, FALSE, FALSE, FALSE },

    { &ANX_NET_CALLOUT_FLOW_V4, &FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4,
      L"AnXin Flow Established v4", AnxFlowEstablishedClassify, NULL,
      ANX_NET_CAP_FLOW_STATS, FALSE, 0, 0, FALSE, FALSE, FALSE },

    { &ANX_NET_CALLOUT_FLOW_V6, &FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6,
      L"AnXin Flow Established v6", AnxFlowEstablishedClassify, NULL,
      ANX_NET_CAP_FLOW_STATS, FALSE, 0, 0, FALSE, FALSE, FALSE },

    { &ANX_NET_CALLOUT_STREAM_V4, &FWPM_LAYER_STREAM_V4,
      L"AnXin Stream v4", AnxStreamClassify, AnxFlowDelete,
      ANX_NET_CAP_STREAM, TRUE, 0, 0, FALSE, FALSE, FALSE },

    { &ANX_NET_CALLOUT_STREAM_V6, &FWPM_LAYER_STREAM_V6,
      L"AnXin Stream v6", AnxStreamClassify, AnxFlowDelete,
      ANX_NET_CAP_STREAM, TRUE, 0, 0, FALSE, FALSE, FALSE },

    { &ANX_NET_CALLOUT_DATAGRAM_V4, &FWPM_LAYER_DATAGRAM_DATA_V4,
      L"AnXin Datagram v4", AnxDatagramClassify, AnxFlowDelete,
      ANX_NET_CAP_DATAGRAM, TRUE, 0, 0, FALSE, FALSE, FALSE },

    { &ANX_NET_CALLOUT_DATAGRAM_V6, &FWPM_LAYER_DATAGRAM_DATA_V6,
      L"AnXin Datagram v6", AnxDatagramClassify, AnxFlowDelete,
      ANX_NET_CAP_DATAGRAM, TRUE, 0, 0, FALSE, FALSE, FALSE },
};

#define ANX_CALLOUT_COUNT  RTL_NUMBER_OF(g_Callouts)

/* ==========================================================================
 * 地址与字段提取辅助 / Address and field extraction helpers
 * ========================================================================== */

static FORCEINLINE void AnxAddrFromV4(_Out_ ANX_NET_ADDR* Out, _In_ UINT32 HostOrder)
{
    RtlZeroMemory(Out, sizeof(*Out));
    Out->Family   = ANX_NET_AF_INET;
    /* WFP 在 v4 层给出的是主机字节序整数，转回网络字节序存放 */
    /* WFP hands out a host-order integer at v4 layers; store network order */
    Out->Bytes[0] = (UINT8)((HostOrder >> 24) & 0xFF);
    Out->Bytes[1] = (UINT8)((HostOrder >> 16) & 0xFF);
    Out->Bytes[2] = (UINT8)((HostOrder >> 8) & 0xFF);
    Out->Bytes[3] = (UINT8)(HostOrder & 0xFF);
}

static FORCEINLINE void AnxAddrFromV6(_Out_ ANX_NET_ADDR* Out, _In_reads_bytes_(16) const UINT8* Bytes)
{
    RtlZeroMemory(Out, sizeof(*Out));
    Out->Family = ANX_NET_AF_INET6;
    RtlCopyMemory(Out->Bytes, Bytes, 16);
}

/*
 * 从 ALE 层的固定字段中提取连接信息。
 * 每个 ALE 层的字段下标不同，因此按 layerId 分派。
 * Extracts connection info from the ALE fixed values. Field indices differ per
 * layer, so we dispatch on layerId.
 */
static BOOLEAN AnxExtractAleConn(_In_ const FWPS_INCOMING_VALUES0* InFixedValues,
                                 _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
                                 _In_ UINT32 Direction,
                                 _Out_ ANX_CONN_INFO* Conn)
{
    UINT32 localAddrIdx;
    UINT32 remoteAddrIdx;
    UINT32 localPortIdx;
    UINT32 remotePortIdx;
    UINT32 protocolIdx;
    UINT32 flagsIdx;
    UINT32 appIdIdx;
    BOOLEAN isV6;
    UINT32 conditionFlags = 0;

    RtlZeroMemory(Conn, sizeof(*Conn));

    switch (InFixedValues->layerId) {
    case FWPS_LAYER_ALE_AUTH_CONNECT_V4:
        localAddrIdx  = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS;
        remoteAddrIdx = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS;
        localPortIdx  = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT;
        remotePortIdx = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT;
        protocolIdx   = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL;
        flagsIdx      = FWPS_FIELD_ALE_AUTH_CONNECT_V4_FLAGS;
        appIdIdx      = FWPS_FIELD_ALE_AUTH_CONNECT_V4_ALE_APP_ID;
        isV6 = FALSE;
        break;

    case FWPS_LAYER_ALE_AUTH_CONNECT_V6:
        localAddrIdx  = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_ADDRESS;
        remoteAddrIdx = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS;
        localPortIdx  = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_PORT;
        remotePortIdx = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT;
        protocolIdx   = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL;
        flagsIdx      = FWPS_FIELD_ALE_AUTH_CONNECT_V6_FLAGS;
        appIdIdx      = FWPS_FIELD_ALE_AUTH_CONNECT_V6_ALE_APP_ID;
        isV6 = TRUE;
        break;

    case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4:
        localAddrIdx  = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_ADDRESS;
        remoteAddrIdx = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS;
        localPortIdx  = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT;
        remotePortIdx = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT;
        protocolIdx   = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL;
        flagsIdx      = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_FLAGS;
        appIdIdx      = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_ALE_APP_ID;
        isV6 = FALSE;
        break;

    case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6:
        localAddrIdx  = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_ADDRESS;
        remoteAddrIdx = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_ADDRESS;
        localPortIdx  = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_PORT;
        remotePortIdx = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_PORT;
        protocolIdx   = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_PROTOCOL;
        flagsIdx      = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_FLAGS;
        appIdIdx      = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_ALE_APP_ID;
        isV6 = TRUE;
        break;

    default:
        return FALSE;
    }

    if (InFixedValues->valueCount <= appIdIdx) {
        return FALSE;
    }

    if (isV6) {
        AnxAddrFromV6(&Conn->LocalAddr,
                      InFixedValues->incomingValue[localAddrIdx].value.byteArray16->byteArray16);
        AnxAddrFromV6(&Conn->RemoteAddr,
                      InFixedValues->incomingValue[remoteAddrIdx].value.byteArray16->byteArray16);
    } else {
        AnxAddrFromV4(&Conn->LocalAddr,
                      InFixedValues->incomingValue[localAddrIdx].value.uint32);
        AnxAddrFromV4(&Conn->RemoteAddr,
                      InFixedValues->incomingValue[remoteAddrIdx].value.uint32);
    }

    Conn->LocalPort  = InFixedValues->incomingValue[localPortIdx].value.uint16;
    Conn->RemotePort = InFixedValues->incomingValue[remotePortIdx].value.uint16;
    Conn->Protocol   = InFixedValues->incomingValue[protocolIdx].value.uint8;
    Conn->Direction  = Direction;

    conditionFlags = InFixedValues->incomingValue[flagsIdx].value.uint32;
    Conn->IsLoopback = (BOOLEAN)((conditionFlags & FWP_CONDITION_FLAG_IS_LOOPBACK) != 0);
    Conn->IsReauthorize = (BOOLEAN)((conditionFlags & FWP_CONDITION_FLAG_IS_REAUTHORIZE) != 0);

    if (!Conn->IsLoopback) {
        Conn->IsLoopback = AnxAddrIsLoopback(&Conn->RemoteAddr);
    }

    /* 应用标识：优先用 ALE_APP_ID，元数据里的进程路径作为展示用途 */
    /* App identity: ALE_APP_ID drives matching; the metadata path is for display */
    if (InFixedValues->incomingValue[appIdIdx].value.byteBlob != NULL) {
        const FWP_BYTE_BLOB* blob = InFixedValues->incomingValue[appIdIdx].value.byteBlob;
        if (blob->data != NULL && blob->size >= sizeof(WCHAR)) {
            Conn->AppIdHash = AnxHashAppIdBytes(blob->data, blob->size);
            AnxCopyPathToBuffer(Conn->ImagePath, ANX_NET_MAX_PATH,
                                (PCWSTR)blob->data, blob->size / sizeof(WCHAR));
        }
    }

    if (FWPS_IS_METADATA_FIELD_PRESENT(InMetaValues, FWPS_METADATA_FIELD_PROCESS_ID)) {
        Conn->ProcessId = (UINT32)InMetaValues->processId;
    }

    if (Conn->ImagePath[0] == L'\0' &&
        FWPS_IS_METADATA_FIELD_PRESENT(InMetaValues, FWPS_METADATA_FIELD_PROCESS_PATH) &&
        InMetaValues->processPath != NULL &&
        InMetaValues->processPath->data != NULL &&
        InMetaValues->processPath->size >= sizeof(WCHAR)) {
        AnxCopyPathToBuffer(Conn->ImagePath, ANX_NET_MAX_PATH,
                            (PCWSTR)InMetaValues->processPath->data,
                            InMetaValues->processPath->size / sizeof(WCHAR));
        if (Conn->AppIdHash == 0) {
            Conn->AppIdHash = AnxHashAppIdBytes(InMetaValues->processPath->data,
                                                InMetaValues->processPath->size);
        }
    }

    return TRUE;
}

/* 把最终动作写进 classifyOut / Writes the terminal action into classifyOut */
static FORCEINLINE void AnxApplyAction(_Inout_ FWPS_CLASSIFY_OUT0* ClassifyOut, _In_ UINT32 Action)
{
    if (Action == ANX_NET_ACTION_BLOCK) {
        ClassifyOut->actionType = FWP_ACTION_BLOCK;
        ClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    } else {
        ClassifyOut->actionType = FWP_ACTION_PERMIT;
    }
}

/* ==========================================================================
 * ALE 连接级分类 / ALE connection-level classification
 * ========================================================================== */

/*
 * 函数名称：AnxAleClassifyCommon
 * 函数作用：出站 connect 与入站 accept 共用的裁决主流程。
 * Purpose: The shared verdict pipeline for outbound connect and inbound accept.
 *
 * 裁决优先级 / Verdict precedence:
 *   1. 旁路条件（关闭 / 未接管 / 卸载中 / 自身进程 / 回环）→ 放行
 *      Bypass conditions (disabled / detached / unloading / self / loopback)
 *   2. 裁决缓存命中 → 直接采用
 *      Verdict cache hit
 *   3. 规则表首个命中 → 采用；命中 PROMPT 则进入第 4 步
 *      First matching rule; a PROMPT verdict falls through to step 4
 *   4. PROMPT 模式且可挂起 → FwpsPendClassify0 等用户裁决
 *      In PROMPT mode, pend via FwpsPendClassify0 and await the user
 *   5. 兜底默认动作
 *      Fall back to the configured default action
 *
 * 调用方：AnxAleConnectClassify、AnxAleAcceptClassify
 * Called by: AnxAleConnectClassify and AnxAleAcceptClassify
 * IRQL：<= DISPATCH_LEVEL
 * 中文关键词：连接裁决，挂起询问，兜底放行
 * English keywords: connection verdict, pend and ask, fail-open
 */
static void AnxAleClassifyCommon(_In_ const FWPS_INCOMING_VALUES0* InFixedValues,
                                 _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
                                 _In_ const void* ClassifyContext,
                                 _In_ const FWPS_FILTER3* Filter,
                                 _In_ UINT32 Direction,
                                 _Inout_ FWPS_CLASSIFY_OUT0* ClassifyOut)
{
    ANX_CONN_INFO  conn;
    ANX_NET_CONFIG config;
    ANX_NET_EVENT  event;
    UINT32         action;
    UINT32         ruleId = 0;
    UINT32         defaultAction;

    /*
     * 没有写权限说明上游已经做了终局裁决，我们只能观察，不能改写。
     * Without the write right an upstream filter already decided; we may only
     * observe, never override.
     */
    if ((ClassifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0) {
        return;
    }

    /* 默认放行，后续任何一步失败都停在这个安全状态上 */
    /* Default to permit so any failure below lands on the safe state */
    ClassifyOut->actionType = FWP_ACTION_PERMIT;

    if (AnxIsShuttingDown() || !AnxIsAttached()) {
        return;
    }

    AnxConfigGet(&config);
    if (config.Enabled == 0) {
        return;
    }

    if (!AnxExtractAleConn(InFixedValues, InMetaValues, Direction, &conn)) {
        return;
    }

    /* 本产品自身的流量永远放行，否则会把上报通道自己掐断 */
    /* Our own traffic always passes, otherwise we would cut our own uplink */
    if (config.SelfPid != 0 && conn.ProcessId == config.SelfPid) {
        return;
    }

    if (conn.IsLoopback && config.AllowLoopback != 0) {
        return;
    }

    /* 2. 裁决缓存 / verdict cache */
    if (AnxCacheLookup(&conn, &action)) {
        AnxApplyAction(ClassifyOut, action);
        AnxStatCountConnection(conn.ProcessId, conn.AppIdHash,
                               (BOOLEAN)(action == ANX_NET_ACTION_ALLOW));
        AnxEventBuildFromConn(&event, &conn, ANX_NET_EVT_CONNECT_LOG, action, 0);
        event.Flags |= ANX_NET_EVTF_CACHE_HIT;
        AnxEventPost(&event);
        return;
    }

    /* 3. 规则表 / rule table */
    action = AnxRulesEvaluate(&conn, &ruleId);

    if (action == ANX_NET_ACTION_ALLOW || action == ANX_NET_ACTION_BLOCK) {
        AnxApplyAction(ClassifyOut, action);
        AnxStatCountConnection(conn.ProcessId, conn.AppIdHash,
                               (BOOLEAN)(action == ANX_NET_ACTION_ALLOW));
        AnxEventBuildFromConn(&event, &conn, ANX_NET_EVT_CONNECT_LOG, action, ruleId);
        AnxEventPost(&event);
        return;
    }

    /* 未命中规则时回落到默认动作 / fall back to the default action */
    defaultAction = (Direction == ANX_NET_DIR_OUTBOUND)
                        ? config.DefaultOutbound
                        : config.DefaultInbound;

    if (action != ANX_NET_ACTION_PROMPT) {
        action = defaultAction;
    }

    /* 学习模式只观察不拦截 / learn mode observes without blocking */
    if (config.Mode == ANX_NET_MODE_LEARN) {
        AnxEventBuildFromConn(&event, &conn, ANX_NET_EVT_CONNECT_LOG,
                              ANX_NET_ACTION_ALLOW, ruleId);
        AnxEventPost(&event);
        return;
    }

    /* 4. 弹窗询问 / pend and ask */
    if (action == ANX_NET_ACTION_PROMPT && config.Mode == ANX_NET_MODE_PROMPT) {
        UINT64   classifyHandle = 0;
        UINT64   decisionId;
        NTSTATUS status;

        /*
         * 重授权不再重复询问：同一条连接会被反复 classify，弹第二次窗
         * 对用户是纯噪音。此处按默认动作静默处理。
         * Reauthorization never re-prompts: the same connection is classified
         * repeatedly and a second dialog would be pure noise. Fall through to
         * the default action silently.
         */
        if (conn.IsReauthorize) {
            action = (defaultAction == ANX_NET_ACTION_BLOCK)
                         ? ANX_NET_ACTION_BLOCK : ANX_NET_ACTION_ALLOW;
            AnxApplyAction(ClassifyOut, action);
            return;
        }

        if (ClassifyContext == NULL) {
            action = (defaultAction == ANX_NET_ACTION_BLOCK)
                         ? ANX_NET_ACTION_BLOCK : ANX_NET_ACTION_ALLOW;
            AnxApplyAction(ClassifyOut, action);
            return;
        }

        status = FwpsAcquireClassifyHandle0((void*)ClassifyContext, 0, &classifyHandle);
        if (!NT_SUCCESS(status)) {
            AnxWarn("FwpsAcquireClassifyHandle0 failed 0x%08X, using default\n", status);
            action = (defaultAction == ANX_NET_ACTION_BLOCK)
                         ? ANX_NET_ACTION_BLOCK : ANX_NET_ACTION_ALLOW;
            AnxApplyAction(ClassifyOut, action);
            return;
        }

        decisionId = AnxPendingAdd(classifyHandle, InFixedValues->layerId, &conn,
                                   config.PromptTimeoutMs);
        if (decisionId == 0) {
            /* 登记失败绝不能挂起，否则没人负责完成这次分类 */
            /* Never pend when registration failed — nobody would complete it */
            FwpsReleaseClassifyHandle0(classifyHandle);
            action = (defaultAction == ANX_NET_ACTION_BLOCK)
                         ? ANX_NET_ACTION_BLOCK : ANX_NET_ACTION_ALLOW;
            AnxApplyAction(ClassifyOut, action);
            return;
        }

        status = FwpsPendClassify0(classifyHandle, Filter->filterId, 0, ClassifyOut);
        if (!NT_SUCCESS(status)) {
            /* 挂起失败：撤销登记（不完成分类）并按默认动作裁决 */
            /* Pend failed: cancel registration (never complete) and use default */
            /* VUL-093 修复：旧代码调用 AnxPendingResolve → FwpsCompleteClassify0，
             * 但分类从未挂起，Complete 属于未定义行为。改用 AnxPendingCancel。 */
            AnxPendingCancel(decisionId);
            AnxApplyAction(ClassifyOut, defaultAction == ANX_NET_ACTION_BLOCK
                                            ? ANX_NET_ACTION_BLOCK : ANX_NET_ACTION_ALLOW);
            return;
        }

        /* 挂起成功，上报待决策事件；裁决由 IOCTL 或超时扫描完成 */
        /* Pended; report the request. The verdict arrives via IOCTL or timeout */
        AnxEventBuildFromConn(&event, &conn, ANX_NET_EVT_CONNECT_REQUEST,
                              ANX_NET_ACTION_PROMPT, ruleId);
        event.DecisionId = decisionId;
        AnxEventPost(&event);
        return;
    }

    /* 5. 兜底默认动作 / terminal default action */
    if (action != ANX_NET_ACTION_BLOCK) {
        action = ANX_NET_ACTION_ALLOW;
    }
    AnxApplyAction(ClassifyOut, action);
    AnxStatCountConnection(conn.ProcessId, conn.AppIdHash,
                           (BOOLEAN)(action == ANX_NET_ACTION_ALLOW));
    AnxEventBuildFromConn(&event, &conn, ANX_NET_EVT_CONNECT_LOG, action, ruleId);
    AnxEventPost(&event);
}

static void NTAPI AnxAleConnectClassify(_In_ const FWPS_INCOMING_VALUES0* InFixedValues,
                                        _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
                                        _Inout_opt_ void* LayerData,
                                        _In_opt_ const void* ClassifyContext,
                                        _In_ const FWPS_FILTER3* Filter,
                                        _In_ UINT64 FlowContext,
                                        _Inout_ FWPS_CLASSIFY_OUT0* ClassifyOut)
{
    UNREFERENCED_PARAMETER(LayerData);
    UNREFERENCED_PARAMETER(FlowContext);

    AnxAleClassifyCommon(InFixedValues, InMetaValues, ClassifyContext, Filter,
                         ANX_NET_DIR_OUTBOUND, ClassifyOut);
}

static void NTAPI AnxAleAcceptClassify(_In_ const FWPS_INCOMING_VALUES0* InFixedValues,
                                       _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
                                       _Inout_opt_ void* LayerData,
                                       _In_opt_ const void* ClassifyContext,
                                       _In_ const FWPS_FILTER3* Filter,
                                       _In_ UINT64 FlowContext,
                                       _Inout_ FWPS_CLASSIFY_OUT0* ClassifyOut)
{
    UNREFERENCED_PARAMETER(LayerData);
    UNREFERENCED_PARAMETER(FlowContext);

    AnxAleClassifyCommon(InFixedValues, InMetaValues, ClassifyContext, Filter,
                         ANX_NET_DIR_INBOUND, ClassifyOut);
}

/* ==========================================================================
 * 建流：挂上下文 / Flow established: attach context
 * ========================================================================== */

/*
 * 函数名称：AnxFlowEstablishedClassify
 * 函数作用：在流建立时为 TCP 关联 STREAM 层上下文、为 UDP 关联 DATAGRAM 层上下文。
 * Purpose: On flow establishment, attaches a STREAM-layer context for TCP and a
 *          DATAGRAM-layer context for UDP.
 *
 * 每条流只关联到一个 (layer, callout) 组合，因此上下文的所有权唯一，
 * flowDeleteFn 里释放一次即可，不需要引用计数。
 * A flow is associated with exactly one (layer, callout) pair, so ownership of
 * the context is unique and flowDeleteFn frees it exactly once — no refcount.
 *
 * 调用方：WFP（ALE_FLOW_ESTABLISHED 层）
 * Called by: WFP at the ALE_FLOW_ESTABLISHED layer
 * IRQL：<= DISPATCH_LEVEL
 * 中文关键词：建流回调，流上下文，统计关联
 * English keywords: flow established, flow context, stats association
 */
static void NTAPI AnxFlowEstablishedClassify(_In_ const FWPS_INCOMING_VALUES0* InFixedValues,
                                             _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
                                             _Inout_opt_ void* LayerData,
                                             _In_opt_ const void* ClassifyContext,
                                             _In_ const FWPS_FILTER3* Filter,
                                             _In_ UINT64 FlowContext,
                                             _Inout_ FWPS_CLASSIFY_OUT0* ClassifyOut)
{
    ANX_NET_CONFIG config;
    PANX_FLOW_CTX  ctx;
    NTSTATUS       status;
    UINT16         targetLayer;
    UINT32         targetCallout = 0;
    BOOLEAN        isV6;
    UINT32         i;
    UINT32         remoteAddrIdx, localPortIdx, remotePortIdx, protocolIdx;

    UNREFERENCED_PARAMETER(LayerData);
    UNREFERENCED_PARAMETER(ClassifyContext);
    UNREFERENCED_PARAMETER(Filter);
    UNREFERENCED_PARAMETER(FlowContext);

    /* 检查型 callout：永远放行，只做旁路观察 */
    /* Inspection callout: always continue, observation only */
    ClassifyOut->actionType = FWP_ACTION_CONTINUE;

    if (AnxIsShuttingDown() || !AnxIsAttached()) {
        return;
    }

    AnxConfigGet(&config);
    if (config.Enabled == 0 || config.EnableStats == 0) {
        return;
    }

    if (!FWPS_IS_METADATA_FIELD_PRESENT(InMetaValues, FWPS_METADATA_FIELD_FLOW_HANDLE)) {
        return;
    }

    switch (InFixedValues->layerId) {
    case FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4:
        remoteAddrIdx = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_ADDRESS;
        localPortIdx  = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_PORT;
        remotePortIdx = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_PORT;
        protocolIdx   = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_PROTOCOL;
        isV6 = FALSE;
        break;
    case FWPS_LAYER_ALE_FLOW_ESTABLISHED_V6:
        remoteAddrIdx = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_REMOTE_ADDRESS;
        localPortIdx  = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_PORT;
        remotePortIdx = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_REMOTE_PORT;
        protocolIdx   = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_PROTOCOL;
        isV6 = TRUE;
        break;
    default:
        return;
    }

    if (InFixedValues->valueCount <= protocolIdx) {
        return;
    }

    ctx = (PANX_FLOW_CTX)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(ANX_FLOW_CTX), ANX_TAG_FLOW);
    if (ctx == NULL) {
        return;
    }

    ctx->FlowId     = InMetaValues->flowHandle;
    ctx->Protocol   = InFixedValues->incomingValue[protocolIdx].value.uint8;
    ctx->LocalPort  = InFixedValues->incomingValue[localPortIdx].value.uint16;
    ctx->RemotePort = InFixedValues->incomingValue[remotePortIdx].value.uint16;
    ctx->Direction  = ANX_NET_DIR_OUTBOUND;
    ctx->BytesIn    = 0;
    ctx->BytesOut   = 0;
    ctx->InspectDone = 0;
    ctx->InspectedBytes = 0;
    ctx->AppIdHash  = 0;
    ctx->ProcessId  = 0;

    if (isV6) {
        AnxAddrFromV6(&ctx->RemoteAddr,
                      InFixedValues->incomingValue[remoteAddrIdx].value.byteArray16->byteArray16);
    } else {
        AnxAddrFromV4(&ctx->RemoteAddr,
                      InFixedValues->incomingValue[remoteAddrIdx].value.uint32);
    }
    if (FWPS_IS_METADATA_FIELD_PRESENT(InMetaValues, FWPS_METADATA_FIELD_PROCESS_ID)) {
        ctx->ProcessId = (UINT32)InMetaValues->processId;
    }
    if (FWPS_IS_METADATA_FIELD_PRESENT(InMetaValues, FWPS_METADATA_FIELD_PROCESS_PATH) &&
        InMetaValues->processPath != NULL &&
        InMetaValues->processPath->data != NULL &&
        InMetaValues->processPath->size >= sizeof(WCHAR)) {
        ctx->AppIdHash = AnxHashAppIdBytes(InMetaValues->processPath->data,
                                           InMetaValues->processPath->size);
    }

    /* 按协议决定把上下文挂到哪一层 / pick the layer by protocol */
    if (ctx->Protocol == ANX_NET_PROTO_TCP) {
        targetLayer = isV6 ? FWPS_LAYER_STREAM_V6 : FWPS_LAYER_STREAM_V4;
    } else if (ctx->Protocol == ANX_NET_PROTO_UDP) {
        targetLayer = isV6 ? FWPS_LAYER_DATAGRAM_DATA_V6 : FWPS_LAYER_DATAGRAM_DATA_V4;
    } else {
        ExFreePoolWithTag(ctx, ANX_TAG_FLOW);
        return;
    }

    for (i = 0; i < ANX_CALLOUT_COUNT; i++) {
        if (!g_Callouts[i].Registered) {
            continue;
        }
        if ((targetLayer == FWPS_LAYER_STREAM_V4 &&
             g_Callouts[i].LayerKey == &FWPM_LAYER_STREAM_V4) ||
            (targetLayer == FWPS_LAYER_STREAM_V6 &&
             g_Callouts[i].LayerKey == &FWPM_LAYER_STREAM_V6) ||
            (targetLayer == FWPS_LAYER_DATAGRAM_DATA_V4 &&
             g_Callouts[i].LayerKey == &FWPM_LAYER_DATAGRAM_DATA_V4) ||
            (targetLayer == FWPS_LAYER_DATAGRAM_DATA_V6 &&
             g_Callouts[i].LayerKey == &FWPM_LAYER_DATAGRAM_DATA_V6)) {
            targetCallout = g_Callouts[i].CalloutId;
            break;
        }
    }

    if (targetCallout == 0) {
        ExFreePoolWithTag(ctx, ANX_TAG_FLOW);
        return;
    }

    status = FwpsFlowAssociateContext0(ctx->FlowId, targetLayer, targetCallout, (UINT64)(ULONG_PTR)ctx);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(ctx, ANX_TAG_FLOW);
        return;
    }
}

/*
 * 函数名称：AnxFlowDelete
 * 函数作用：流终止时上报累计流量并释放上下文。
 * Purpose: Reports the accumulated byte counters and frees the context when a
 *          flow terminates.
 * 调用方：WFP
 * Called by: WFP
 * IRQL：<= DISPATCH_LEVEL
 * 中文关键词：流删除，流量上报，上下文释放
 * English keywords: flow delete, byte reporting, context release
 */
static void NTAPI AnxFlowDelete(_In_ UINT16 LayerId, _In_ UINT32 CalloutId, _In_ UINT64 FlowContext)
{
    PANX_FLOW_CTX ctx = (PANX_FLOW_CTX)(ULONG_PTR)FlowContext;
    ANX_NET_EVENT event;

    UNREFERENCED_PARAMETER(LayerId);
    UNREFERENCED_PARAMETER(CalloutId);

    if (ctx == NULL) {
        return;
    }

    if (ctx->BytesIn != 0 || ctx->BytesOut != 0) {
        RtlZeroMemory(&event, sizeof(event));
        event.Size        = sizeof(ANX_NET_EVENT);
        event.Kind        = ANX_NET_EVT_FLOW_CLOSED;
        event.TimestampMs = AnxGetSystemTimeMs();
        event.ProcessId   = ctx->ProcessId;
        event.Direction   = ctx->Direction;
        event.Protocol    = ctx->Protocol;
        event.LocalPort   = ctx->LocalPort;
        event.RemotePort  = ctx->RemotePort;
        event.Action      = ANX_NET_ACTION_ALLOW;
        event.AppIdHash   = ctx->AppIdHash;
        event.BytesIn     = (UINT64)ctx->BytesIn;
        event.BytesOut    = (UINT64)ctx->BytesOut;
        RtlCopyMemory(&event.RemoteAddress, &ctx->RemoteAddr, sizeof(ANX_NET_ADDR));
        AnxEventPost(&event);
    }

    ExFreePoolWithTag(ctx, ANX_TAG_FLOW);
}

/* ==========================================================================
 * 流内容检查 / Stream content inspection
 * ========================================================================== */

/*
 * 函数名称：AnxStreamClassify
 * 函数作用：TCP 流分类：统计字节、限速、并从首部提取 TLS SNI 或 HTTP Host 做域名管控。
 * Purpose: TCP stream classification — byte accounting, shaping, and extracting
 *          the TLS SNI or HTTP Host from the head of the stream for domain
 *          control.
 *
 * 只检查每条流的前 ANX_MAX_INSPECT_BYTES 字节，且只检查一次。TLS 握手与 HTTP
 * 请求行都出现在流的最开头，继续扫描后续数据只会浪费 CPU 而无收益。
 * Only the first ANX_MAX_INSPECT_BYTES of each flow are examined, exactly once.
 * Both the TLS handshake and the HTTP request line appear at the very start of
 * the stream; scanning further would burn CPU for nothing.
 *
 * 调用方：WFP（STREAM 层）
 * Called by: WFP at the STREAM layer
 * IRQL：<= DISPATCH_LEVEL
 * 中文关键词：流检查，SNI 提取，域名拦截，限速
 * English keywords: stream inspection, SNI extraction, domain blocking, shaping
 */
static void NTAPI AnxStreamClassify(_In_ const FWPS_INCOMING_VALUES0* InFixedValues,
                                    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
                                    _Inout_opt_ void* LayerData,
                                    _In_opt_ const void* ClassifyContext,
                                    _In_ const FWPS_FILTER3* Filter,
                                    _In_ UINT64 FlowContext,
                                    _Inout_ FWPS_CLASSIFY_OUT0* ClassifyOut)
{
    FWPS_STREAM_CALLOUT_IO_PACKET0* packet;
    PANX_FLOW_CTX                   ctx = (PANX_FLOW_CTX)(ULONG_PTR)FlowContext;
    ANX_NET_CONFIG                  config;
    ANX_NET_EVENT                   event;
    BOOLEAN                         outbound;
    SIZE_T                          dataLength;

    UNREFERENCED_PARAMETER(InMetaValues);
    UNREFERENCED_PARAMETER(InFixedValues);
    UNREFERENCED_PARAMETER(ClassifyContext);
    UNREFERENCED_PARAMETER(Filter);

    if ((ClassifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0) {
        return;
    }

    ClassifyOut->actionType = FWP_ACTION_PERMIT;

    if (LayerData == NULL || ctx == NULL) {
        return;
    }
    if (AnxIsShuttingDown() || !AnxIsAttached()) {
        return;
    }

    AnxConfigGet(&config);
    if (config.Enabled == 0) {
        return;
    }

    packet = (FWPS_STREAM_CALLOUT_IO_PACKET0*)LayerData;
    if (packet->streamData == NULL) {
        return;
    }

    outbound   = (BOOLEAN)((packet->streamData->flags & FWPS_STREAM_FLAG_SEND) != 0);
    dataLength = packet->streamData->dataLength;

    /* --- 字节统计 / byte accounting --- */
    if (config.EnableStats != 0 && dataLength != 0) {
        if (outbound) {
            InterlockedAdd64(&ctx->BytesOut, (LONG64)dataLength);
        } else {
            InterlockedAdd64(&ctx->BytesIn, (LONG64)dataLength);
        }
        AnxStatAddBytes(ctx->ProcessId, ctx->AppIdHash,
                        outbound ? 0 : dataLength,
                        outbound ? dataLength : 0);
    }

    /* --- 限速 / rate limiting --- */
    if (config.EnableRateLimit != 0 && dataLength != 0) {
        if (!AnxRateConsume(ctx->ProcessId, ctx->AppIdHash, dataLength, (BOOLEAN)!outbound)) {
            /*
             * 超出配额：要求 WFP 暂缓这段数据，等下一轮再送。
             * 这是「延迟」而非「丢弃」，TCP 语义得以保持。
             * Over quota: ask WFP to defer this chunk and re-deliver later.
             * This defers rather than drops, preserving TCP semantics.
             */
            packet->streamAction = FWPS_STREAM_ACTION_DEFER;
            ClassifyOut->actionType = FWP_ACTION_BLOCK;
            ClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
            ClassifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;

            RtlZeroMemory(&event, sizeof(event));
            event.Size        = sizeof(ANX_NET_EVENT);
            event.Kind        = ANX_NET_EVT_RATE_LIMITED;
            event.TimestampMs = AnxGetSystemTimeMs();
            event.ProcessId   = ctx->ProcessId;
            event.Protocol    = ctx->Protocol;
            event.RemotePort  = ctx->RemotePort;
            event.AppIdHash   = ctx->AppIdHash;
            event.BytesIn     = (UINT64)ctx->BytesIn;
            event.BytesOut    = (UINT64)ctx->BytesOut;
            RtlCopyMemory(&event.RemoteAddress, &ctx->RemoteAddr, sizeof(ANX_NET_ADDR));
            AnxEventPost(&event);
            return;
        }
    }

    /* --- 内容检查：只在出站方向、只做一次 --- */
    /* --- Inspection: outbound only, exactly once --- */
    if (config.EnableStreamInspect == 0 || !outbound || dataLength == 0) {
        return;
    }
    if (InterlockedCompareExchange(&ctx->InspectDone, 1, 0) != 0) {
        return;
    }

    {
        UINT8*   buffer;
        SIZE_T   copyLength;
        SIZE_T   bytesCopied = 0;
        WCHAR    domain[ANX_NET_MAX_DOMAIN];
        BOOLEAN  parsed = FALSE;
        UINT32   domainSource = ANX_NET_DSRC_TLS_SNI;
        UINT32   action;
        UINT32   ruleId = 0;
        copyLength = dataLength;
        if (copyLength > ANX_MAX_INSPECT_BYTES) {
            copyLength = ANX_MAX_INSPECT_BYTES;
        }

        buffer = (UINT8*)ExAllocatePool2(POOL_FLAG_NON_PAGED, copyLength, ANX_TAG_GENERIC);
        if (buffer == NULL) {
            return;
        }

        FwpsCopyStreamDataToBuffer0(packet->streamData, buffer, copyLength, &bytesCopied);
        if (bytesCopied == 0) {
            ExFreePoolWithTag(buffer, ANX_TAG_GENERIC);
            return;
        }

        parsed = AnxParseTlsSni(buffer, bytesCopied, domain, ANX_NET_MAX_DOMAIN);
        if (!parsed) {
            parsed = AnxParseHttpHost(buffer, bytesCopied, domain, ANX_NET_MAX_DOMAIN);
            domainSource = ANX_NET_DSRC_HTTP_HOST;
        }

        ExFreePoolWithTag(buffer, ANX_TAG_GENERIC);

        if (!parsed) {
            return;
        }

        action = AnxDomainsEvaluate(domain, &ruleId);

        RtlZeroMemory(&event, sizeof(event));
        event.Size         = sizeof(ANX_NET_EVENT);
        event.TimestampMs  = AnxGetSystemTimeMs();
        event.ProcessId    = ctx->ProcessId;
        event.Direction    = ANX_NET_DIR_OUTBOUND;
        event.Protocol     = ctx->Protocol;
        event.LocalPort    = ctx->LocalPort;
        event.RemotePort   = ctx->RemotePort;
        event.RuleId       = ruleId;
        event.AppIdHash    = ctx->AppIdHash;
        event.DomainSource = domainSource;
        RtlCopyMemory(&event.RemoteAddress, &ctx->RemoteAddr, sizeof(ANX_NET_ADDR));
        AnxCopyPathToBuffer(event.Domain, ANX_NET_MAX_DOMAIN, domain, ANX_NET_MAX_DOMAIN - 1);

        if (action == ANX_NET_ACTION_BLOCK) {
            event.Kind   = ANX_NET_EVT_DOMAIN_BLOCKED;
            event.Action = ANX_NET_ACTION_BLOCK;
            AnxEventPost(&event);

            /* 域名命中黑名单：直接终止这条流 / kill the flow on a blocklist hit */
            packet->streamAction = FWPS_STREAM_ACTION_DROP_CONNECTION;
            ClassifyOut->actionType = FWP_ACTION_BLOCK;
            ClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
            ClassifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
            return;
        }

        event.Kind   = ANX_NET_EVT_CONNECT_LOG;
        event.Action = ANX_NET_ACTION_ALLOW;
        AnxEventPost(&event);
    }
}

/* ==========================================================================
 * 数据报检查（DNS） / Datagram inspection (DNS)
 * ========================================================================== */

/*
 * 函数名称：AnxDatagramClassify
 * 函数作用：UDP 数据报分类：统计字节，并对出站 DNS 查询做域名管控。
 * Purpose: UDP datagram classification — byte accounting plus domain control on
 *          outbound DNS queries.
 *
 * 只解析出站方向。入站方向的 NBL 数据偏移指向传输层头部，需要额外的偏移回退，
 * 而拦截查询已经足以阻断解析，因此不处理响应。
 * Only the outbound direction is parsed. Inbound NBLs point at the transport
 * header and would need extra offset handling; blocking the query already
 * prevents resolution, so responses are left alone.
 *
 * 调用方：WFP（DATAGRAM_DATA 层）
 * Called by: WFP at the DATAGRAM_DATA layer
 * IRQL：<= DISPATCH_LEVEL
 * 中文关键词：DNS 管控，数据报检查，域名拦截
 * English keywords: DNS control, datagram inspection, domain blocking
 */
static void NTAPI AnxDatagramClassify(_In_ const FWPS_INCOMING_VALUES0* InFixedValues,
                                      _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
                                      _Inout_opt_ void* LayerData,
                                      _In_opt_ const void* ClassifyContext,
                                      _In_ const FWPS_FILTER3* Filter,
                                      _In_ UINT64 FlowContext,
                                      _Inout_ FWPS_CLASSIFY_OUT0* ClassifyOut)
{
    PANX_FLOW_CTX  ctx = (PANX_FLOW_CTX)(ULONG_PTR)FlowContext;
    NET_BUFFER_LIST* nbl;
    NET_BUFFER*    netBuffer;
    ANX_NET_CONFIG config;
    ANX_NET_EVENT  event;
    UINT32         directionIdx;
    UINT32         remotePortIdx;
    UINT16         remotePort;
    BOOLEAN        outbound;
    ULONG          dataLength;
    UINT8*         storage = NULL;
    UINT8*         payload;
    WCHAR          domain[ANX_NET_MAX_DOMAIN];
    UINT32         action;
    UINT32         ruleId = 0;

    UNREFERENCED_PARAMETER(ClassifyContext);
    UNREFERENCED_PARAMETER(Filter);

    if ((ClassifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0) {
        return;
    }

    ClassifyOut->actionType = FWP_ACTION_PERMIT;

    if (LayerData == NULL) {
        return;
    }
    if (AnxIsShuttingDown() || !AnxIsAttached()) {
        return;
    }

    AnxConfigGet(&config);
    if (config.Enabled == 0 || config.EnableDns == 0) {
        return;
    }

    switch (InFixedValues->layerId) {
    case FWPS_LAYER_DATAGRAM_DATA_V4:
        directionIdx  = FWPS_FIELD_DATAGRAM_DATA_V4_DIRECTION;
        remotePortIdx = FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_PORT;
        break;
    case FWPS_LAYER_DATAGRAM_DATA_V6:
        directionIdx  = FWPS_FIELD_DATAGRAM_DATA_V6_DIRECTION;
        remotePortIdx = FWPS_FIELD_DATAGRAM_DATA_V6_IP_REMOTE_PORT;
        break;
    default:
        return;
    }

    if (InFixedValues->valueCount <= directionIdx ||
        InFixedValues->valueCount <= remotePortIdx) {
        return;
    }

    outbound   = (BOOLEAN)(InFixedValues->incomingValue[directionIdx].value.uint32 == FWP_DIRECTION_OUTBOUND);
    remotePort = InFixedValues->incomingValue[remotePortIdx].value.uint16;

    /* 只关心出站的 DNS 端口 / outbound DNS ports only */
    if (!outbound || (remotePort != 53 && remotePort != 5353)) {
        return;
    }

    nbl = (NET_BUFFER_LIST*)LayerData;
    netBuffer = NET_BUFFER_LIST_FIRST_NB(nbl);
    if (netBuffer == NULL) {
        return;
    }

    dataLength = NET_BUFFER_DATA_LENGTH(netBuffer);
    if (dataLength < 13 || dataLength > 4096) {
        return;
    }

    storage = (UINT8*)ExAllocatePool2(POOL_FLAG_NON_PAGED, dataLength, ANX_TAG_GENERIC);
    if (storage == NULL) {
        return;
    }

    /*
     * NdisGetDataBuffer 在数据非连续时会用 storage 做拼接，连续时直接返回内部指针。
     * NdisGetDataBuffer copies into storage when the data is not contiguous and
     * returns an internal pointer when it is.
     */
    payload = (UINT8*)NdisGetDataBuffer(netBuffer, dataLength, storage, 1, 0);
    if (payload == NULL) {
        ExFreePoolWithTag(storage, ANX_TAG_GENERIC);
        return;
    }

    if (!AnxParseDnsQuery(payload, dataLength, domain, ANX_NET_MAX_DOMAIN)) {
        ExFreePoolWithTag(storage, ANX_TAG_GENERIC);
        return;
    }

    ExFreePoolWithTag(storage, ANX_TAG_GENERIC);

    action = AnxDomainsEvaluate(domain, &ruleId);

    RtlZeroMemory(&event, sizeof(event));
    event.Size         = sizeof(ANX_NET_EVENT);
    event.TimestampMs  = AnxGetSystemTimeMs();
    event.Direction    = ANX_NET_DIR_OUTBOUND;
    event.Protocol     = ANX_NET_PROTO_UDP;
    event.RemotePort   = remotePort;
    event.RuleId       = ruleId;
    event.DomainSource = ANX_NET_DSRC_DNS;

    if (ctx != NULL) {
        event.ProcessId = ctx->ProcessId;
        event.AppIdHash = ctx->AppIdHash;
        RtlCopyMemory(&event.RemoteAddress, &ctx->RemoteAddr, sizeof(ANX_NET_ADDR));
    } else if (FWPS_IS_METADATA_FIELD_PRESENT(InMetaValues, FWPS_METADATA_FIELD_PROCESS_ID)) {
        event.ProcessId = (UINT32)InMetaValues->processId;
    }

    AnxCopyPathToBuffer(event.Domain, ANX_NET_MAX_DOMAIN, domain, ANX_NET_MAX_DOMAIN - 1);

    if (action == ANX_NET_ACTION_BLOCK) {
        event.Kind   = ANX_NET_EVT_DOMAIN_BLOCKED;
        event.Action = ANX_NET_ACTION_BLOCK;
        AnxEventPost(&event);

        ClassifyOut->actionType = FWP_ACTION_BLOCK;
        ClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        return;
    }

    event.Kind   = ANX_NET_EVT_DNS_QUERY;
    event.Action = ANX_NET_ACTION_ALLOW;
    AnxEventPost(&event);
}

/* ==========================================================================
 * 通知回调 / Notify callback
 * ========================================================================== */

static NTSTATUS NTAPI AnxCalloutNotify(_In_ FWPS_CALLOUT_NOTIFY_TYPE NotifyType,
                                       _In_ const GUID* FilterKey,
                                       _Inout_ FWPS_FILTER3* Filter)
{
    UNREFERENCED_PARAMETER(NotifyType);
    UNREFERENCED_PARAMETER(FilterKey);
    UNREFERENCED_PARAMETER(Filter);
    return STATUS_SUCCESS;
}

/* ==========================================================================
 * 注册与注销 / Registration and teardown
 * ========================================================================== */

/*
 * 函数名称：AnxCalloutsRegister
 * 函数作用：向 WFP 注册全部 callout，逐个失败可容忍。
 * Purpose: Registers every callout with WFP; individual failures are tolerated.
 *
 * 某一层注册失败不视为致命错误：驱动会降级运行并在 Capabilities 里如实反映，
 * 用户态据此决定哪些功能可用。
 * A per-layer failure is not fatal: the driver runs degraded and reports the
 * truth in Capabilities so user mode knows which features are live.
 *
 * 调用方：AnxWfpInitialize
 * Called by: AnxWfpInitialize
 * IRQL：PASSIVE_LEVEL
 * 中文关键词：callout 注册，降级运行，能力位
 * English keywords: callout registration, degraded mode, capability bits
 */
NTSTATUS AnxCalloutsRegister(_In_ PDEVICE_OBJECT DeviceObject)
{
    UINT32   i;
    UINT32   succeeded = 0;
    NTSTATUS status;

    for (i = 0; i < ANX_CALLOUT_COUNT; i++) {
        FWPS_CALLOUT3 callout;

        RtlZeroMemory(&callout, sizeof(callout));
        callout.calloutKey        = *g_Callouts[i].CalloutKey;
        callout.classifyFn        = g_Callouts[i].ClassifyFn;
        callout.notifyFn          = AnxCalloutNotify;
        callout.flowDeleteFn      = g_Callouts[i].FlowDeleteFn;

        status = FwpsCalloutRegister3(DeviceObject, &callout, &g_Callouts[i].CalloutId);
        if (!NT_SUCCESS(status)) {
            AnxError("FwpsCalloutRegister3(%ws) failed 0x%08X\n", g_Callouts[i].Name, status);
            continue;
        }

        g_Callouts[i].Registered = TRUE;
        g_Anx.Capabilities |= g_Callouts[i].CapabilityBit;
        succeeded++;
    }

    if (succeeded == 0) {
        return STATUS_UNSUCCESSFUL;
    }

    if ((g_Anx.Capabilities & (ANX_NET_CAP_ALE_V4 | ANX_NET_CAP_ALE_V6)) != 0) {
        g_Anx.Capabilities |= ANX_NET_CAP_PEND;
    }
    if ((g_Anx.Capabilities & ANX_NET_CAP_STREAM) != 0) {
        g_Anx.Capabilities |= ANX_NET_CAP_RATE_LIMIT;
    }

    return STATUS_SUCCESS;
}

/*
 * 函数名称：AnxCalloutsAddFilters
 * 函数作用：为每个已注册的 callout 添加一条兜底过滤器，把该层流量引到 callout。
 * Purpose: Adds one catch-all filter per registered callout so the layer's
 *          traffic reaches it.
 *
 * 过滤器不带任何条件、权重取最低：所有连接都会到达 callout，具体放行与拦截
 * 交给驱动内部的规则表统一裁决，避免 WFP 过滤器与内核规则表两套逻辑打架。
 * The filters carry no conditions and the lowest weight: every connection
 * reaches the callout and the driver's rule table is the single arbiter,
 * avoiding two competing sources of truth.
 *
 * 调用方：AnxWfpInitialize
 * Called by: AnxWfpInitialize
 * IRQL：PASSIVE_LEVEL
 * 中文关键词：过滤器添加，兜底规则，单一裁决源
 * English keywords: filter add, catch-all rule, single source of truth
 */
NTSTATUS AnxCalloutsAddFilters(void)
{
    UINT32   i;
    UINT32   added = 0;
    NTSTATUS status;

    for (i = 0; i < ANX_CALLOUT_COUNT; i++) {
        FWPM_CALLOUT0 mCallout;
        FWPM_FILTER0  filter;
        WCHAR         nameBuffer[64];

        if (!g_Callouts[i].Registered) {
            continue;
        }

        RtlZeroMemory(&mCallout, sizeof(mCallout));
        mCallout.calloutKey         = *g_Callouts[i].CalloutKey;
        mCallout.displayData.name   = (PWSTR)g_Callouts[i].Name;
        mCallout.applicableLayer    = *g_Callouts[i].LayerKey;
        mCallout.flags              = 0;

        status = FwpmCalloutAdd0(g_Anx.EngineHandle, &mCallout, NULL, NULL);
        if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
            AnxError("FwpmCalloutAdd0(%ws) failed 0x%08X\n", g_Callouts[i].Name, status);
            continue;
        }
        g_Callouts[i].Added = TRUE;

        RtlStringCchPrintfW(nameBuffer, RTL_NUMBER_OF(nameBuffer), L"%ws Filter",
                            g_Callouts[i].Name);

        RtlZeroMemory(&filter, sizeof(filter));
        filter.displayData.name  = nameBuffer;
        filter.layerKey          = *g_Callouts[i].LayerKey;
        filter.subLayerKey       = ANX_NET_SUBLAYER_KEY;
        filter.weight.type       = FWP_EMPTY;   /* 由 WFP 自动分配权重 */
        filter.numFilterConditions = 0;
        filter.filterCondition   = NULL;
        filter.action.type       = g_Callouts[i].Terminating
                                       ? FWP_ACTION_CALLOUT_TERMINATING
                                       : FWP_ACTION_CALLOUT_INSPECTION;
        filter.action.calloutKey = *g_Callouts[i].CalloutKey;

        status = FwpmFilterAdd0(g_Anx.EngineHandle, &filter, NULL, &g_Callouts[i].FilterId);
        if (!NT_SUCCESS(status)) {
            AnxError("FwpmFilterAdd0(%ws) failed 0x%08X\n", g_Callouts[i].Name, status);
            continue;
        }

        g_Callouts[i].Filtered = TRUE;
        added++;
    }

    return (added > 0) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

/*
 * 函数名称：AnxCalloutsUnregister
 * 函数作用：删除过滤器、移除 callout 定义并注销 callout。
 * Purpose: Deletes filters, removes callout definitions and unregisters callouts.
 *
 * 顺序不可颠倒：必须先删过滤器断掉流量来源，再注销 callout，
 * 否则 FwpsCalloutUnregisterById 会返回 STATUS_DEVICE_BUSY。
 * The order is mandatory: filters must go first to cut off traffic, then the
 * callouts, otherwise FwpsCalloutUnregisterById returns STATUS_DEVICE_BUSY.
 *
 * 调用方：AnxWfpShutdown
 * Called by: AnxWfpShutdown
 * IRQL：PASSIVE_LEVEL
 * 中文关键词：注销顺序，删除过滤器，设备忙
 * English keywords: teardown ordering, delete filters, device busy
 */
void AnxCalloutsUnregister(void)
{
    UINT32   i;
    NTSTATUS status;

    /* 1. 先删过滤器 / delete filters first */
    for (i = 0; i < ANX_CALLOUT_COUNT; i++) {
        if (g_Callouts[i].Filtered && g_Anx.EngineHandle != NULL) {
            (void)FwpmFilterDeleteById0(g_Anx.EngineHandle, g_Callouts[i].FilterId);
            g_Callouts[i].Filtered = FALSE;
        }
    }

    /* 2. 再删 callout 定义 / then remove the callout definitions */
    for (i = 0; i < ANX_CALLOUT_COUNT; i++) {
        if (g_Callouts[i].Added && g_Anx.EngineHandle != NULL) {
            (void)FwpmCalloutDeleteByKey0(g_Anx.EngineHandle, g_Callouts[i].CalloutKey);
            g_Callouts[i].Added = FALSE;
        }
    }

    /* 3. 最后注销 callout / finally unregister the callouts */
    for (i = 0; i < ANX_CALLOUT_COUNT; i++) {
        if (g_Callouts[i].Registered) {
            status = FwpsCalloutUnregisterById0(g_Callouts[i].CalloutId);
            if (!NT_SUCCESS(status)) {
                AnxError("FwpsCalloutUnregisterById0(%ws) failed 0x%08X\n",
                         g_Callouts[i].Name, status);
            }
            g_Callouts[i].Registered = FALSE;
        }
    }
}
