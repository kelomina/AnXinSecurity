/*++
Copyright (c) AnXin Security. All rights reserved.

Module Name:
    pending.c

Abstract:
    挂起决策：把一次 WFP 分类暂时搁置，等用户在界面上点「允许/阻止」后再完成。
    Pended decisions: park a WFP classification until the user clicks
    Allow/Block in the UI, then complete it.

    生命周期 / Lifecycle:
      classifyFn
        -> FwpsAcquireClassifyHandle0
        -> AnxPendingAdd (登记 + 启动超时)     / register and arm the timeout
        -> FwpsPendClassify0                    (分类返回，连接被挂起)
      ... 用户裁决 / user verdict ...
        -> IOCTL_ANX_NET_SET_VERDICT
        -> AnxPendingResolve
        -> FwpsCompleteClassify0 + FwpsReleaseClassifyHandle0

    绝对不变量 / Hard invariants:
    - 每一个被挂起的分类都必须被完成，否则该连接永远挂住、驱动也无法卸载。
      Every pended classification MUST be completed, otherwise the connection
      hangs forever and the driver cannot unload.
      为此有三条兜底：超时定时器、用户态断开时的 AbortAll、卸载时的 AbortAll。
      Three safety nets guarantee this: the timeout timer, AbortAll on user-mode
      detach, and AbortAll on unload.
    - 挂起总数有上限；超限时不再挂起，直接按默认动作放行/拦截。
      The number of pended decisions is capped; beyond the cap we stop pending
      and fall back to the default action.

Environment:
    Kernel mode only.

--*/

#include "anx_net_internal.h"

static KDEFERRED_ROUTINE AnxPendingTimerDpc;

/* ==========================================================================
 * 内部辅助 / Internal helpers
 * ========================================================================== */

/*
 * 完成一次被挂起的分类。调用前 entry 必须已经从链表摘除。
 * Completes a pended classification. The entry must already be unlinked.
 */
static void AnxPendingCompleteEntry(_In_ PANX_PENDING_ENTRY Entry, _In_ UINT32 Action)
{
    FWPS_CLASSIFY_OUT0 classifyOut;

    RtlZeroMemory(&classifyOut, sizeof(classifyOut));

    if (Action == ANX_NET_ACTION_BLOCK) {
        classifyOut.actionType = FWP_ACTION_BLOCK;
        /*
         * 拦截时必须清掉写权限，否则权重更低的过滤器还能把它改回放行。
         * On block, clear the write right so a lower-weight filter cannot
         * override the verdict back to permit.
         */
        classifyOut.rights &= ~FWPS_RIGHT_ACTION_WRITE;
    } else {
        classifyOut.actionType = FWP_ACTION_PERMIT;
        classifyOut.rights = FWPS_RIGHT_ACTION_WRITE;
    }

    FwpsCompleteClassify0(Entry->ClassifyHandle, 0, &classifyOut);
    FwpsReleaseClassifyHandle0(Entry->ClassifyHandle);

    InterlockedDecrement(&g_Anx.PendingCount);
    ExFreePoolWithTag(Entry, ANX_TAG_PENDING);
}

/*
 * 上报一条「决策已完成」事件，让用户态可以更新界面并落日志。
 * Emits a "decision completed" event so user mode can update the UI and log it.
 */
static void AnxPendingEmitResult(_In_ const ANX_PENDING_ENTRY* Entry,
                                 _In_ UINT32 Action, _In_ BOOLEAN TimedOut)
{
    ANX_NET_EVENT event;

    RtlZeroMemory(&event, sizeof(event));

    event.Size        = sizeof(ANX_NET_EVENT);
    event.Kind        = ANX_NET_EVT_CONNECT_LOG;
    event.DecisionId  = Entry->DecisionId;
    event.TimestampMs = AnxGetSystemTimeMs();
    event.ProcessId   = Entry->ProcessId;
    event.Direction   = Entry->Direction;
    event.Protocol    = Entry->Protocol;
    event.RemotePort  = Entry->RemotePort;
    event.Action      = Action;
    event.AppIdHash   = Entry->AppIdHash;

    if (TimedOut) {
        event.Flags |= ANX_NET_EVTF_TIMED_OUT;
    }

    RtlCopyMemory(&event.RemoteAddress, &Entry->RemoteAddr, sizeof(ANX_NET_ADDR));

    AnxEventPost(&event);
}

/* ==========================================================================
 * 超时扫描 / Timeout sweep
 * ========================================================================== */

/*
 * 函数名称：AnxPendingTimerDpc
 * 函数作用：周期性扫描挂起链表，把已超时的决策按配置动作完成。
 * Purpose: Periodically sweeps the pending list and completes timed-out
 *          decisions with the configured timeout action.
 *
 * 这是防止「用户不点、连接永远挂住」的核心兜底。
 * This is the core safety net against "the user never clicks and the connection
 * hangs forever".
 *
 * 调用方：内核定时器 DPC
 * Called by: the kernel timer DPC
 * IRQL：DISPATCH_LEVEL
 * 中文关键词：超时扫描，兜底完成，默认动作
 * English keywords: timeout sweep, fallback completion, default action
 */
static VOID AnxPendingTimerDpc(_In_ PKDPC Dpc, _In_opt_ PVOID Context,
                               _In_opt_ PVOID Arg1, _In_opt_ PVOID Arg2)
{
    ANX_NET_CONFIG config;
    LIST_ENTRY     expired;
    KIRQL          oldIrql;
    PLIST_ENTRY    link;
    UINT64         now;
    UINT32         timeoutAction;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Arg1);
    UNREFERENCED_PARAMETER(Arg2);

    if (AnxIsShuttingDown()) {
        return;
    }

    AnxConfigGet(&config);
    timeoutAction = config.TimeoutAction;
    if (timeoutAction != ANX_NET_ACTION_BLOCK) {
        timeoutAction = ANX_NET_ACTION_ALLOW;
    }

    now = AnxGetSystemTimeMs();
    InitializeListHead(&expired);

    KeAcquireSpinLock(&g_Anx.PendingLock, &oldIrql);
    link = g_Anx.PendingList.Flink;
    while (link != &g_Anx.PendingList) {
        PANX_PENDING_ENTRY entry = CONTAINING_RECORD(link, ANX_PENDING_ENTRY, Link);
        PLIST_ENTRY        next  = link->Flink;

        if (!entry->Completed && entry->ExpiryMs != 0 && entry->ExpiryMs <= now) {
            entry->Completed = TRUE;
            RemoveEntryList(link);
            InsertTailList(&expired, link);
        }
        link = next;
    }
    KeReleaseSpinLock(&g_Anx.PendingLock, oldIrql);

    /* 完成动作放到锁外，避免在持锁时回调进 WFP */
    /* Complete outside the lock so we never re-enter WFP while holding it */
    while (!IsListEmpty(&expired)) {
        PLIST_ENTRY        item  = RemoveHeadList(&expired);
        PANX_PENDING_ENTRY entry = CONTAINING_RECORD(item, ANX_PENDING_ENTRY, Link);

        InterlockedIncrement64(&g_Anx.PendingTimedOut);
        AnxPendingEmitResult(entry, timeoutAction, TRUE);
        AnxPendingCompleteEntry(entry, timeoutAction);
    }
}

/* ==========================================================================
 * 初始化与清理 / Initialization and teardown
 * ========================================================================== */

/*
 * 函数名称：AnxPendingInitialize
 * 函数作用：初始化挂起链表、锁与周期性超时定时器。
 * Purpose: Initializes the pending list, its lock and the periodic timeout timer.
 * 调用方：DriverEntry
 * Called by: DriverEntry
 * IRQL：PASSIVE_LEVEL
 * 中文关键词：挂起队列初始化，定时器
 * English keywords: pending queue init, timer
 */
NTSTATUS AnxPendingInitialize(void)
{
    LARGE_INTEGER dueTime;

    InitializeListHead(&g_Anx.PendingList);
    KeInitializeSpinLock(&g_Anx.PendingLock);

    g_Anx.NextDecisionId = 1;

    KeInitializeTimerEx(&g_Anx.PendingTimer, SynchronizationTimer);
    KeInitializeDpc(&g_Anx.PendingDpc, AnxPendingTimerDpc, NULL);

    /* 负数表示相对时间，单位 100ns / negative means relative, in 100ns units */
    dueTime.QuadPart = -((LONGLONG)ANX_PENDING_TIMER_MS * 10000LL);

    KeSetTimerEx(&g_Anx.PendingTimer, dueTime, (LONG)ANX_PENDING_TIMER_MS, &g_Anx.PendingDpc);
    g_Anx.PendingTimerStarted = TRUE;

    return STATUS_SUCCESS;
}

/*
 * 函数名称：AnxPendingShutdown
 * 函数作用：停定时器、等 DPC 退场，然后按放行完成所有残留挂起。
 * Purpose: Cancels the timer, drains the DPC, then completes every leftover
 *          pended decision as permit.
 *
 * 卸载路径上必须选择放行：此时驱动即将失效，拦截一条正在挂起的连接没有意义，
 * 而放行能保证调用方不被永久卡住。
 * The unload path must choose permit: the driver is going away, blocking a
 * pended connection achieves nothing, and permitting guarantees the caller is
 * not stuck forever.
 *
 * 调用方：DriverUnload（必须早于 FwpsCalloutUnregisterById）
 * Called by: DriverUnload, and it MUST run before FwpsCalloutUnregisterById
 * IRQL：PASSIVE_LEVEL
 * 中文关键词：停止定时器，兜底放行，卸载顺序
 * English keywords: stop timer, fallback permit, unload ordering
 */
void AnxPendingShutdown(void)
{
    if (g_Anx.PendingTimerStarted) {
        KeCancelTimer(&g_Anx.PendingTimer);
        KeFlushQueuedDpcs();
        g_Anx.PendingTimerStarted = FALSE;
    }

    AnxPendingAbortAll(ANX_NET_ACTION_ALLOW);
}

/* ==========================================================================
 * 登记与完成 / Register and resolve
 * ========================================================================== */

/*
 * 函数名称：AnxPendingAdd
 * 函数作用：登记一次挂起决策，返回分配的 DecisionId；失败返回 0。
 * Purpose: Registers a pended decision and returns its DecisionId, or 0 on
 *          failure.
 *
 * 返回 0 时调用方绝不能调用 FwpsPendClassify0，必须就地按默认动作裁决，
 * 否则会出现「已挂起但无人负责完成」的悬挂分类。
 * On 0 the caller MUST NOT call FwpsPendClassify0 and must decide in place with
 * the default action, otherwise a classification would be pended with nobody
 * responsible for completing it.
 *
 * 调用方：ALE 分类回调
 * Called by: ALE classify callbacks
 * IRQL：<= DISPATCH_LEVEL
 * 中文关键词：挂起登记，决策编号，容量上限
 * English keywords: pend registration, decision id, capacity cap
 */
UINT64 AnxPendingAdd(_In_ UINT64 ClassifyHandle, _In_ UINT16 LayerId,
                     _In_ const ANX_CONN_INFO* Conn, _In_ UINT32 TimeoutMs)
{
    PANX_PENDING_ENTRY entry;
    KIRQL              oldIrql;
    UINT64             decisionId;

    if (AnxIsShuttingDown() || !AnxIsAttached()) {
        return 0;
    }

    if (InterlockedCompareExchange(&g_Anx.PendingCount, 0, 0) >= (LONG)ANX_NET_MAX_PENDING) {
        AnxWarn("Pending cap %u reached, falling back to default action\n",
                ANX_NET_MAX_PENDING);
        return 0;
    }

    entry = (PANX_PENDING_ENTRY)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                                sizeof(ANX_PENDING_ENTRY),
                                                ANX_TAG_PENDING);
    if (entry == NULL) {
        return 0;
    }

    decisionId = (UINT64)InterlockedIncrement64(&g_Anx.NextDecisionId);

    entry->DecisionId     = decisionId;
    entry->ClassifyHandle = ClassifyHandle;
    entry->LayerId        = LayerId;
    entry->Completed      = FALSE;
    entry->AppIdHash      = Conn->AppIdHash;
    entry->ProcessId      = Conn->ProcessId;
    entry->RemotePort     = Conn->RemotePort;
    entry->Protocol       = (UINT8)Conn->Protocol;
    entry->Direction      = (UINT8)Conn->Direction;
    entry->ExpiryMs       = AnxGetSystemTimeMs() +
                            ((TimeoutMs != 0) ? TimeoutMs : ANX_DEFAULT_PROMPT_MS);
    RtlCopyMemory(&entry->RemoteAddr, &Conn->RemoteAddr, sizeof(ANX_NET_ADDR));

    KeAcquireSpinLock(&g_Anx.PendingLock, &oldIrql);
    InsertTailList(&g_Anx.PendingList, &entry->Link);
    KeReleaseSpinLock(&g_Anx.PendingLock, oldIrql);

    InterlockedIncrement(&g_Anx.PendingCount);

    return decisionId;
}

/*
 * 函数名称：AnxPendingResolve
 * 函数作用：按用户裁决完成一次挂起的分类，并按需写入裁决缓存。
 * Purpose: Completes a pended classification with the user's verdict and
 *          optionally caches it.
 * 参数 Flags: ANX_NET_VF_REMEMBER / ANX_NET_VF_REMEMBER_PROCESS
 * 调用方：IOCTL_ANX_NET_SET_VERDICT 处理分支
 * Called by: the IOCTL_ANX_NET_SET_VERDICT handler
 * IRQL：<= DISPATCH_LEVEL
 * 中文关键词：用户裁决，完成分类，记住选择
 * English keywords: user verdict, complete classify, remember choice
 */
NTSTATUS AnxPendingResolve(_In_ UINT64 DecisionId, _In_ UINT32 Action, _In_ UINT32 Flags,
                           _In_ UINT32 CacheTtlMs)
{
    PANX_PENDING_ENTRY entry = NULL;
    KIRQL              oldIrql;
    PLIST_ENTRY        link;

    if (Action != ANX_NET_ACTION_ALLOW && Action != ANX_NET_ACTION_BLOCK) {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&g_Anx.PendingLock, &oldIrql);
    for (link = g_Anx.PendingList.Flink;
         link != &g_Anx.PendingList;
         link = link->Flink) {
        PANX_PENDING_ENTRY candidate = CONTAINING_RECORD(link, ANX_PENDING_ENTRY, Link);
        if (candidate->DecisionId == DecisionId && !candidate->Completed) {
            candidate->Completed = TRUE;
            RemoveEntryList(link);
            entry = candidate;
            break;
        }
    }
    KeReleaseSpinLock(&g_Anx.PendingLock, oldIrql);

    if (entry == NULL) {
        /* 已被超时扫描抢先完成，或者是伪造的 DecisionId */
        /* Already completed by the timeout sweep, or a bogus DecisionId */
        return STATUS_NOT_FOUND;
    }

    if ((Flags & (ANX_NET_VF_REMEMBER | ANX_NET_VF_REMEMBER_PROCESS)) != 0) {
        ANX_CONN_INFO conn;

        RtlZeroMemory(&conn, sizeof(conn));
        conn.ProcessId  = entry->ProcessId;
        conn.AppIdHash  = entry->AppIdHash;
        conn.Direction  = entry->Direction;
        conn.Protocol   = entry->Protocol;
        conn.RemotePort = entry->RemotePort;
        RtlCopyMemory(&conn.RemoteAddr, &entry->RemoteAddr, sizeof(ANX_NET_ADDR));

        AnxCacheInsert(&conn, Action,
                       (BOOLEAN)((Flags & ANX_NET_VF_REMEMBER_PROCESS) != 0),
                       CacheTtlMs);
    }

    AnxStatCountConnection(entry->ProcessId, entry->AppIdHash,
                           (BOOLEAN)(Action == ANX_NET_ACTION_ALLOW));

    AnxPendingEmitResult(entry, Action, FALSE);
    AnxPendingCompleteEntry(entry, Action);

    return STATUS_SUCCESS;
}

/*
 * 函数名称：AnxPendingCancel
 * 函数作用：撤销一次已登记但未成功挂起的决策（FwpsPendClassify0 失败时调用）。
 * Purpose: Cancels a registered-but-never-pended decision. Called when
 *          FwpsPendClassify0 fails after AnxPendingAdd succeeded.
 *
 * 与 AnxPendingResolve 的关键区别：不调用 FwpsCompleteClassify0。
 * 分类从未真正挂起，Complete 属于未定义行为（VUL-093）。
 * Key difference from AnxPendingResolve: does NOT call FwpsCompleteClassify0.
 * The classification was never pended; completing it is undefined behaviour.
 *
 * 调用方：ALE 分类回调（FwpsPendClassify0 失败路径）
 * Called by: ALE classify callbacks on FwpsPendClassify0 failure
 * IRQL：<= DISPATCH_LEVEL
 * 中文关键词：撤销登记，未挂起回滚，释放句柄
 * English keywords: cancel registration, non-pended rollback, release handle
 */
void AnxPendingCancel(_In_ UINT64 DecisionId)
{
    PANX_PENDING_ENTRY entry = NULL;
    KIRQL              oldIrql;
    PLIST_ENTRY        link;

    KeAcquireSpinLock(&g_Anx.PendingLock, &oldIrql);
    for (link = g_Anx.PendingList.Flink;
         link != &g_Anx.PendingList;
         link = link->Flink) {
        PANX_PENDING_ENTRY candidate = CONTAINING_RECORD(link, ANX_PENDING_ENTRY, Link);
        if (candidate->DecisionId == DecisionId && !candidate->Completed) {
            candidate->Completed = TRUE;
            RemoveEntryList(link);
            entry = candidate;
            break;
        }
    }
    KeReleaseSpinLock(&g_Anx.PendingLock, oldIrql);

    if (entry == NULL) {
        return;
    }

    /* 仅释放句柄，不完成分类 / release handle only, never complete */
    FwpsReleaseClassifyHandle0(entry->ClassifyHandle);
    InterlockedDecrement(&g_Anx.PendingCount);
    ExFreePoolWithTag(entry, ANX_TAG_PENDING);
}

/*
 * 函数名称：AnxPendingAbortAll
 * 函数作用：以指定动作完成全部挂起决策，用于用户态断开与驱动卸载。
 * Purpose: Completes every pended decision with the given action, used on
 *          user-mode detach and on driver unload.
 * 调用方：AnxPendingShutdown、IRP_MJ_CLEANUP（用户态掉线）
 * Called by: AnxPendingShutdown and IRP_MJ_CLEANUP on user-mode disconnect
 * IRQL：<= DISPATCH_LEVEL
 * 中文关键词：全量完成，掉线兜底，防止悬挂
 * English keywords: complete all, disconnect fallback, hang prevention
 */
void AnxPendingAbortAll(_In_ UINT32 Action)
{
    LIST_ENTRY drained;
    KIRQL      oldIrql;

    if (Action != ANX_NET_ACTION_BLOCK) {
        Action = ANX_NET_ACTION_ALLOW;
    }

    InitializeListHead(&drained);

    KeAcquireSpinLock(&g_Anx.PendingLock, &oldIrql);
    while (!IsListEmpty(&g_Anx.PendingList)) {
        PLIST_ENTRY        link  = RemoveHeadList(&g_Anx.PendingList);
        PANX_PENDING_ENTRY entry = CONTAINING_RECORD(link, ANX_PENDING_ENTRY, Link);
        entry->Completed = TRUE;
        InsertTailList(&drained, link);
    }
    KeReleaseSpinLock(&g_Anx.PendingLock, oldIrql);

    while (!IsListEmpty(&drained)) {
        PLIST_ENTRY        link  = RemoveHeadList(&drained);
        PANX_PENDING_ENTRY entry = CONTAINING_RECORD(link, ANX_PENDING_ENTRY, Link);
        AnxPendingCompleteEntry(entry, Action);
    }
}
