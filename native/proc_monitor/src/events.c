/*++
Copyright (c) AnXin Security. All rights reserved.

Module Name:
    events.c

Abstract:
    AnXinProcMon.sys 双事件队列 + 取消安全 IRP 队列（CSQ）。
    Two event queues (lifecycle / behavior) plus the cancel-safe IRP queue (CSQ)
    carrying the inverted call. 模式移植自 net_filter/src/events.c，按契约 v6
    §3.5 扩展为：双队列、满则丢最旧 + DROP_MARKER、每队列独立 sequence
    （InterlockedIncrement64 原子递增）、LOOKASIDE 节点壳 + 按需负载分配。

    队列策略（§3.5 / 防 OOM 蓝屏）：
    - 生命周期队列：容量 2048，满 → 丢最旧 + 注入 DROP_MARKER（含丢弃数）
    - 行为队列：容量 8192，同策略
    - 事件节点壳走 LOOKASIDE（有界复用），负载按需非分页池分配（≤4KB），
      分配失败 → 事件降级为无负载，绝不阻塞回调。

    The queue strategy (contract §3.5 / OOM-BSOD defense):
    - Lifecycle queue: depth 2048, full -> drop oldest + DROP_MARKER with count
    - Behavior queue: depth 8192, same policy
    - Node shells come from a LOOKASIDE list (bounded reuse); payloads are
      on-demand non-paged allocations (<= 4KB); allocation failure degrades
      the event to header-only and never blocks the callback.

Environment:
    Kernel mode only.

--*/

#include "anx_proc_internal.h"

static LOOKASIDE_LIST_EX g_NodeLookaside;
static BOOLEAN           g_NodeLookasideReady = FALSE;

static void AnxProcPostDropMarker(_In_ PANX_PROC_QUEUE Queue);

/* ==========================================================================
 * CSQ 回调（每个队列一份，用 Queue 上下文区分）
 * CSQ callbacks (one set per queue, distinguished by the queue context)
 * ========================================================================== */

static IO_CSQ_INSERT_IRP            AnxProcCsqInsertIrp;
static IO_CSQ_REMOVE_IRP            AnxProcCsqRemoveIrp;
static IO_CSQ_PEEK_NEXT_IRP         AnxProcCsqPeekNextIrp;
static IO_CSQ_ACQUIRE_LOCK          AnxProcCsqAcquireLock;
static IO_CSQ_RELEASE_LOCK          AnxProcCsqReleaseLock;
static IO_CSQ_COMPLETE_CANCELED_IRP AnxProcCsqCompleteCanceledIrp;

_IRQL_raises_(DISPATCH_LEVEL)
_IRQL_saves_global_(OldIrql, Csq)
static VOID AnxProcCsqAcquireLock(_In_ PIO_CSQ Csq, _Out_ PKIRQL Irql)
{
    PANX_PROC_QUEUE queue = CONTAINING_RECORD(Csq, ANX_PROC_QUEUE, Csq);
    KeAcquireSpinLock(&queue->IrpQueueLock, Irql);
}

_IRQL_restores_global_(OldIrql, Csq)
static VOID AnxProcCsqReleaseLock(_In_ PIO_CSQ Csq, _In_ KIRQL Irql)
{
    PANX_PROC_QUEUE queue = CONTAINING_RECORD(Csq, ANX_PROC_QUEUE, Csq);
    KeReleaseSpinLock(&queue->IrpQueueLock, Irql);
}

static VOID AnxProcCsqInsertIrp(_In_ PIO_CSQ Csq, _In_ PIRP Irp)
{
    PANX_PROC_QUEUE queue = CONTAINING_RECORD(Csq, ANX_PROC_QUEUE, Csq);
    InsertTailList(&queue->IrpQueue, &Irp->Tail.Overlay.ListEntry);
}

static VOID AnxProcCsqRemoveIrp(_In_ PIO_CSQ Csq, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(Csq);
    RemoveEntryList(&Irp->Tail.Overlay.ListEntry);
    InitializeListHead(&Irp->Tail.Overlay.ListEntry);
}

static PIRP AnxProcCsqPeekNextIrp(_In_ PIO_CSQ Csq, _In_ PIRP Irp,
                                  _In_ PVOID PeekContext)
{
    PANX_PROC_QUEUE queue = CONTAINING_RECORD(Csq, ANX_PROC_QUEUE, Csq);
    PLIST_ENTRY next;

    UNREFERENCED_PARAMETER(PeekContext);

    next = (Irp == NULL) ? queue->IrpQueue.Flink : Irp->Tail.Overlay.ListEntry.Flink;

    if (next == &queue->IrpQueue) {
        return NULL;
    }
    return CONTAINING_RECORD(next, IRP, Tail.Overlay.ListEntry);
}

static VOID AnxProcCsqCompleteCanceledIrp(_In_ PIO_CSQ Csq, _In_ PIRP Irp)
{
    PANX_PROC_QUEUE queue = CONTAINING_RECORD(Csq, ANX_PROC_QUEUE, Csq);
    UNREFERENCED_PARAMETER(queue);

    Irp->IoStatus.Status = STATUS_CANCELLED;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

/*
 * 函数名称：AnxProcCsqInitialize
 * 函数作用：初始化单个队列的取消安全 IRP 队列。
 * Purpose: Initializes the cancel-safe IRP queue of one event queue.
 * IRQL：PASSIVE_LEVEL
 */
static void AnxProcCsqInitialize(_In_ PANX_PROC_QUEUE Queue)
{
    InitializeListHead(&Queue->IrpQueue);
    KeInitializeSpinLock(&Queue->IrpQueueLock);

    (void)IoCsqInitialize(&Queue->Csq,
                          AnxProcCsqInsertIrp,
                          AnxProcCsqRemoveIrp,
                          AnxProcCsqPeekNextIrp,
                          AnxProcCsqAcquireLock,
                          AnxProcCsqReleaseLock,
                          AnxProcCsqCompleteCanceledIrp);
}

/* ==========================================================================
 * 事件队列 / Event queues
 * ========================================================================== */

/*
 * 函数名称：AnxProcEventsInitialize
 * 函数作用：初始化双队列（含事件链表、锁、CSQ）与节点 LOOKASIDE。
 * Purpose: Initializes both queues and the node lookaside list.
 * IRQL：PASSIVE_LEVEL
 */
NTSTATUS AnxProcEventsInitialize(void)
{
    NTSTATUS status;

    status = ExInitializeLookasideListEx(&g_NodeLookaside, NULL, NULL,
                                         NonPagedPoolNx, 0,
                                         sizeof(ANX_PROC_EVENT_NODE),
                                         ANX_PROC_TAG_NODE, 0);
    if (!NT_SUCCESS(status)) {
        AnxProcError("ExInitializeLookasideListEx(node) failed 0x%08X\n", status);
        return status;
    }
    g_NodeLookasideReady = TRUE;

    InitializeListHead(&g_AnxProc.LifecycleQueue.EventList);
    KeInitializeSpinLock(&g_AnxProc.LifecycleQueue.EventLock);
    g_AnxProc.LifecycleQueue.MaxDepth = ANX_PROC_MAX_LIFECYCLE_QUEUE;
    /* 生命周期主干（CREATE/EXIT/REMOTE_THREAD/IMAGE_LOAD）满时丢新保旧：
       攻击链起点往往最早产生，必须先保住（§3.5 分级丢弃） */
    g_AnxProc.LifecycleQueue.DropNewest = TRUE;
    AnxProcCsqInitialize(&g_AnxProc.LifecycleQueue);

    InitializeListHead(&g_AnxProc.BehaviorQueue.EventList);
    KeInitializeSpinLock(&g_AnxProc.BehaviorQueue.EventLock);
    g_AnxProc.BehaviorQueue.MaxDepth = ANX_PROC_MAX_BEHAVIOR_QUEUE;
    /* 行为事件（FILE/REG/NET）高频且时效性强：满时丢旧保新（§3.5） */
    g_AnxProc.BehaviorQueue.DropNewest = FALSE;
    AnxProcCsqInitialize(&g_AnxProc.BehaviorQueue);

    return STATUS_SUCCESS;
}

/*
 * 函数名称：AnxProcEventsShutdown
 * 函数作用：完成全部挂起 IRP、释放未消费事件与负载、销毁 LOOKASIDE。
 * Purpose: Completes pended IRPs, frees unconsumed events & payloads, deletes
 *          the lookaside list.
 * IRQL：PASSIVE_LEVEL
 */
void AnxProcEventsShutdown(void)
{
    KIRQL      oldIrql;
    LIST_ENTRY reaped;
    ULONG      queueIdx;

    for (queueIdx = 0; queueIdx < 2; queueIdx++) {
        PANX_PROC_QUEUE queue = (queueIdx == 0)
            ? &g_AnxProc.LifecycleQueue : &g_AnxProc.BehaviorQueue;

        AnxProcCsqFlushAll(queue, STATUS_DEVICE_NOT_READY);

        InitializeListHead(&reaped);
        KeAcquireSpinLock(&queue->EventLock, &oldIrql);
        while (!IsListEmpty(&queue->EventList)) {
            InsertTailList(&reaped, RemoveHeadList(&queue->EventList));
        }
        InterlockedExchange(&queue->EventCount, 0);
        KeReleaseSpinLock(&queue->EventLock, oldIrql);

        while (!IsListEmpty(&reaped)) {
            PLIST_ENTRY link = RemoveHeadList(&reaped);
            PANX_PROC_EVENT_NODE node =
                CONTAINING_RECORD(link, ANX_PROC_EVENT_NODE, Link);
            if (node->Payload != NULL) {
                ExFreePoolWithTag(node->Payload, ANX_PROC_TAG_PAYLOAD);
            }
            if (g_NodeLookasideReady) {
                ExFreeToLookasideListEx(&g_NodeLookaside, node);
            }
        }
    }

    if (g_NodeLookasideReady) {
        ExDeleteLookasideListEx(&g_NodeLookaside);
        g_NodeLookasideReady = FALSE;
    }
}

/*
 * 函数名称：AnxProcCsqFlushAll
 * 函数作用：以指定状态完成并清空单个队列全部挂起的 GET_EVENTS IRP。
 * Purpose: Completes every pended IRP of one queue with a status.
 * IRQL：<= DISPATCH_LEVEL
 */
void AnxProcCsqFlushAll(_In_ PANX_PROC_QUEUE Queue, _In_ NTSTATUS Status)
{
    PIRP irp;

    while ((irp = IoCsqRemoveNextIrp(&Queue->Csq, NULL)) != NULL) {
        irp->IoStatus.Status = Status;
        irp->IoStatus.Information = 0;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
    }
}

/*
 * 函数名称：AnxProcQueueByKind
 * 函数作用：按事件类型返回所属队列（生命周期 vs 行为）。
 * Purpose: Returns the owning queue for an event type.
 * IRQL：任何 / any
 */
ANX_PROC_QUEUE* AnxProcQueueByKind(_In_ UINT16 EventType)
{
    switch (EventType) {
    case ANX_PROC_EVT_PROC_CREATE:
    case ANX_PROC_EVT_PROC_EXIT:
    case ANX_PROC_EVT_IMAGE_LOAD:
    case ANX_PROC_EVT_REMOTE_THREAD:
        return &g_AnxProc.LifecycleQueue;
    default:
        return &g_AnxProc.BehaviorQueue;
    }
}

/*
 * 函数名称：AnxProcPostEvent
 * 函数作用：构造事件头、入队并尝试与挂起 IRP 配对完成。
 * Purpose: Builds the header, enqueues and tries to pair with pended IRPs.
 *
 * 回调热路径纪律（§3.3）：全程 O(1) + 无分页操作 + 有界内存，
 * 绝不阻塞关键路径之外的系统操作；锁内不进行任何分页访问。
 *
 * Payload 所有权：本函数只拷贝，从不释放调用方内存；调用方负责用
 * ANX_PROC_TAG_PAYLOAD 释放（与 net_filter AnxEventPost 同约定）。
 * Payload ownership: this function copies only and never frees the caller's
 * memory; the caller frees it with ANX_PROC_TAG_PAYLOAD (same convention as
 * net_filter's AnxEventPost).
 *
 * IRQL：<= DISPATCH_LEVEL
 */
void AnxProcPostEvent(_In_ PANX_PROC_QUEUE Queue, _In_ UINT16 EventType,
                      _In_ UINT16 Flags, _In_ ULONG Pid, _In_ ULONG ParentPid,
                      _In_ ULONG CreatorPid, _In_ ULONG SessionId,
                      _In_ ULONG ExitStatus, _In_ UINT64 CreateTime,
                      _In_reads_opt_(PayloadSize) const void* Payload,
                      _In_ ULONG PayloadSize)
{
    PANX_PROC_EVENT_NODE node;
    PANX_PROC_EVENT_NODE evicted = NULL;
    KIRQL                oldIrql;
    ULONG                payloadSize = PayloadSize;

    if (!g_NodeLookasideReady || AnxProcIsShuttingDown()) {
        return;
    }
    if (!AnxProcIsAttached()) {
        /* 未接管：没有消费者，排队只会占用非分页池（net_filter 同策略） */
        return;
    }

    if (payloadSize > ANX_PROC_MAX_PAYLOAD) {
        payloadSize = ANX_PROC_MAX_PAYLOAD;
    }

    node = (PANX_PROC_EVENT_NODE)ExAllocateFromLookasideListEx(&g_NodeLookaside);
    if (node == NULL) {
        InterlockedIncrement64(&Queue->EventsDropped);
        InterlockedIncrement(&Queue->DroppedSinceLast);
        return;
    }

    RtlZeroMemory(&node->Hdr, sizeof(node->Hdr));
    node->Payload = NULL;
    node->PayloadSize = 0;

    if (payloadSize > 0 && Payload != NULL) {
        PUINT8 copy = (PUINT8)ExAllocatePool2(POOL_FLAG_NON_PAGED, payloadSize,
                                              ANX_PROC_TAG_PAYLOAD);
        if (copy == NULL) {
            /* 分配失败 → 降级为无负载事件，绝不阻塞回调 */
            payloadSize = 0;
        } else {
            RtlCopyMemory(copy, Payload, payloadSize);
            node->Payload = copy;
            node->PayloadSize = payloadSize;
        }
    }

    node->Hdr.event_time  = AnxProcGetFileTime();
    node->Hdr.create_time = CreateTime;
    node->Hdr.pid         = Pid;
    node->Hdr.parent_pid  = ParentPid;
    node->Hdr.creator_pid = CreatorPid;
    node->Hdr.session_id  = SessionId;
    node->Hdr.exit_status = ExitStatus;
    node->Hdr.sequence    = (UINT32)InterlockedIncrement64(&Queue->Sequence);
    node->Hdr.event_type  = EventType;
    node->Hdr.flags       = Flags;
    node->Hdr.payload_len = (UINT16)payloadSize;

    KeAcquireSpinLock(&Queue->EventLock, &oldIrql);

    if (Queue->EventCount >= Queue->MaxDepth) {
        if (Queue->DropNewest) {
            /*
             * 丢新保旧（§3.5 分级丢弃）：生命周期主干事件满时拒绝新事件，
             * 保住最早产生的攻击链起点（CREATE/EXIT/REMOTE_THREAD）。
             * Drop-newest policy (§3.5): when the lifecycle backbone is full,
             * refuse the newcomer and keep the earliest attack-chain origin.
             */
            KeReleaseSpinLock(&Queue->EventLock, oldIrql);
            InterlockedIncrement64(&Queue->EventsDropped);
            InterlockedIncrement(&Queue->DroppedSinceLast);
            if (node->Payload != NULL) {
                ExFreePoolWithTag(node->Payload, ANX_PROC_TAG_PAYLOAD);
            }
            ExFreeToLookasideListEx(&g_NodeLookaside, node);
            /* 注入 DROP_MARKER，驱动用户态全盘快照纠偏（§4.4） */
            AnxProcPostDropMarker(Queue);
            return;
        }
        /* 丢旧保新：行为事件高频且时效性强，保留最新观测 */
        PLIST_ENTRY oldest = RemoveHeadList(&Queue->EventList);
        evicted = CONTAINING_RECORD(oldest, ANX_PROC_EVENT_NODE, Link);
        Queue->EventCount--;
    }

    InsertTailList(&Queue->EventList, &node->Link);
    Queue->EventCount++;

    KeReleaseSpinLock(&Queue->EventLock, oldIrql);

    InterlockedIncrement64(&Queue->EventsQueued);
    AnxProcTouchHealth();

    if (evicted != NULL) {
        InterlockedIncrement64(&Queue->EventsDropped);
        InterlockedIncrement(&Queue->DroppedSinceLast);
        if (evicted->Payload != NULL) {
            ExFreePoolWithTag(evicted->Payload, ANX_PROC_TAG_PAYLOAD);
        }
        ExFreeToLookasideListEx(&g_NodeLookaside, evicted);
        /* 注入 DROP_MARKER，驱动用户态全盘快照纠偏（§4.4） */
        AnxProcPostDropMarker(Queue);
    }

    AnxProcDrainToIrps(Queue);
}

/*
 * 函数名称：AnxProcPostDropMarker
 * 函数作用：队列满丢弃后注入 DROP_MARKER 事件（含丢弃计数），驱动用户态
 * 快照纠偏（§4.4）。
 * Purpose: Injects a DROP_MARKER event after queue eviction so user mode can
 *          trigger a full-snapshot reconcile (contract §4.4).
 * IRQL：<= DISPATCH_LEVEL
 */
static void AnxProcPostDropMarker(_In_ PANX_PROC_QUEUE Queue)
{
    UINT32 dropped = (UINT32)InterlockedExchange(&Queue->DroppedSinceLast, 0);
    KIRQL  oldIrql;

    if (dropped == 0) {
        return;
    }
    /* DROP_MARKER 直接构造节点入队（绕过 AnxProcPostEvent 的满则再丢逻辑） */
    PANX_PROC_EVENT_NODE node =
        (PANX_PROC_EVENT_NODE)ExAllocateFromLookasideListEx(&g_NodeLookaside);
    if (node == NULL) {
        return;
    }

    RtlZeroMemory(&node->Hdr, sizeof(node->Hdr));
    node->Payload = NULL;
    node->PayloadSize = 0;

    node->Hdr.event_time  = AnxProcGetFileTime();
    node->Hdr.sequence    = (UINT32)InterlockedIncrement64(&Queue->Sequence);
    node->Hdr.event_type  = ANX_PROC_EVT_DROP_MARKER;
    node->Hdr.payload_len = sizeof(UINT32);

    node->Payload = (PUINT8)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(UINT32),
                                            ANX_PROC_TAG_PAYLOAD);
    if (node->Payload != NULL) {
        RtlCopyMemory(node->Payload, &dropped, sizeof(UINT32));
        node->PayloadSize = sizeof(UINT32);
    } else {
        node->Hdr.payload_len = 0;
    }

    KeAcquireSpinLock(&Queue->EventLock, &oldIrql);
    if (Queue->EventCount >= Queue->MaxDepth) {
        /* 极端：连 marker 都放不进，直接丢弃计数归零重建 */
        PLIST_ENTRY oldest = RemoveHeadList(&Queue->EventList);
        PANX_PROC_EVENT_NODE evicted =
            CONTAINING_RECORD(oldest, ANX_PROC_EVENT_NODE, Link);
        Queue->EventCount--;
        if (evicted->Payload != NULL) {
            ExFreePoolWithTag(evicted->Payload, ANX_PROC_TAG_PAYLOAD);
        }
        ExFreeToLookasideListEx(&g_NodeLookaside, evicted);
        InterlockedIncrement64(&Queue->EventsDropped);
    }
    InsertTailList(&Queue->EventList, &node->Link);
    Queue->EventCount++;
    KeReleaseSpinLock(&Queue->EventLock, oldIrql);

    InterlockedIncrement64(&Queue->EventsQueued);
    AnxProcTouchHealth();
    AnxProcDrainToIrps(Queue);
}

/*
 * 函数名称：AnxProcDrainToIrps
 * 函数作用：把单个队列中的事件与挂起的 GET_EVENTS IRP 逐一配对完成。
 * Purpose: Pairs queued events with pended GET_EVENTS IRPs and completes them.
 * IRQL：<= DISPATCH_LEVEL
 */
void AnxProcDrainToIrps(_In_ PANX_PROC_QUEUE Queue)
{
    for (;;) {
        KIRQL                 oldIrql;
        PANX_PROC_EVENT_NODE node = NULL;
        PIRP                  irp;

        KeAcquireSpinLock(&Queue->EventLock, &oldIrql);
        if (!IsListEmpty(&Queue->EventList)) {
            PLIST_ENTRY link = RemoveHeadList(&Queue->EventList);
            node = CONTAINING_RECORD(link, ANX_PROC_EVENT_NODE, Link);
            Queue->EventCount--;
        }
        KeReleaseSpinLock(&Queue->EventLock, oldIrql);

        if (node == NULL) {
            return;
        }

        irp = IoCsqRemoveNextIrp(&Queue->Csq, NULL);
        if (irp == NULL) {
            /* 没有消费者，放回队首 */
            KeAcquireSpinLock(&Queue->EventLock, &oldIrql);
            InsertHeadList(&Queue->EventList, &node->Link);
            Queue->EventCount++;
            KeReleaseSpinLock(&Queue->EventLock, oldIrql);
            return;
        }

        /*
         * IRP 输出缓冲长度在 IOCTL 分支已校验 >= 48 字节事件头；
         * 事件按「头 + 负载」原样拷贝，长度 = 48 + payload_len。
         * 若用户态缓冲装不下完整负载，截断负载（事件头完整），
         * 保证用户态至少能感知事件存在与丢包计数。
         */
        {
            PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(irp);
            ULONG outLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
            ULONG payloadLen = node->PayloadSize;
            ULONG total;

            if (payloadLen > (outLen > sizeof(ANX_PROC_EVENT_HDR)
                                  ? outLen - sizeof(ANX_PROC_EVENT_HDR) : 0)) {
                payloadLen = (outLen > sizeof(ANX_PROC_EVENT_HDR))
                                 ? outLen - sizeof(ANX_PROC_EVENT_HDR) : 0;
            }
            total = sizeof(ANX_PROC_EVENT_HDR) + payloadLen;

            RtlCopyMemory(irp->AssociatedIrp.SystemBuffer, &node->Hdr,
                          sizeof(ANX_PROC_EVENT_HDR));
            if (node->Payload != NULL && payloadLen > 0) {
                RtlCopyMemory((PUINT8)irp->AssociatedIrp.SystemBuffer +
                              sizeof(ANX_PROC_EVENT_HDR),
                              node->Payload, payloadLen);
            }

            irp->IoStatus.Status = STATUS_SUCCESS;
            irp->IoStatus.Information = total;
        }

        IoCompleteRequest(irp, IO_NO_INCREMENT);

        if (node->Payload != NULL) {
            ExFreePoolWithTag(node->Payload, ANX_PROC_TAG_PAYLOAD);
        }
        ExFreeToLookasideListEx(&g_NodeLookaside, node);
    }
}
