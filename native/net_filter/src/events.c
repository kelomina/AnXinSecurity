/*++
Copyright (c) AnXin Security. All rights reserved.

Module Name:
    events.c

Abstract:
    内核 → 用户的事件队列，以及承载「倒置调用」的取消安全 IRP 队列（CSQ）。
    The kernel-to-user event queue and the cancel-safe IRP queue (CSQ) that
    carries the inverted call.

    工作方式 / How it works:
    1. 用户态预先投递若干重叠的 IOCTL_ANX_NET_GET_EVENT，驱动把 IRP 挂进 CSQ。
       User mode posts several overlapped IOCTL_ANX_NET_GET_EVENT requests and
       the driver parks the IRPs in the CSQ.
    2. 分类回调在 DISPATCH_LEVEL 调 AnxEventPost 投递事件。
       Classify callbacks post events from DISPATCH_LEVEL via AnxEventPost.
    3. AnxEventDrainToIrps 把事件与挂起的 IRP 配对完成。
       AnxEventDrainToIrps pairs events with pended IRPs and completes them.

    队列满时丢弃最旧的事件并累加丢弃计数，随下一条事件回传给用户态；
    绝不因为用户态消费不及时而阻塞网络路径。
    When the queue is full the oldest event is dropped and a drop counter is
    carried on the next event. The network path is never blocked because user
    mode is slow to consume.

Environment:
    Kernel mode only.

--*/

#include "anx_net_internal.h"

static LOOKASIDE_LIST_EX g_EventLookaside;
static BOOLEAN           g_EventLookasideReady = FALSE;

/* ==========================================================================
 * CSQ 回调 / CSQ callbacks
 * ========================================================================== */

static IO_CSQ_INSERT_IRP           AnxCsqInsertIrp;
static IO_CSQ_REMOVE_IRP           AnxCsqRemoveIrp;
static IO_CSQ_PEEK_NEXT_IRP        AnxCsqPeekNextIrp;
static IO_CSQ_ACQUIRE_LOCK         AnxCsqAcquireLock;
static IO_CSQ_RELEASE_LOCK         AnxCsqReleaseLock;
static IO_CSQ_COMPLETE_CANCELED_IRP AnxCsqCompleteCanceledIrp;

_IRQL_raises_(DISPATCH_LEVEL)
_IRQL_saves_global_(OldIrql, Csq)
static VOID AnxCsqAcquireLock(_In_ PIO_CSQ Csq, _Out_ PKIRQL Irql)
{
    UNREFERENCED_PARAMETER(Csq);
    KeAcquireSpinLock(&g_Anx.IrpQueueLock, Irql);
}

_IRQL_restores_global_(OldIrql, Csq)
static VOID AnxCsqReleaseLock(_In_ PIO_CSQ Csq, _In_ KIRQL Irql)
{
    UNREFERENCED_PARAMETER(Csq);
    KeReleaseSpinLock(&g_Anx.IrpQueueLock, Irql);
}

static VOID AnxCsqInsertIrp(_In_ PIO_CSQ Csq, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(Csq);
    InsertTailList(&g_Anx.IrpQueue, &Irp->Tail.Overlay.ListEntry);
}

static VOID AnxCsqRemoveIrp(_In_ PIO_CSQ Csq, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(Csq);
    RemoveEntryList(&Irp->Tail.Overlay.ListEntry);
    InitializeListHead(&Irp->Tail.Overlay.ListEntry);
}

static PIRP AnxCsqPeekNextIrp(_In_ PIO_CSQ Csq, _In_ PIRP Irp, _In_ PVOID PeekContext)
{
    PLIST_ENTRY next;

    UNREFERENCED_PARAMETER(Csq);
    UNREFERENCED_PARAMETER(PeekContext);

    next = (Irp == NULL) ? g_Anx.IrpQueue.Flink : Irp->Tail.Overlay.ListEntry.Flink;

    if (next == &g_Anx.IrpQueue) {
        return NULL;
    }

    return CONTAINING_RECORD(next, IRP, Tail.Overlay.ListEntry);
}

static VOID AnxCsqCompleteCanceledIrp(_In_ PIO_CSQ Csq, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(Csq);
    Irp->IoStatus.Status = STATUS_CANCELLED;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

/*
 * 函数名称：AnxCsqInitialize
 * 函数作用：初始化取消安全 IRP 队列。
 * Purpose: Initializes the cancel-safe IRP queue.
 * 调用方：AnxEventsInitialize
 * Called by: AnxEventsInitialize
 * IRQL：PASSIVE_LEVEL
 * 中文关键词：取消安全队列，倒置调用
 * English keywords: cancel-safe queue, inverted call
 */
void AnxCsqInitialize(void)
{
    InitializeListHead(&g_Anx.IrpQueue);
    KeInitializeSpinLock(&g_Anx.IrpQueueLock);

    /* IoCsqInitialize 永不失败 / IoCsqInitialize cannot fail */
    (void)IoCsqInitialize(&g_Anx.Csq,
                          AnxCsqInsertIrp,
                          AnxCsqRemoveIrp,
                          AnxCsqPeekNextIrp,
                          AnxCsqAcquireLock,
                          AnxCsqReleaseLock,
                          AnxCsqCompleteCanceledIrp);
}

/*
 * 函数名称：AnxCsqFlushAll
 * 函数作用：以指定状态完成并清空全部挂起的 GET_EVENT IRP。
 * Purpose: Completes and drains every pended GET_EVENT IRP with a status.
 * 调用方：句柄关闭（IRP_MJ_CLEANUP）、DriverUnload
 * Called by: handle close (IRP_MJ_CLEANUP) and DriverUnload
 * IRQL：<= DISPATCH_LEVEL
 * 中文关键词：清空队列，完成请求，卸载
 * English keywords: drain queue, complete requests, unload
 */
void AnxCsqFlushAll(_In_ NTSTATUS Status)
{
    PIRP irp;

    while ((irp = IoCsqRemoveNextIrp(&g_Anx.Csq, NULL)) != NULL) {
        irp->IoStatus.Status = Status;
        irp->IoStatus.Information = 0;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
    }
}

/* ==========================================================================
 * 事件队列 / Event queue
 * ========================================================================== */

/*
 * 函数名称：AnxEventsInitialize
 * 函数作用：初始化事件链表、事件节点后备列表与 CSQ。
 * Purpose: Initializes the event list, the event-node lookaside list and the CSQ.
 * 调用方：DriverEntry
 * Called by: DriverEntry
 * IRQL：PASSIVE_LEVEL
 * 中文关键词：事件队列初始化，后备列表
 * English keywords: event queue init, lookaside list
 */
NTSTATUS AnxEventsInitialize(void)
{
    NTSTATUS status;

    InitializeListHead(&g_Anx.EventList);
    KeInitializeSpinLock(&g_Anx.EventLock);

    status = ExInitializeLookasideListEx(&g_EventLookaside, NULL, NULL,
                                         NonPagedPoolNx, 0,
                                         sizeof(ANX_EVENT_NODE), ANX_TAG_EVENT, 0);
    if (!NT_SUCCESS(status)) {
        AnxError("ExInitializeLookasideListEx(event) failed 0x%08X\n", status);
        return status;
    }
    g_EventLookasideReady = TRUE;

    AnxCsqInitialize();
    return STATUS_SUCCESS;
}

/*
 * 函数名称：AnxEventsShutdown
 * 函数作用：完成全部挂起 IRP、释放未消费事件、销毁后备列表。
 * Purpose: Completes pended IRPs, frees unconsumed events, destroys lookaside.
 * 调用方：DriverUnload、DriverEntry 失败回滚
 * Called by: DriverUnload and DriverEntry rollback
 * IRQL：PASSIVE_LEVEL
 * 中文关键词：事件清理，卸载
 * English keywords: event cleanup, unload
 */
void AnxEventsShutdown(void)
{
    KIRQL      oldIrql;
    LIST_ENTRY reaped;

    AnxCsqFlushAll(STATUS_DEVICE_NOT_READY);

    InitializeListHead(&reaped);

    KeAcquireSpinLock(&g_Anx.EventLock, &oldIrql);
    while (!IsListEmpty(&g_Anx.EventList)) {
        InsertTailList(&reaped, RemoveHeadList(&g_Anx.EventList));
    }
    InterlockedExchange(&g_Anx.EventCount, 0);
    KeReleaseSpinLock(&g_Anx.EventLock, oldIrql);

    while (!IsListEmpty(&reaped)) {
        PLIST_ENTRY link = RemoveHeadList(&reaped);
        if (g_EventLookasideReady) {
            ExFreeToLookasideListEx(&g_EventLookaside,
                                    CONTAINING_RECORD(link, ANX_EVENT_NODE, Link));
        }
    }

    if (g_EventLookasideReady) {
        ExDeleteLookasideListEx(&g_EventLookaside);
        g_EventLookasideReady = FALSE;
    }
}

/*
 * 函数名称：AnxEventBuildFromConn
 * 函数作用：用连接信息填充一条事件结构。
 * Purpose: Populates an event structure from connection info.
 *
 * 结构体先整体清零：事件会原样拷到用户态缓冲，任何未初始化字节都是内核内存
 * 泄漏。
 * The structure is zeroed first: the event is copied verbatim to a user buffer,
 * so any uninitialized byte would be a kernel memory disclosure.
 *
 * 调用方：ALE 与检查回调
 * Called by: the ALE and inspection callbacks
 * IRQL：<= DISPATCH_LEVEL
 * 中文关键词：事件构造，清零，信息泄漏防护
 * English keywords: event construction, zeroing, info-leak prevention
 */
void AnxEventBuildFromConn(_Out_ ANX_NET_EVENT* Event, _In_ const ANX_CONN_INFO* Conn,
                           _In_ UINT32 Kind, _In_ UINT32 Action, _In_ UINT32 RuleId)
{
    SIZE_T pathChars = 0;

    RtlZeroMemory(Event, sizeof(ANX_NET_EVENT));

    Event->Size        = sizeof(ANX_NET_EVENT);
    Event->Kind        = Kind;
    Event->TimestampMs = AnxGetSystemTimeMs();
    Event->ProcessId   = Conn->ProcessId;
    Event->Direction   = Conn->Direction;
    Event->Protocol    = Conn->Protocol;
    Event->LocalPort   = Conn->LocalPort;
    Event->RemotePort  = Conn->RemotePort;
    Event->RuleId      = RuleId;
    Event->Action      = Action;
    Event->AppIdHash   = Conn->AppIdHash;

    if (Conn->IsLoopback) {
        Event->Flags |= ANX_NET_EVTF_LOOPBACK;
    }
    if (Conn->IsReauthorize) {
        Event->Flags |= ANX_NET_EVTF_REAUTHORIZE;
    }

    RtlCopyMemory(&Event->LocalAddress, &Conn->LocalAddr, sizeof(ANX_NET_ADDR));
    RtlCopyMemory(&Event->RemoteAddress, &Conn->RemoteAddr, sizeof(ANX_NET_ADDR));

    while (pathChars < ANX_NET_MAX_PATH && Conn->ImagePath[pathChars] != L'\0') {
        pathChars++;
    }
    AnxCopyPathToBuffer(Event->ImagePath, ANX_NET_MAX_PATH, Conn->ImagePath, pathChars);
}

/*
 * 函数名称：AnxEventPost
 * 函数作用：把一条事件放入队列并立即尝试与挂起的 IRP 配对完成。
 * Purpose: Enqueues an event and immediately tries to pair it with a pended IRP.
 *
 * 用户态未接管时直接丢弃：没有消费者，排队只会白白占用非分页内存。
 * Events are dropped outright while user mode is not attached — with no
 * consumer, queuing would only burn non-paged pool.
 *
 * 调用方：全部分类回调、挂起超时路径
 * Called by: every classify callback and the pending-timeout path
 * IRQL：<= DISPATCH_LEVEL
 * 中文关键词：事件投递，队列溢出，丢弃计数
 * English keywords: event post, queue overflow, drop counter
 */
void AnxEventPost(_In_ const ANX_NET_EVENT* Event)
{
    PANX_EVENT_NODE node;
    PANX_EVENT_NODE evicted = NULL;
    KIRQL           oldIrql;

    if (!g_EventLookasideReady || AnxIsShuttingDown()) {
        return;
    }
    if (!AnxIsAttached()) {
        return;
    }

    node = (PANX_EVENT_NODE)ExAllocateFromLookasideListEx(&g_EventLookaside);
    if (node == NULL) {
        InterlockedIncrement64(&g_Anx.EventsDropped);
        InterlockedIncrement(&g_Anx.DroppedSinceLast);
        return;
    }

    RtlCopyMemory(&node->Event, Event, sizeof(ANX_NET_EVENT));

    KeAcquireSpinLock(&g_Anx.EventLock, &oldIrql);

    if (g_Anx.EventCount >= (LONG)ANX_NET_MAX_EVENT_QUEUE) {
        /* 丢最旧的一条，保住最新的观测 / drop the oldest, keep the newest */
        PLIST_ENTRY oldest = RemoveHeadList(&g_Anx.EventList);
        evicted = CONTAINING_RECORD(oldest, ANX_EVENT_NODE, Link);
        g_Anx.EventCount--;
    }

    InsertTailList(&g_Anx.EventList, &node->Link);
    g_Anx.EventCount++;

    KeReleaseSpinLock(&g_Anx.EventLock, oldIrql);

    InterlockedIncrement64(&g_Anx.EventsQueued);

    if (evicted != NULL) {
        ExFreeToLookasideListEx(&g_EventLookaside, evicted);
        InterlockedIncrement64(&g_Anx.EventsDropped);
        InterlockedIncrement(&g_Anx.DroppedSinceLast);
    }

    AnxEventDrainToIrps();
}

/*
 * 函数名称：AnxEventDrainToIrps
 * 函数作用：把队列中的事件与挂起的 GET_EVENT IRP 逐一配对完成。
 * Purpose: Pairs queued events with pended GET_EVENT IRPs and completes them.
 *
 * 取不到 IRP 时把事件塞回队首，等下一次投递或下一个 IRP 到达时再处理；
 * IOCTL 分支在挂入 IRP 之后也会调用本函数，以关闭「事件先到、IRP 后到」的竞态。
 * If no IRP is available the event is pushed back to the head and retried on
 * the next post or the next IRP. The IOCTL path also calls this right after
 * queuing an IRP, closing the "event first, IRP second" race.
 *
 * 调用方：AnxEventPost、IOCTL_ANX_NET_GET_EVENT 分支
 * Called by: AnxEventPost and the IOCTL_ANX_NET_GET_EVENT handler
 * IRQL：<= DISPATCH_LEVEL
 * 中文关键词：事件配对，完成请求，竞态关闭
 * English keywords: event pairing, request completion, race closure
 */
void AnxEventDrainToIrps(void)
{
    for (;;) {
        KIRQL           oldIrql;
        PANX_EVENT_NODE node = NULL;
        PIRP            irp;
        LONG            dropped;

        KeAcquireSpinLock(&g_Anx.EventLock, &oldIrql);
        if (!IsListEmpty(&g_Anx.EventList)) {
            PLIST_ENTRY link = RemoveHeadList(&g_Anx.EventList);
            node = CONTAINING_RECORD(link, ANX_EVENT_NODE, Link);
            g_Anx.EventCount--;
        }
        KeReleaseSpinLock(&g_Anx.EventLock, oldIrql);

        if (node == NULL) {
            return;
        }

        irp = IoCsqRemoveNextIrp(&g_Anx.Csq, NULL);
        if (irp == NULL) {
            /* 没有消费者，放回队首 / no consumer, push it back */
            KeAcquireSpinLock(&g_Anx.EventLock, &oldIrql);
            InsertHeadList(&g_Anx.EventList, &node->Link);
            g_Anx.EventCount++;
            KeReleaseSpinLock(&g_Anx.EventLock, oldIrql);
            return;
        }

        /* 把累计丢弃数搭在这条事件上带给用户态 */
        /* Carry the accumulated drop count out on this event */
        dropped = InterlockedExchange(&g_Anx.DroppedSinceLast, 0);
        node->Event.DroppedSinceLast = (UINT32)dropped;

        /*
         * 输出缓冲长度在 IOCTL 分支已校验 >= sizeof(ANX_NET_EVENT)，
         * 这里直接拷贝。
         * The output length was validated as >= sizeof(ANX_NET_EVENT) by the
         * IOCTL handler, so the copy is safe here.
         */
        RtlCopyMemory(irp->AssociatedIrp.SystemBuffer, &node->Event, sizeof(ANX_NET_EVENT));

        irp->IoStatus.Status = STATUS_SUCCESS;
        irp->IoStatus.Information = sizeof(ANX_NET_EVENT);
        IoCompleteRequest(irp, IO_NO_INCREMENT);

        ExFreeToLookasideListEx(&g_EventLookaside, node);
    }
}
