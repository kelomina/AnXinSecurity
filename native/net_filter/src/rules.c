/*++
Copyright (c) AnXin Security. All rights reserved.

Module Name:
    rules.c

Abstract:
    规则表、域名表、限速表、裁决缓存与进程级统计。
    Rule table, domain table, rate-limit table, verdict cache and per-process
    statistics.

    设计要点 / Design notes:
    - 三张表都采用「整表原子替换」：用户态一次性下发完整集合，驱动在独占锁下
      换出指针，旧表在锁外释放，分类路径永远看不到半更新状态。
      All three tables use whole-table atomic replace: user mode pushes the
      complete set, the driver swaps the pointer under an exclusive lock and
      frees the old table outside it, so the classify path never observes a
      half-applied state.
    - 分类路径（DISPATCH_LEVEL）只取共享锁并做只读扫描，不分配内存。
      The classify path (DISPATCH_LEVEL) takes only a shared lock and performs
      a read-only scan; it never allocates.
    - 缓存与统计节点走 lookaside list，避免热路径上的通用池分配。
      Cache and stat nodes come from lookaside lists to keep the general pool
      allocator off the hot path.

Environment:
    Kernel mode only.

--*/

#include "anx_net_internal.h"

/* ==========================================================================
 * 模块内部状态 / Module-private state
 * ========================================================================== */

static LOOKASIDE_LIST_EX g_CacheLookaside;
static LOOKASIDE_LIST_EX g_StatLookaside;
static BOOLEAN           g_CacheLookasideReady = FALSE;
static BOOLEAN           g_StatLookasideReady  = FALSE;

/* 单个桶允许的最大条目数，超出时回收最旧的一条，防止缓存无限增长 */
/* Max entries per bucket; the oldest is evicted beyond this so the cache
 * cannot grow without bound. */
#define ANX_CACHE_BUCKET_LIMIT   32u

/* ==========================================================================
 * 辅助 / Helpers
 * ========================================================================== */

static FORCEINLINE ULONG AnxCacheBucketIndex(_In_ const ANX_CONN_INFO* Conn)
{
    UINT64 mix = Conn->AppIdHash;

    mix ^= (UINT64)Conn->RemotePort << 1;
    mix ^= (UINT64)Conn->Protocol << 17;
    mix ^= (UINT64)Conn->RemoteAddr.Bytes[0];
    mix ^= (UINT64)Conn->RemoteAddr.Bytes[1] << 8;
    mix ^= (UINT64)Conn->RemoteAddr.Bytes[2] << 16;
    mix ^= (UINT64)Conn->RemoteAddr.Bytes[3] << 24;
    mix ^= mix >> 32;

    return (ULONG)(mix & (ANX_CACHE_BUCKETS - 1));
}

static FORCEINLINE ULONG AnxStatBucketIndex(_In_ UINT32 ProcessId)
{
    return (ULONG)((ProcessId * 2654435761u) & (ANX_STAT_BUCKETS - 1));
}

static FORCEINLINE BOOLEAN AnxPortInRange(_In_ UINT16 Port, _In_ UINT32 Low, _In_ UINT32 High)
{
    /* Low 与 High 同为 0 表示不限端口 / both zero means "any port" */
    if (Low == 0 && High == 0) {
        return TRUE;
    }
    return (BOOLEAN)(Port >= Low && Port <= High);
}

/*
 * 域名后缀匹配：pattern 为 "example.com" 时，
 * "example.com" 与 "a.example.com" 命中，"badexample.com" 不命中。
 * Suffix match: pattern "example.com" matches "example.com" and
 * "a.example.com" but not "badexample.com".
 */
static BOOLEAN AnxDomainSuffixMatch(_In_ PCWSTR Domain, _In_ PCWSTR Pattern)
{
    SIZE_T domainLen = 0;
    SIZE_T patternLen = 0;
    SIZE_T offset;

    while (Domain[domainLen] != L'\0' && domainLen < ANX_NET_MAX_DOMAIN) {
        domainLen++;
    }
    while (Pattern[patternLen] != L'\0' && patternLen < ANX_NET_MAX_DOMAIN) {
        patternLen++;
    }

    if (patternLen == 0 || domainLen < patternLen) {
        return FALSE;
    }

    offset = domainLen - patternLen;

    if (RtlCompareMemory(Domain + offset, Pattern, patternLen * sizeof(WCHAR))
            != patternLen * sizeof(WCHAR)) {
        return FALSE;
    }

    /* 完全相等，或紧邻的前一个字符必须是点，才算子域 */
    /* Exact match, or the preceding character must be a dot to be a subdomain */
    return (BOOLEAN)(offset == 0 || Domain[offset - 1] == L'.');
}

static BOOLEAN AnxDomainContainsMatch(_In_ PCWSTR Domain, _In_ PCWSTR Pattern)
{
    SIZE_T domainLen = 0;
    SIZE_T patternLen = 0;
    SIZE_T i;

    while (Domain[domainLen] != L'\0' && domainLen < ANX_NET_MAX_DOMAIN) {
        domainLen++;
    }
    while (Pattern[patternLen] != L'\0' && patternLen < ANX_NET_MAX_DOMAIN) {
        patternLen++;
    }

    if (patternLen == 0 || domainLen < patternLen) {
        return FALSE;
    }

    for (i = 0; i + patternLen <= domainLen; i++) {
        if (RtlCompareMemory(Domain + i, Pattern, patternLen * sizeof(WCHAR))
                == patternLen * sizeof(WCHAR)) {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOLEAN AnxDomainExactMatch(_In_ PCWSTR Domain, _In_ PCWSTR Pattern)
{
    SIZE_T i;

    for (i = 0; i < ANX_NET_MAX_DOMAIN; i++) {
        if (Domain[i] != Pattern[i]) {
            return FALSE;
        }
        if (Domain[i] == L'\0') {
            return TRUE;
        }
    }

    return TRUE;
}

/* ==========================================================================
 * 初始化与清理 / Initialization and teardown
 * ========================================================================== */

/*
 * 函数名称：AnxRulesInitialize
 * 函数作用：初始化规则/缓存/统计子系统的锁、桶链表与 lookaside list。
 * Purpose: Initializes locks, bucket lists and lookaside lists for the rule,
 *          cache and stats subsystems.
 * 调用方：DriverEntry
 * Called by: DriverEntry
 * IRQL：PASSIVE_LEVEL
 * 中文关键词：初始化，桶链表，后备列表
 * English keywords: initialization, bucket lists, lookaside list
 */
NTSTATUS AnxRulesInitialize(void)
{
    NTSTATUS status;
    ULONG    i;

    for (i = 0; i < ANX_CACHE_BUCKETS; i++) {
        InitializeListHead(&g_Anx.CacheBuckets[i]);
    }
    for (i = 0; i < ANX_STAT_BUCKETS; i++) {
        InitializeListHead(&g_Anx.StatBuckets[i]);
    }

    status = ExInitializeLookasideListEx(&g_CacheLookaside, NULL, NULL,
                                         NonPagedPoolNx, 0,
                                         sizeof(ANX_CACHE_ENTRY), ANX_TAG_CACHE, 0);
    if (!NT_SUCCESS(status)) {
        AnxError("ExInitializeLookasideListEx(cache) failed 0x%08X\n", status);
        return status;
    }
    g_CacheLookasideReady = TRUE;

    status = ExInitializeLookasideListEx(&g_StatLookaside, NULL, NULL,
                                         NonPagedPoolNx, 0,
                                         sizeof(ANX_STAT_NODE), ANX_TAG_STAT, 0);
    if (!NT_SUCCESS(status)) {
        AnxError("ExInitializeLookasideListEx(stat) failed 0x%08X\n", status);
        ExDeleteLookasideListEx(&g_CacheLookaside);
        g_CacheLookasideReady = FALSE;
        return status;
    }
    g_StatLookasideReady = TRUE;

    return STATUS_SUCCESS;
}

/*
 * 函数名称：AnxRulesShutdown
 * 函数作用：释放三张表、清空缓存与统计、销毁 lookaside list。
 * Purpose: Frees the three tables, drains cache and stats, destroys lookasides.
 * 调用方：DriverUnload、DriverEntry 失败回滚
 * Called by: DriverUnload and DriverEntry rollback
 * IRQL：PASSIVE_LEVEL
 * 中文关键词：卸载清理，资源释放
 * English keywords: unload cleanup, resource release
 */
void AnxRulesShutdown(void)
{
    PANX_RULE_TABLE   ruleTable;
    PANX_DOMAIN_TABLE domainTable;
    PANX_LIMIT_TABLE  limitTable;
    KIRQL             oldIrql;
    ULONG             i;

    oldIrql = ExAcquireSpinLockExclusive(&g_Anx.TableLock);
    ruleTable   = g_Anx.RuleTable;
    domainTable = g_Anx.DomainTable;
    limitTable  = g_Anx.LimitTable;
    g_Anx.RuleTable   = NULL;
    g_Anx.DomainTable = NULL;
    g_Anx.LimitTable  = NULL;
    ExReleaseSpinLockExclusive(&g_Anx.TableLock, oldIrql);

    if (ruleTable != NULL)   { ExFreePoolWithTag(ruleTable, ANX_TAG_RULES); }
    if (domainTable != NULL) { ExFreePoolWithTag(domainTable, ANX_TAG_DOMAIN); }
    if (limitTable != NULL)  { ExFreePoolWithTag(limitTable, ANX_TAG_LIMIT); }

    /* 清空裁决缓存 / drain the verdict cache */
    oldIrql = ExAcquireSpinLockExclusive(&g_Anx.CacheLock);
    for (i = 0; i < ANX_CACHE_BUCKETS; i++) {
        while (!IsListEmpty(&g_Anx.CacheBuckets[i])) {
            PLIST_ENTRY entry = RemoveHeadList(&g_Anx.CacheBuckets[i]);
            PANX_CACHE_ENTRY node = CONTAINING_RECORD(entry, ANX_CACHE_ENTRY, Link);
            if (g_CacheLookasideReady) {
                ExFreeToLookasideListEx(&g_CacheLookaside, node);
            }
        }
    }
    ExReleaseSpinLockExclusive(&g_Anx.CacheLock, oldIrql);

    /* 清空进程统计 / drain per-process stats */
    oldIrql = ExAcquireSpinLockExclusive(&g_Anx.StatLock);
    for (i = 0; i < ANX_STAT_BUCKETS; i++) {
        while (!IsListEmpty(&g_Anx.StatBuckets[i])) {
            PLIST_ENTRY entry = RemoveHeadList(&g_Anx.StatBuckets[i]);
            PANX_STAT_NODE node = CONTAINING_RECORD(entry, ANX_STAT_NODE, Link);
            if (g_StatLookasideReady) {
                ExFreeToLookasideListEx(&g_StatLookaside, node);
            }
        }
    }
    ExReleaseSpinLockExclusive(&g_Anx.StatLock, oldIrql);

    if (g_CacheLookasideReady) {
        ExDeleteLookasideListEx(&g_CacheLookaside);
        g_CacheLookasideReady = FALSE;
    }
    if (g_StatLookasideReady) {
        ExDeleteLookasideListEx(&g_StatLookaside);
        g_StatLookasideReady = FALSE;
    }
}

/* ==========================================================================
 * 表下发 / Table installation
 * ========================================================================== */

/*
 * 函数名称：AnxRulesSetTable
 * 函数作用：校验并整表替换连接级规则表。
 * Purpose: Validates and atomically replaces the connection-level rule table.
 * 参数 Buffer/Length: 用户态传入的 ANX_NET_RULE_SET
 * 调用方：IOCTL_ANX_NET_SET_RULES 处理分支
 * Called by: the IOCTL_ANX_NET_SET_RULES handler
 * IRQL：PASSIVE_LEVEL
 * 中文关键词：规则下发，整表替换，输入校验
 * English keywords: rule installation, whole-table replace, input validation
 */
NTSTATUS AnxRulesSetTable(_In_reads_bytes_(Length) const void* Buffer, _In_ ULONG Length)
{
    const ANX_NET_RULE_SET* input;
    PANX_RULE_TABLE         table;
    PANX_RULE_TABLE         old;
    SIZE_T                  required;
    SIZE_T                  allocSize;
    KIRQL                   oldIrql;
    ULONG                   i;

    if (Buffer == NULL || (SIZE_T)Length < (SIZE_T)FIELD_OFFSET(ANX_NET_RULE_SET, Rules)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    input = (const ANX_NET_RULE_SET*)Buffer;

    if (input->Count > ANX_NET_MAX_RULES) {
        return STATUS_INVALID_PARAMETER;
    }

    required = FIELD_OFFSET(ANX_NET_RULE_SET, Rules) +
               (SIZE_T)input->Count * sizeof(ANX_NET_RULE);
    if ((SIZE_T)Length < required) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* 逐条校验动作取值，避免非法值在分类路径上被当成放行 */
    /* Validate every action so an illegal value cannot be treated as permit */
    for (i = 0; i < input->Count; i++) {
        if (input->Rules[i].Action > ANX_NET_ACTION_CONTINUE) {
            return STATUS_INVALID_PARAMETER;
        }
        if (input->Rules[i].Direction > ANX_NET_DIR_ANY) {
            return STATUS_INVALID_PARAMETER;
        }
        if (input->Rules[i].RemoteAddr.Family != 0 &&
            input->Rules[i].RemoteAddr.Family != ANX_NET_AF_INET &&
            input->Rules[i].RemoteAddr.Family != ANX_NET_AF_INET6) {
            return STATUS_INVALID_PARAMETER;
        }
    }

    allocSize = FIELD_OFFSET(ANX_RULE_TABLE, Rules) +
                (SIZE_T)input->Count * sizeof(ANX_NET_RULE);
    if (allocSize < sizeof(ANX_RULE_TABLE)) {
        allocSize = sizeof(ANX_RULE_TABLE);
    }

    table = (PANX_RULE_TABLE)ExAllocatePool2(POOL_FLAG_NON_PAGED, allocSize, ANX_TAG_RULES);
    if (table == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    table->Version = input->Version;
    table->Count   = input->Count;
    if (input->Count > 0) {
        RtlCopyMemory(table->Rules, input->Rules,
                      (SIZE_T)input->Count * sizeof(ANX_NET_RULE));
    }

    oldIrql = ExAcquireSpinLockExclusive(&g_Anx.TableLock);
    old = g_Anx.RuleTable;
    g_Anx.RuleTable = table;
    ExReleaseSpinLockExclusive(&g_Anx.TableLock, oldIrql);

    if (old != NULL) {
        ExFreePoolWithTag(old, ANX_TAG_RULES);
    }

    /* 规则变了，旧裁决缓存全部作废 / rules changed, the cache is now stale */
    AnxCacheFlush(ANX_NET_FLUSH_ALL, 0, 0);

    AnxTrace("Rule table installed: version=%u count=%u\n", table->Version, table->Count);
    return STATUS_SUCCESS;
}

/*
 * 函数名称：AnxDomainsSetTable
 * 函数作用：校验并整表替换域名规则表。
 * Purpose: Validates and atomically replaces the domain rule table.
 * 调用方：IOCTL_ANX_NET_SET_DOMAINS 处理分支
 * Called by: the IOCTL_ANX_NET_SET_DOMAINS handler
 * IRQL：PASSIVE_LEVEL
 * 中文关键词：域名规则，整表替换
 * English keywords: domain rules, whole-table replace
 */
NTSTATUS AnxDomainsSetTable(_In_reads_bytes_(Length) const void* Buffer, _In_ ULONG Length)
{
    const ANX_NET_DOMAIN_SET* input;
    PANX_DOMAIN_TABLE         table;
    PANX_DOMAIN_TABLE         old;
    SIZE_T                    required;
    SIZE_T                    allocSize;
    KIRQL                     oldIrql;
    ULONG                     i;

    if (Buffer == NULL || (SIZE_T)Length < (SIZE_T)FIELD_OFFSET(ANX_NET_DOMAIN_SET, Rules)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    input = (const ANX_NET_DOMAIN_SET*)Buffer;

    if (input->Count > ANX_NET_MAX_DOMAIN_RULES) {
        return STATUS_INVALID_PARAMETER;
    }

    required = FIELD_OFFSET(ANX_NET_DOMAIN_SET, Rules) +
               (SIZE_T)input->Count * sizeof(ANX_NET_DOMAIN_RULE);
    if ((SIZE_T)Length < required) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    for (i = 0; i < input->Count; i++) {
        if (input->Rules[i].Action != ANX_NET_ACTION_ALLOW &&
            input->Rules[i].Action != ANX_NET_ACTION_BLOCK) {
            return STATUS_INVALID_PARAMETER;
        }
        if (input->Rules[i].MatchType > ANX_NET_DM_CONTAINS) {
            return STATUS_INVALID_PARAMETER;
        }
    }

    allocSize = FIELD_OFFSET(ANX_DOMAIN_TABLE, Rules) +
                (SIZE_T)input->Count * sizeof(ANX_NET_DOMAIN_RULE);
    if (allocSize < sizeof(ANX_DOMAIN_TABLE)) {
        allocSize = sizeof(ANX_DOMAIN_TABLE);
    }

    table = (PANX_DOMAIN_TABLE)ExAllocatePool2(POOL_FLAG_NON_PAGED, allocSize, ANX_TAG_DOMAIN);
    if (table == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    table->Version = input->Version;
    table->Count   = input->Count;
    if (input->Count > 0) {
        RtlCopyMemory(table->Rules, input->Rules,
                      (SIZE_T)input->Count * sizeof(ANX_NET_DOMAIN_RULE));
        /* 强制 NUL 结尾并统一小写，避免用户态传入未终止的串 */
        /* Force NUL termination and lower-case in case user mode sent junk */
        for (i = 0; i < table->Count; i++) {
            table->Rules[i].Domain[ANX_NET_MAX_DOMAIN - 1] = L'\0';
            AnxDomainToLower(table->Rules[i].Domain, ANX_NET_MAX_DOMAIN);
        }
    }

    oldIrql = ExAcquireSpinLockExclusive(&g_Anx.TableLock);
    old = g_Anx.DomainTable;
    g_Anx.DomainTable = table;
    ExReleaseSpinLockExclusive(&g_Anx.TableLock, oldIrql);

    if (old != NULL) {
        ExFreePoolWithTag(old, ANX_TAG_DOMAIN);
    }

    AnxTrace("Domain table installed: version=%u count=%u\n", table->Version, table->Count);
    return STATUS_SUCCESS;
}

/*
 * 函数名称：AnxLimitsSetTable
 * 函数作用：校验并整表替换限速表，并把限速值刷入已有的统计节点。
 * Purpose: Validates and replaces the rate-limit table, then pushes the limits
 *          into already-existing stat nodes.
 * 调用方：IOCTL_ANX_NET_SET_LIMITS 处理分支
 * Called by: the IOCTL_ANX_NET_SET_LIMITS handler
 * IRQL：PASSIVE_LEVEL
 * 中文关键词：限速表，令牌桶，配额刷新
 * English keywords: rate-limit table, token bucket, quota refresh
 */
NTSTATUS AnxLimitsSetTable(_In_reads_bytes_(Length) const void* Buffer, _In_ ULONG Length)
{
    const ANX_NET_LIMIT_SET* input;
    PANX_LIMIT_TABLE         table;
    PANX_LIMIT_TABLE         old;
    SIZE_T                   required;
    SIZE_T                   allocSize;
    KIRQL                    oldIrql;
    ULONG                    i;
    ULONG                    b;

    if (Buffer == NULL || (SIZE_T)Length < (SIZE_T)FIELD_OFFSET(ANX_NET_LIMIT_SET, Limits)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    input = (const ANX_NET_LIMIT_SET*)Buffer;

    if (input->Count > ANX_NET_MAX_LIMITS) {
        return STATUS_INVALID_PARAMETER;
    }

    required = FIELD_OFFSET(ANX_NET_LIMIT_SET, Limits) +
               (SIZE_T)input->Count * sizeof(ANX_NET_LIMIT);
    if ((SIZE_T)Length < required) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    allocSize = FIELD_OFFSET(ANX_LIMIT_TABLE, Limits) +
                (SIZE_T)input->Count * sizeof(ANX_NET_LIMIT);
    if (allocSize < sizeof(ANX_LIMIT_TABLE)) {
        allocSize = sizeof(ANX_LIMIT_TABLE);
    }

    table = (PANX_LIMIT_TABLE)ExAllocatePool2(POOL_FLAG_NON_PAGED, allocSize, ANX_TAG_LIMIT);
    if (table == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    table->Version = input->Version;
    table->Count   = input->Count;
    if (input->Count > 0) {
        RtlCopyMemory(table->Limits, input->Limits,
                      (SIZE_T)input->Count * sizeof(ANX_NET_LIMIT));
    }

    oldIrql = ExAcquireSpinLockExclusive(&g_Anx.TableLock);
    old = g_Anx.LimitTable;
    g_Anx.LimitTable = table;
    ExReleaseSpinLockExclusive(&g_Anx.TableLock, oldIrql);

    if (old != NULL) {
        ExFreePoolWithTag(old, ANX_TAG_LIMIT);
    }

    /*
     * 把新配额刷进已存在的统计节点。新进程会在 AnxStatAcquire 时按表初始化，
     * 这里只处理已经建好节点的老进程。
     * Push the new quota into existing stat nodes. New processes pick the limit
     * up in AnxStatAcquire; this loop only fixes up already-created nodes.
     */
    oldIrql = ExAcquireSpinLockExclusive(&g_Anx.StatLock);
    for (b = 0; b < ANX_STAT_BUCKETS; b++) {
        PLIST_ENTRY link;
        for (link = g_Anx.StatBuckets[b].Flink;
             link != &g_Anx.StatBuckets[b];
             link = link->Flink) {
            PANX_STAT_NODE node = CONTAINING_RECORD(link, ANX_STAT_NODE, Link);
            node->LimitIn    = 0;
            node->LimitOut   = 0;
            node->BurstBytes = 0;
            for (i = 0; i < table->Count; i++) {
                if (table->Limits[i].AppIdHash == 0 ||
                    table->Limits[i].AppIdHash == node->Stat.AppIdHash) {
                    node->LimitIn    = table->Limits[i].BytesPerSecIn;
                    node->LimitOut   = table->Limits[i].BytesPerSecOut;
                    node->BurstBytes = table->Limits[i].BurstBytes;
                    /* 精确匹配优先于全局条目 / exact match beats the global entry */
                    if (table->Limits[i].AppIdHash != 0) {
                        break;
                    }
                }
            }
        }
    }
    ExReleaseSpinLockExclusive(&g_Anx.StatLock, oldIrql);

    AnxTrace("Limit table installed: version=%u count=%u\n", table->Version, table->Count);
    return STATUS_SUCCESS;
}

/* ==========================================================================
 * 规则求值 / Rule evaluation
 * ========================================================================== */

/*
 * 函数名称：AnxRulesEvaluate
 * 函数作用：按数组顺序求值连接级规则，返回首个命中的动作。
 * Purpose: Evaluates connection rules in array order and returns the first hit.
 *
 * 返回 ANX_NET_ACTION_CONTINUE 表示所有规则都未做出终局裁决，调用方应回落到
 * 配置里的默认动作。
 * Returning ANX_NET_ACTION_CONTINUE means no rule reached a terminal verdict and
 * the caller must fall back to the configured default action.
 *
 * 调用方：ALE 分类回调
 * Called by: ALE classify callbacks
 * IRQL：<= DISPATCH_LEVEL
 * 并发安全：共享自旋锁保护表指针，只读扫描
 * 中文关键词：规则求值，首个命中，默认动作
 * English keywords: rule evaluation, first match wins, default action
 */
UINT32 AnxRulesEvaluate(_In_ const ANX_CONN_INFO* Conn, _Out_ UINT32* MatchedRuleId)
{
    KIRQL           oldIrql;
    PANX_RULE_TABLE table;
    UINT32          action = ANX_NET_ACTION_CONTINUE;
    ULONG           i;

    *MatchedRuleId = 0;

    oldIrql = ExAcquireSpinLockShared(&g_Anx.TableLock);
    table = g_Anx.RuleTable;

    if (table != NULL) {
        for (i = 0; i < table->Count; i++) {
            const ANX_NET_RULE* rule = &table->Rules[i];

            if ((rule->Flags & ANX_NET_RF_ENABLED) == 0) {
                continue;
            }
            if (Conn->IsLoopback && (rule->Flags & ANX_NET_RF_MATCH_LOOPBACK) == 0) {
                continue;
            }
            if (rule->Direction != ANX_NET_DIR_ANY && rule->Direction != Conn->Direction) {
                continue;
            }
            if (rule->Protocol != ANX_NET_PROTO_ANY && rule->Protocol != Conn->Protocol) {
                continue;
            }
            if (rule->AppIdHash != 0 && rule->AppIdHash != Conn->AppIdHash) {
                continue;
            }
            if (!AnxPortInRange(Conn->RemotePort, rule->RemotePortLow, rule->RemotePortHigh)) {
                continue;
            }
            if (!AnxPortInRange(Conn->LocalPort, rule->LocalPortLow, rule->LocalPortHigh)) {
                continue;
            }
            if (!AnxAddrMatchesCidr(&Conn->RemoteAddr, &rule->RemoteAddr, rule->RemotePrefixLen)) {
                continue;
            }

            if (rule->Action == ANX_NET_ACTION_CONTINUE) {
                continue;
            }

            action = rule->Action;
            *MatchedRuleId = rule->RuleId;
            break;
        }
    }

    ExReleaseSpinLockShared(&g_Anx.TableLock, oldIrql);
    return action;
}

/*
 * 函数名称：AnxDomainsEvaluate
 * 函数作用：对已归一化的小写域名求值域名规则表。
 * Purpose: Evaluates the domain rule table against a normalized lower-case name.
 * 调用方：DNS 与流内容检查回调
 * Called by: the DNS and stream-inspection callbacks
 * IRQL：<= DISPATCH_LEVEL
 * 中文关键词：域名匹配，黑白名单，后缀匹配
 * English keywords: domain matching, allow/block list, suffix match
 */
UINT32 AnxDomainsEvaluate(_In_ PCWSTR Domain, _Out_ UINT32* MatchedRuleId)
{
    KIRQL             oldIrql;
    PANX_DOMAIN_TABLE table;
    UINT32            action = ANX_NET_ACTION_CONTINUE;
    ULONG             i;

    *MatchedRuleId = 0;

    if (Domain == NULL || Domain[0] == L'\0') {
        return action;
    }

    oldIrql = ExAcquireSpinLockShared(&g_Anx.TableLock);
    table = g_Anx.DomainTable;

    if (table != NULL) {
        for (i = 0; i < table->Count; i++) {
            const ANX_NET_DOMAIN_RULE* rule = &table->Rules[i];
            BOOLEAN hit = FALSE;

            switch (rule->MatchType) {
            case ANX_NET_DM_EXACT:
                hit = AnxDomainExactMatch(Domain, rule->Domain);
                break;
            case ANX_NET_DM_SUFFIX:
                hit = AnxDomainSuffixMatch(Domain, rule->Domain);
                break;
            case ANX_NET_DM_CONTAINS:
                hit = AnxDomainContainsMatch(Domain, rule->Domain);
                break;
            default:
                break;
            }

            if (hit) {
                action = rule->Action;
                *MatchedRuleId = rule->RuleId;
                break;
            }
        }
    }

    ExReleaseSpinLockShared(&g_Anx.TableLock, oldIrql);
    return action;
}

/* ==========================================================================
 * 裁决缓存 / Verdict cache
 * ========================================================================== */

/*
 * 函数名称：AnxCacheLookup
 * 函数作用：查找该连接是否已有缓存裁决，命中时通过 Action 返回。
 * Purpose: Looks up a cached verdict for the connection.
 *
 * 过期条目直接当未命中处理，实际回收留给插入路径与卸载路径，
 * 这样查找路径可以只取共享锁。
 * Expired entries are treated as a miss; actual reclamation happens on the
 * insert and unload paths so the lookup path can hold only a shared lock.
 *
 * 调用方：ALE 分类回调
 * Called by: ALE classify callbacks
 * IRQL：<= DISPATCH_LEVEL
 * 中文关键词：裁决缓存，命中，过期
 * English keywords: verdict cache, hit, expiry
 */
BOOLEAN AnxCacheLookup(_In_ const ANX_CONN_INFO* Conn, _Out_ UINT32* Action)
{
    KIRQL       oldIrql;
    ULONG       bucket;
    PLIST_ENTRY link;
    BOOLEAN     found = FALSE;
    UINT64      now;

    *Action = ANX_NET_ACTION_CONTINUE;

    now    = AnxGetSystemTimeMs();
    bucket = AnxCacheBucketIndex(Conn);

    oldIrql = ExAcquireSpinLockShared(&g_Anx.CacheLock);
    for (link = g_Anx.CacheBuckets[bucket].Flink;
         link != &g_Anx.CacheBuckets[bucket];
         link = link->Flink) {
        PANX_CACHE_ENTRY node = CONTAINING_RECORD(link, ANX_CACHE_ENTRY, Link);

        if (node->AppIdHash != Conn->AppIdHash) {
            continue;
        }
        if (node->Direction != (UINT8)Conn->Direction) {
            continue;
        }
        if (!node->AnyRemote) {
            if (node->Protocol != (UINT8)Conn->Protocol ||
                node->RemotePort != Conn->RemotePort ||
                node->RemoteAddr.Family != Conn->RemoteAddr.Family ||
                RtlCompareMemory(node->RemoteAddr.Bytes, Conn->RemoteAddr.Bytes, 16) != 16) {
                continue;
            }
        }
        if (node->ExpiryMs != 0 && node->ExpiryMs <= now) {
            continue;   /* 已过期，视为未命中 / expired, treated as a miss */
        }

        *Action = node->Action;
        found = TRUE;
        break;
    }
    ExReleaseSpinLockShared(&g_Anx.CacheLock, oldIrql);

    if (found) {
        InterlockedIncrement64(&g_Anx.CacheHits);
    } else {
        InterlockedIncrement64(&g_Anx.CacheMisses);
    }

    return found;
}

/*
 * 函数名称：AnxCacheInsert
 * 函数作用：写入一条裁决缓存；桶满时淘汰最旧的一条。
 * Purpose: Inserts a verdict cache entry, evicting the oldest when the bucket
 *          is full.
 * 参数 AnyRemote: TRUE 表示该裁决对该进程的所有目标生效
 * 参数 TtlMs: 0 表示使用配置里的 CacheTtlMs
 * 调用方：AnxPendingResolve（用户裁决后）、ALE 规则命中后
 * Called by: AnxPendingResolve after a user verdict, and on rule hits
 * IRQL：<= DISPATCH_LEVEL
 * 中文关键词：缓存插入，淘汰策略，生存期
 * English keywords: cache insert, eviction, TTL
 */
void AnxCacheInsert(_In_ const ANX_CONN_INFO* Conn, _In_ UINT32 Action,
                    _In_ BOOLEAN AnyRemote, _In_ UINT32 TtlMs)
{
    PANX_CACHE_ENTRY node;
    PANX_CACHE_ENTRY victim = NULL;
    ANX_NET_CONFIG   config;
    KIRQL            oldIrql;
    ULONG            bucket;
    ULONG            count = 0;
    PLIST_ENTRY      link;
    UINT64           now;

    if (!g_CacheLookasideReady) {
        return;
    }
    if (Action != ANX_NET_ACTION_ALLOW && Action != ANX_NET_ACTION_BLOCK) {
        return;
    }

    AnxConfigGet(&config);
    if (TtlMs == 0) {
        TtlMs = config.CacheTtlMs;
    }

    now = AnxGetSystemTimeMs();

    /* 先在锁外分配，避免在 DISPATCH_LEVEL 持锁期间调用分配器 */
    /* Allocate before taking the lock so the allocator is never called while
     * holding a DISPATCH_LEVEL spin lock. */
    node = (PANX_CACHE_ENTRY)ExAllocateFromLookasideListEx(&g_CacheLookaside);
    if (node == NULL) {
        return;
    }

    RtlZeroMemory(node, sizeof(*node));
    node->AppIdHash  = Conn->AppIdHash;
    node->ProcessId  = Conn->ProcessId;
    node->Action     = Action;
    node->Protocol   = (UINT8)Conn->Protocol;
    node->Direction  = (UINT8)Conn->Direction;
    node->RemotePort = Conn->RemotePort;
    node->AnyRemote  = AnyRemote;
    node->ExpiryMs   = (TtlMs == 0) ? 0 : (now + TtlMs);
    RtlCopyMemory(&node->RemoteAddr, &Conn->RemoteAddr, sizeof(ANX_NET_ADDR));

    bucket = AnxCacheBucketIndex(Conn);

    oldIrql = ExAcquireSpinLockExclusive(&g_Anx.CacheLock);

    for (link = g_Anx.CacheBuckets[bucket].Flink;
         link != &g_Anx.CacheBuckets[bucket];
         link = link->Flink) {
        count++;
    }

    if (count >= ANX_CACHE_BUCKET_LIMIT) {
        PLIST_ENTRY oldest = RemoveTailList(&g_Anx.CacheBuckets[bucket]);
        victim = CONTAINING_RECORD(oldest, ANX_CACHE_ENTRY, Link);
    }

    /* 新条目插到头部，淘汰从尾部走，形成近似 LRU */
    /* New entries go to the head and eviction takes the tail — approximate LRU */
    InsertHeadList(&g_Anx.CacheBuckets[bucket], &node->Link);

    ExReleaseSpinLockExclusive(&g_Anx.CacheLock, oldIrql);

    if (victim != NULL) {
        ExFreeToLookasideListEx(&g_CacheLookaside, victim);
    }
}

/*
 * 函数名称：AnxCacheFlush
 * 函数作用：按范围清空裁决缓存（全部 / 按 PID / 按 AppIdHash）。
 * Purpose: Flushes the verdict cache by scope (all / by PID / by AppIdHash).
 * 调用方：IOCTL_ANX_NET_FLUSH_CACHE、规则表更新、进程退出
 * Called by: IOCTL_ANX_NET_FLUSH_CACHE, rule updates, process exit
 * IRQL：<= DISPATCH_LEVEL
 * 中文关键词：缓存刷新，作废，范围清理
 * English keywords: cache flush, invalidation, scoped cleanup
 */
void AnxCacheFlush(_In_ UINT32 Scope, _In_ UINT32 ProcessId, _In_ UINT64 AppIdHash)
{
    KIRQL      oldIrql;
    ULONG      i;
    LIST_ENTRY reaped;

    if (!g_CacheLookasideReady) {
        return;
    }

    InitializeListHead(&reaped);

    oldIrql = ExAcquireSpinLockExclusive(&g_Anx.CacheLock);
    for (i = 0; i < ANX_CACHE_BUCKETS; i++) {
        PLIST_ENTRY link = g_Anx.CacheBuckets[i].Flink;
        while (link != &g_Anx.CacheBuckets[i]) {
            PANX_CACHE_ENTRY node = CONTAINING_RECORD(link, ANX_CACHE_ENTRY, Link);
            PLIST_ENTRY      next = link->Flink;
            BOOLEAN          remove = FALSE;

            switch (Scope) {
            case ANX_NET_FLUSH_ALL:
                remove = TRUE;
                break;
            case ANX_NET_FLUSH_BY_PID:
                remove = (BOOLEAN)(node->ProcessId == ProcessId);
                break;
            case ANX_NET_FLUSH_BY_APPID:
                remove = (BOOLEAN)(node->AppIdHash == AppIdHash);
                break;
            default:
                break;
            }

            if (remove) {
                RemoveEntryList(link);
                InsertTailList(&reaped, link);
            }
            link = next;
        }
    }
    ExReleaseSpinLockExclusive(&g_Anx.CacheLock, oldIrql);

    /* 释放放到锁外做 / free outside the lock */
    while (!IsListEmpty(&reaped)) {
        PLIST_ENTRY link = RemoveHeadList(&reaped);
        ExFreeToLookasideListEx(&g_CacheLookaside,
                                CONTAINING_RECORD(link, ANX_CACHE_ENTRY, Link));
    }
}

/* ==========================================================================
 * 进程统计与限速 / Per-process stats and rate limiting
 * ========================================================================== */

/*
 * 函数名称：AnxStatAcquire
 * 函数作用：取得（必要时创建）某进程的统计节点。
 * Purpose: Gets, creating if necessary, the stat node for a process.
 *
 * 返回的指针只在调用方仍持有引用语义的短窗口内有效：节点只会在
 * AnxRulesShutdown 时释放，因此在驱动运行期内指针稳定。
 * The returned pointer stays valid for the driver's lifetime — nodes are only
 * freed in AnxRulesShutdown — so no reference counting is needed.
 *
 * 调用方：AnxStatAddBytes、AnxStatCountConnection、AnxRateConsume
 * Called by: AnxStatAddBytes, AnxStatCountConnection, AnxRateConsume
 * IRQL：<= DISPATCH_LEVEL
 * 中文关键词：统计节点，按需创建，哈希桶
 * English keywords: stat node, lazy creation, hash bucket
 */
PANX_STAT_NODE AnxStatAcquire(_In_ UINT32 ProcessId, _In_ UINT64 AppIdHash)
{
    KIRQL            oldIrql;
    ULONG            bucket;
    PLIST_ENTRY      link;
    PANX_STAT_NODE   node = NULL;
    PANX_STAT_NODE   fresh = NULL;
    PANX_LIMIT_TABLE limits;
    ULONG            i;

    if (!g_StatLookasideReady) {
        return NULL;
    }

    bucket = AnxStatBucketIndex(ProcessId);

    /* 快路径：共享锁查找 / fast path: shared-lock lookup */
    oldIrql = ExAcquireSpinLockShared(&g_Anx.StatLock);
    for (link = g_Anx.StatBuckets[bucket].Flink;
         link != &g_Anx.StatBuckets[bucket];
         link = link->Flink) {
        PANX_STAT_NODE candidate = CONTAINING_RECORD(link, ANX_STAT_NODE, Link);
        if (candidate->Stat.ProcessId == ProcessId) {
            node = candidate;
            break;
        }
    }
    ExReleaseSpinLockShared(&g_Anx.StatLock, oldIrql);

    if (node != NULL) {
        return node;
    }

    fresh = (PANX_STAT_NODE)ExAllocateFromLookasideListEx(&g_StatLookaside);
    if (fresh == NULL) {
        return NULL;
    }

    RtlZeroMemory(fresh, sizeof(*fresh));
    fresh->Stat.ProcessId = ProcessId;
    fresh->Stat.AppIdHash = AppIdHash;
    fresh->LastRefillMs   = AnxGetSystemTimeMs();

    oldIrql = ExAcquireSpinLockExclusive(&g_Anx.StatLock);

    /* 二次检查：可能已被其他 CPU 抢先创建 / re-check: another CPU may have won */
    for (link = g_Anx.StatBuckets[bucket].Flink;
         link != &g_Anx.StatBuckets[bucket];
         link = link->Flink) {
        PANX_STAT_NODE candidate = CONTAINING_RECORD(link, ANX_STAT_NODE, Link);
        if (candidate->Stat.ProcessId == ProcessId) {
            node = candidate;
            break;
        }
    }

    if (node == NULL) {
        limits = g_Anx.LimitTable;
        if (limits != NULL) {
            for (i = 0; i < limits->Count; i++) {
                if (limits->Limits[i].AppIdHash == 0 ||
                    limits->Limits[i].AppIdHash == AppIdHash) {
                    fresh->LimitIn    = limits->Limits[i].BytesPerSecIn;
                    fresh->LimitOut   = limits->Limits[i].BytesPerSecOut;
                    fresh->BurstBytes = limits->Limits[i].BurstBytes;
                    if (limits->Limits[i].AppIdHash != 0) {
                        break;
                    }
                }
            }
        }
        InsertHeadList(&g_Anx.StatBuckets[bucket], &fresh->Link);
        node  = fresh;
        fresh = NULL;
    }

    ExReleaseSpinLockExclusive(&g_Anx.StatLock, oldIrql);

    if (fresh != NULL) {
        ExFreeToLookasideListEx(&g_StatLookaside, fresh);
    }

    return node;
}

/*
 * 函数名称：AnxStatAddBytes
 * 函数作用：累加进程的收发字节数。
 * Purpose: Accumulates per-process byte counters.
 * 调用方：流回调与数据报回调
 * Called by: the stream and datagram callbacks
 * IRQL：<= DISPATCH_LEVEL
 * 中文关键词：流量统计，字节累加，无锁自增
 * English keywords: traffic stats, byte accounting, interlocked increment
 */
void AnxStatAddBytes(_In_ UINT32 ProcessId, _In_ UINT64 AppIdHash,
                     _In_ UINT64 BytesIn, _In_ UINT64 BytesOut)
{
    PANX_STAT_NODE node = AnxStatAcquire(ProcessId, AppIdHash);

    if (node == NULL) {
        return;
    }

    if (BytesIn != 0) {
        InterlockedAdd64((volatile LONG64*)&node->Stat.BytesIn, (LONG64)BytesIn);
    }
    if (BytesOut != 0) {
        InterlockedAdd64((volatile LONG64*)&node->Stat.BytesOut, (LONG64)BytesOut);
    }
    InterlockedExchange64((volatile LONG64*)&node->Stat.LastActivityMs,
                          (LONG64)AnxGetSystemTimeMs());
}

/*
 * 函数名称：AnxStatCountConnection
 * 函数作用：累加进程的放行/拦截连接计数。
 * Purpose: Increments the allowed/blocked connection counters for a process.
 * 调用方：ALE 分类回调做出终局裁决后
 * Called by: ALE classify callbacks after a terminal verdict
 * IRQL：<= DISPATCH_LEVEL
 * 中文关键词：连接计数，放行统计，拦截统计
 * English keywords: connection counters, allow count, block count
 */
void AnxStatCountConnection(_In_ UINT32 ProcessId, _In_ UINT64 AppIdHash, _In_ BOOLEAN Allowed)
{
    PANX_STAT_NODE node = AnxStatAcquire(ProcessId, AppIdHash);

    if (node == NULL) {
        return;
    }

    if (Allowed) {
        InterlockedIncrement64((volatile LONG64*)&node->Stat.ConnAllowed);
    } else {
        InterlockedIncrement64((volatile LONG64*)&node->Stat.ConnBlocked);
    }
    InterlockedExchange64((volatile LONG64*)&node->Stat.LastActivityMs,
                          (LONG64)AnxGetSystemTimeMs());
}

/*
 * 函数名称：AnxRateConsume
 * 函数作用：令牌桶限速判定，返回 TRUE 表示本次字节数在配额内。
 * Purpose: Token-bucket admission test; TRUE means the bytes fit the quota.
 *
 * 令牌补充与扣减用 interlocked 操作完成，不额外加锁。这会带来微小的计量误差
 * （多核同时补充时可能多补一次），对限速器而言可以接受，换来的是数据路径上
 * 零锁竞争。
 * Refill and debit use interlocked operations without an extra lock. This
 * admits a small accounting error (concurrent CPUs may refill twice), which is
 * acceptable for a shaper and buys a lock-free data path.
 *
 * 调用方：流回调与数据报回调
 * Called by: the stream and datagram callbacks
 * IRQL：<= DISPATCH_LEVEL
 * 中文关键词：令牌桶，限速，配额
 * English keywords: token bucket, rate limit, quota
 */
BOOLEAN AnxRateConsume(_In_ UINT32 ProcessId, _In_ UINT64 AppIdHash,
                       _In_ UINT64 Bytes, _In_ BOOLEAN Inbound)
{
    PANX_STAT_NODE   node;
    volatile LONG64* tokens;
    UINT64           limit;
    UINT64           burst;
    UINT64           now;
    UINT64           last;
    LONG64           current;

    node = AnxStatAcquire(ProcessId, AppIdHash);
    if (node == NULL) {
        return TRUE;    /* 无法计量时放行 / permit when we cannot account */
    }

    limit  = Inbound ? node->LimitIn : node->LimitOut;
    if (limit == 0) {
        return TRUE;    /* 未配置限速 / no limit configured */
    }

    tokens = Inbound ? &node->TokensIn : &node->TokensOut;
    burst  = (node->BurstBytes != 0) ? node->BurstBytes : limit;

    now  = AnxGetSystemTimeMs();
    last = (UINT64)InterlockedCompareExchange64((volatile LONG64*)&node->LastRefillMs, 0, 0);

    if (now > last) {
        UINT64 elapsed = now - last;
        UINT64 refill;

        /* 防止超长间隔造成溢出 / clamp so a long gap cannot overflow */
        if (elapsed > 10000) {
            elapsed = 10000;
        }
        refill = (limit / 1000ULL) * elapsed;

        if (refill > 0) {
            LONG64 updated = InterlockedAdd64(tokens, (LONG64)refill);
            if (updated > (LONG64)burst) {
                InterlockedExchange64(tokens, (LONG64)burst);
            }
            InterlockedExchange64((volatile LONG64*)&node->LastRefillMs, (LONG64)now);
        }
    }

    current = InterlockedCompareExchange64(tokens, 0, 0);
    if (current < (LONG64)Bytes) {
        return FALSE;
    }

    InterlockedAdd64(tokens, -(LONG64)Bytes);
    return TRUE;
}

/*
 * 函数名称：AnxStatSnapshot
 * 函数作用：把全部进程统计快照写入用户态缓冲。
 * Purpose: Writes a snapshot of all per-process stats into the user buffer.
 *
 * 缓冲不足时仍写回头部（含 TotalProcesses），并返回 STATUS_BUFFER_OVERFLOW，
 * 用户态据此按需重试。
 * On a short buffer the header (including TotalProcesses) is still written and
 * STATUS_BUFFER_OVERFLOW is returned so user mode can size and retry.
 *
 * 调用方：IOCTL_ANX_NET_GET_STATS 处理分支
 * Called by: the IOCTL_ANX_NET_GET_STATS handler
 * IRQL：PASSIVE_LEVEL
 * 中文关键词：统计快照，缓冲不足，重试
 * English keywords: stats snapshot, short buffer, retry
 */
NTSTATUS AnxStatSnapshot(_Out_writes_bytes_(OutLength) void* Buffer, _In_ ULONG OutLength,
                         _Out_ ULONG* BytesWritten)
{
    ANX_NET_STATS* out;
    KIRQL          oldIrql;
    ULONG          bucket;
    ULONG          capacity;
    ULONG          written = 0;
    ULONG          total = 0;
    SIZE_T         headerSize;

    *BytesWritten = 0;

    headerSize = FIELD_OFFSET(ANX_NET_STATS, Entries);
    if (Buffer == NULL || OutLength < headerSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    out = (ANX_NET_STATS*)Buffer;
    RtlZeroMemory(out, headerSize);

    capacity = (ULONG)((OutLength - headerSize) / sizeof(ANX_NET_PROC_STAT));
    if (capacity > ANX_NET_MAX_STATS) {
        capacity = ANX_NET_MAX_STATS;
    }

    oldIrql = ExAcquireSpinLockShared(&g_Anx.StatLock);
    for (bucket = 0; bucket < ANX_STAT_BUCKETS; bucket++) {
        PLIST_ENTRY link;
        for (link = g_Anx.StatBuckets[bucket].Flink;
             link != &g_Anx.StatBuckets[bucket];
             link = link->Flink) {
            PANX_STAT_NODE node = CONTAINING_RECORD(link, ANX_STAT_NODE, Link);
            total++;
            if (written < capacity) {
                RtlCopyMemory(&out->Entries[written], &node->Stat, sizeof(ANX_NET_PROC_STAT));
                written++;
            }
        }
    }
    ExReleaseSpinLockShared(&g_Anx.StatLock, oldIrql);

    out->Count           = written;
    out->TotalProcesses  = total;
    out->EventsQueued    = (UINT64)InterlockedCompareExchange64(&g_Anx.EventsQueued, 0, 0);
    out->EventsDropped   = (UINT64)InterlockedCompareExchange64(&g_Anx.EventsDropped, 0, 0);
    out->PendingCount    = (UINT64)InterlockedCompareExchange(&g_Anx.PendingCount, 0, 0);
    out->PendingTimedOut = (UINT64)InterlockedCompareExchange64(&g_Anx.PendingTimedOut, 0, 0);
    out->CacheHits       = (UINT64)InterlockedCompareExchange64(&g_Anx.CacheHits, 0, 0);
    out->CacheMisses     = (UINT64)InterlockedCompareExchange64(&g_Anx.CacheMisses, 0, 0);

    *BytesWritten = (ULONG)(headerSize + (SIZE_T)written * sizeof(ANX_NET_PROC_STAT));

    return (total > written) ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;
}
