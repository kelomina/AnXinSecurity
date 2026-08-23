/*++
Copyright (c) AnXin Security. All rights reserved.

Module Name:
    rules.c

Abstract:
    AnXinProcMon.sys 过滤表：整表原子替换 + 匹配决策。
    Filter table: whole-table atomic replace + match decision.
    模式移植自 net_filter/src/rules.c (AnxRulesSetTable)。

    过滤语义（契约 v6 §4.5）：
    - 每类规则按数组顺序匹配，首个命中生效；先 DROP 后 COLLECT 语义由
      用户态构造顺序保证，驱动只做顺序匹配，不隐式优先。
    - 内置防呆（不可被用户表覆盖）：PID 0/4/8 必丢（util.c）；
      映像加载对系统关键 DLL 的内置精确白名单（AnxProcImageBuiltinSkip）。
    - IMAGE_PATH_EXACT：精确完整路径匹配（防 Phantom DLL，§13.4），
      大小写不敏感时逐字符比较；名称长度 0 视为不匹配（必须显式给出）。
    - IMAGE_PATH_PREFIX：前缀匹配（用户态显式配置的目录级跳过）。

    Filter semantics (contract v6 §4.5):
    - Rules of one kind match in array order; first hit wins. The user mode
      orders DROP rules before COLLECT rules; the driver never reorders.
    - Built-in fail-safe (never overridable): PIDs 0/4/8 (util.c);
      built-in exact allowlist for critical System32 DLLs (AnxProcImageBuiltinSkip).
    - IMAGE_PATH_EXACT: exact full-path match (anti Phantom DLL, §13.4);
      case-insensitive compare per char; empty name never matches.
    - IMAGE_PATH_PREFIX: explicit prefix skip configured by user mode.

Environment:
    Kernel mode only.

--*/

#include "anx_proc_internal.h"

/*
 * 函数名称：AnxProcRulesSetTable
 * 函数作用：整表原子替换过滤规则。新表在调用方缓冲中校验并拷贝，
 * 锁下换指针，随后释放旧表。失败时不改变现有表（fail-safe）。
 * Purpose: Atomically replaces the filter table. The new table is validated
 *          and copied from the caller buffer; the pointer is swapped under a
 *          lock; the old table is freed afterwards. On failure the current
 *          table is left untouched (fail-safe).
 * IRQL：PASSIVE_LEVEL
 */
NTSTATUS AnxProcRulesSetTable(_In_reads_bytes_(Length) const void* Buffer,
                              _In_ ULONG Length)
{
    NTSTATUS              status;
    PANX_PROC_FILTER_TABLE table = NULL;
    ULONG                 count = 0;

    if (Buffer == NULL || Length < sizeof(UINT32) * 2) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Length > ANX_PROC_FILTER_TABLE_MAX_BYTES) {
        return STATUS_INVALID_PARAMETER;
    }

    {
        const ANX_PROC_FILTER_SET* set = (const ANX_PROC_FILTER_SET*)Buffer;
        const UINT8*               pCursor;
        ULONG                      nRemaining;
        ULONG                      n;

        if (set->Count > ANX_PROC_MAX_FILTER_RULES) {
            return STATUS_INVALID_PARAMETER;
        }
        count = set->Count;

        /* 逐条校验：变长规则必须完全落在缓冲内 */
        pCursor = (const UINT8*)&set->Rules[0];
        nRemaining = Length - FIELD_OFFSET(ANX_PROC_FILTER_SET, Rules);

        for (n = 0; n < count; n++) {
            const ANX_PROC_FILTER_RULE* rule = (const ANX_PROC_FILTER_RULE*)pCursor;
            ULONG ruleBytes;

            if (nRemaining < sizeof(ANX_PROC_FILTER_RULE)) {
                return STATUS_INVALID_PARAMETER;
            }
            if (rule->NameLen > ANX_PROC_MAX_FILTER_NAME) {
                return STATUS_INVALID_PARAMETER;
            }
            if (rule->RuleType < ANX_PROC_RULE_FILE_PATH_PREFIX ||
                rule->RuleType > ANX_PROC_RULE_IMAGE_PATH_PREFIX) {
                return STATUS_INVALID_PARAMETER;
            }
            if (rule->Action != ANX_PROC_FILTER_COLLECT &&
                rule->Action != ANX_PROC_FILTER_DROP) {
                return STATUS_INVALID_PARAMETER;
            }

            ruleBytes = (ULONG)(FIELD_OFFSET(ANX_PROC_FILTER_RULE, Name) +
                                rule->NameLen * sizeof(WCHAR));
            if (ruleBytes > nRemaining) {
                return STATUS_INVALID_PARAMETER;
            }
            pCursor += ruleBytes;
            nRemaining -= ruleBytes;
        }
    }

    /* 拷贝到驱动自己的非分页内存（用户缓冲不引用），逐条拷贝变长规则 */
    {
        const ANX_PROC_FILTER_SET* srcSet = (const ANX_PROC_FILTER_SET*)Buffer;
        const UINT8*               sCursor = (const UINT8*)&srcSet->Rules[0];
        ULONG                      tableBytes;
        ULONG                      offset = 0;
        ULONG                      n;

        tableBytes = (ULONG)FIELD_OFFSET(ANX_PROC_FILTER_TABLE, Rules);
        for (n = 0; n < count; n++) {
            const ANX_PROC_FILTER_RULE* src = (const ANX_PROC_FILTER_RULE*)sCursor;
            tableBytes += (ULONG)(FIELD_OFFSET(ANX_PROC_FILTER_RULE, Name) +
                                  src->NameLen * sizeof(WCHAR));
            sCursor += FIELD_OFFSET(ANX_PROC_FILTER_RULE, Name) +
                       src->NameLen * sizeof(WCHAR);
        }

        table = (PANX_PROC_FILTER_TABLE)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                                        tableBytes,
                                                        ANX_PROC_TAG_RULES);
        if (table == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlZeroMemory(table, tableBytes);
        table->Version = 0;
        table->Count = count;

        sCursor = (const UINT8*)&srcSet->Rules[0];
        for (n = 0; n < count; n++) {
            const ANX_PROC_FILTER_RULE* src = (const ANX_PROC_FILTER_RULE*)sCursor;
            ANX_PROC_FILTER_RULE* dst =
                (ANX_PROC_FILTER_RULE*)((UINT8*)&table->Rules[0] + offset);
            ULONG ruleBytes = (ULONG)(FIELD_OFFSET(ANX_PROC_FILTER_RULE, Name) +
                                      src->NameLen * sizeof(WCHAR));

            dst->RuleType = src->RuleType;
            dst->Action = src->Action;
            dst->Flags = src->Flags;
            dst->NameLen = src->NameLen;
            if (src->NameLen > 0) {
                RtlCopyMemory(&dst->Name[0], &src->Name[0],
                              src->NameLen * sizeof(WCHAR));
            }
            sCursor += ruleBytes;
            offset += ruleBytes;
        }
    }

    /* 原子交换 */
    {
        KIRQL        oldIrql;
        PANX_PROC_FILTER_TABLE oldTable;

        oldIrql = ExAcquireSpinLockExclusive(&g_AnxProc.TableLock);
        oldTable = g_AnxProc.FilterTable;
        g_AnxProc.FilterTable = table;
        ExReleaseSpinLockExclusive(&g_AnxProc.TableLock, oldIrql);

        if (oldTable != NULL) {
            ExFreePoolWithTag(oldTable, ANX_PROC_TAG_RULES);
        }
    }

    AnxProcTrace("filter table replaced: %lu rules\n", count);
    status = STATUS_SUCCESS;
    return status;
}

/*
 * 函数名称：AnxProcFilterDecide
 * 函数作用：对给定规则类型与名称做匹配决策。TRUE = 采集入队，FALSE = 丢弃。
 * 仅快路径调用（每事件一次），规则数 <= 512，线性匹配在热路径可接受
 * （首条 DROP 规则通常即命中；更优的哈希索引留作后续优化）。
 * Purpose: Match decision for one rule kind. TRUE = collect, FALSE = drop.
 *          Called once per event on the hot path; linear scan over <= 512
 *          rules is acceptable (hash index is a future optimization).
 * IRQL：<= DISPATCH_LEVEL
 */
BOOLEAN AnxProcFilterDecide(_In_ UINT32 RuleType, _In_opt_ PCWSTR Name,
                            _In_ SIZE_T NameChars)
{
    PANX_PROC_FILTER_TABLE table;
    KIRQL                  oldIrql;
    ULONG                  i;
    /* 默认采集（fail-open 于采集侧）：只有命中 DROP 规则才丢弃；
     * 未命中任何规则的事件必须保留，否则过滤表下发后未覆盖的
     * 进程创建/文件/注册表事件会全部丢失（2026-08-14 VM 实测：
     * 探针 CREATE 全部被吞，EDR 溯源链路失效）。
     * Collect by default (fail-open on the collection side): only an explicit
     * DROP rule discards. Events that match no rule must survive; otherwise a
     * pushed filter table silently drops every uncovered event (verified in VM
     * 2026-08-14: all probe CREATEs were swallowed). */
    BOOLEAN                collect = TRUE;

    oldIrql = ExAcquireSpinLockExclusive(&g_AnxProc.TableLock);
    table = g_AnxProc.FilterTable;
    if (table == NULL) {
        /* 无表：默认全部采集（fail-open 于采集侧，fail-closed 于保护侧） */
        ExReleaseSpinLockExclusive(&g_AnxProc.TableLock, oldIrql);
        return TRUE;
    }

    for (i = 0; i < table->Count; i++) {
        const ANX_PROC_FILTER_RULE* rule = &table->Rules[i];
        BOOLEAN                     hit;

        if (rule->RuleType != RuleType || rule->NameLen == 0) {
            continue;
        }

        if (rule->RuleType == ANX_PROC_RULE_IMAGE_PATH_EXACT) {
            /* 精确全等：防 Phantom DLL（§13.4），仅"名称长度相等且逐字符相等"命中 */
            hit = (Name != NULL) && (rule->NameLen == NameChars) &&
                  (RtlCompareMemory(rule->Name, Name,
                                    rule->NameLen * sizeof(WCHAR)) ==
                   rule->NameLen * sizeof(WCHAR));
        } else {
            hit = AnxProcMatchPrefix(rule->Name, rule->NameLen, Name, NameChars,
                                     (rule->Flags & ANX_PROC_FILTER_F_CASE_INSENSITIVE) != 0);
        }

        if (!hit) {
            continue;
        }
        /* 命中：DROP 丢弃并终止；COLLECT 显式保留（继续扫描剩余规则？不——
         * 首个 COLLECT 命中即保留，与"默认采集"语义一致，避免被后续
         * 同类型 DROP 反向覆盖造成规则顺序敏感）。 */
        if (rule->Action == ANX_PROC_FILTER_DROP) {
            collect = FALSE;
            break;
        }
        if (rule->Action == ANX_PROC_FILTER_COLLECT) {
            collect = TRUE;
            break;
        }
    }

    ExReleaseSpinLockExclusive(&g_AnxProc.TableLock, oldIrql);
    return collect;
}

/*
 * 函数名称：AnxProcImageBuiltinSkip
 * 函数作用：映像加载内置精确白名单。System32 核心 DLL 在映像回调中
 * 产生大量事件，这些路径由 TrustService 在用户态验签并缓存，驱动侧
 * 仅对系统关键 DLL 做精确跳过（不含通配/前缀，防 Phantom DLL 变体）。
 * 用户表无法关闭该内置防呆（fail-closed 于"不过滤关键系统映像"）。
 * Purpose: Built-in exact allowlist for critical System32 DLLs on the image
 *          load path. User mode verifies + caches them via TrustService;
 *          the driver only skips exact known-good paths (no prefix/wildcard,
 *          anti Phantom DLL variants). Not overridable by the user table.
 * IRQL：<= DISPATCH_LEVEL
 */
BOOLEAN AnxProcImageBuiltinSkip(_In_opt_ PCWSTR Path, _In_ SIZE_T PathChars)
{
    static const WCHAR* kSkipExact[] = {
        L"\\SystemRoot\\System32\\ntdll.dll",
        L"\\SystemRoot\\System32\\kernel32.dll",
        L"\\SystemRoot\\System32\\KERNELBASE.dll",
        L"\\SystemRoot\\System32\\kernel.appcore.dll",
    };
    static const ULONG kSkipCount = sizeof(kSkipExact) / sizeof(kSkipExact[0]);
    ULONG i;

    if (Path == NULL || PathChars == 0) {
        return FALSE;
    }

    for (i = 0; i < kSkipCount; i++) {
        SIZE_T ruleChars = wcslen(kSkipExact[i]);

        if (ruleChars == PathChars &&
            RtlCompareMemory(kSkipExact[i], Path, ruleChars * sizeof(WCHAR)) ==
                ruleChars * sizeof(WCHAR)) {
            return TRUE;
        }
    }
    return FALSE;
}

/*
 * 函数名称：AnxProcRulesInitialize
 * 函数作用：初始化过滤表锁与空表。
 * Purpose: Initializes the table lock and an empty table.
 * IRQL：PASSIVE_LEVEL
 */
NTSTATUS AnxProcRulesInitialize(void)
{
    /* 过滤表锁在 DriverEntry 的 RtlZeroMemory(&g_AnxProc, ...) 中零初始化
     * （EX_SPIN_LOCK 零值即未持有态），这里只保证表为空 */
    g_AnxProc.FilterTable = NULL;
    return STATUS_SUCCESS;
}

/*
 * 函数名称：AnxProcRulesShutdown
 * 函数作用：释放过滤表。
 * Purpose: Frees the filter table.
 * IRQL：PASSIVE_LEVEL
 */
void AnxProcRulesShutdown(void)
{
    KIRQL        oldIrql;
    PANX_PROC_FILTER_TABLE table;

    oldIrql = ExAcquireSpinLockExclusive(&g_AnxProc.TableLock);
    table = g_AnxProc.FilterTable;
    g_AnxProc.FilterTable = NULL;
    ExReleaseSpinLockExclusive(&g_AnxProc.TableLock, oldIrql);

    if (table != NULL) {
        ExFreePoolWithTag(table, ANX_PROC_TAG_RULES);
    }
}