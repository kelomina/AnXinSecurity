/*++
Copyright (c) AnXin Security. All rights reserved.

Module Name:
    registry.c

Abstract:
    AnXinProcMon.sys 注册表行为采集（CmRegisterCallbackEx）。
    Registry behavior collection (CmRegisterCallbackEx).

    设计（契约 v6 §4.3）：
    - 只采集不拦截：RegNtSetValueKey / RegNtPreCreateKey / RegNtDeleteKey /
      RegNtRenameKey → 采集后返回 STATUS_SUCCESS（不阻断任何操作）。
    - 与 AnXinProcProtect 的注册表自保护回调共存（两驱动独立注册，
      互不干扰；采集侧不修改返回值）。
    - 过滤：REG_KEY_PREFIX 规则（DROP 命中丢弃）。
    - 路径来源（WDK 各通知结构字段差异，均需判空 + __try 保护）：
      * CREATE：REG_CREATE_KEY_INFORMATION.CompleteName（文档化完整路径）。
      * SETVALUE / DELETE / RENAME：结构只有 Object（未文档化 KEY 对象，
        首成员 KeyName 为 PUNICODE_STRING，Sysmon/ProcMon 同法读取；
        Object 为 NULL 或读取失败时事件无负载，用户态按 pid 关联）。
      * RENAME：NewName 为文档化新名，作为负载第二段拼入（"旧名\\n新名"）。
    - 防呆：System PID（4/8）不采集；AnxIn 自身服务键默认由用户态规则表
      决定（不在内核硬编码路径）。

    Design (contract v6 §4.3):
    - Collect-only, never block.
    - Path source depends on the WDK notify structure (all null-checked and
      __try-protected): CREATE uses the documented CompleteName; the others
      only carry an undocumented KEY object whose first member KeyName is a
      PUNICODE_STRING (same approach as Sysmon/ProcMon). RENAME also embeds
      the documented NewName after "old\\nnew".
    - System PIDs (4/8) skipped; AnXin's own service key is governed by the
      user-mode rule table, not hardcoded in the kernel.

Environment:
    Kernel mode only.

--*/

#include "anx_proc_internal.h"

static LARGE_INTEGER g_RegCookie = { 0 };
static BOOLEAN       g_RegRegistered = FALSE;

/*
 * 未文档化 KEY 对象头（CmRegisterCallbackEx 各信息结构的 Object 字段）。
 * 首成员 KeyName 自 Windows XP 起稳定不变，Sysmon / Process Monitor 均以
 * 此方式读取完整键路径。仅读取首成员，绝不解引用其他字段。
 * Undocumented key object header (the Object field of the Cm notify info
 * structs). KeyName as the first member has been stable since Windows XP and
 * is how Sysmon / Process Monitor read the full key path. Only the first
 * member is ever read.
 */
typedef struct _ANX_PROC_REGOBJECT_HEADER {
    PUNICODE_STRING KeyName;
} ANX_PROC_REGOBJECT_HEADER, *PANX_PROC_REGOBJECT_HEADER;

/* ==========================================================================
 * 辅助 / Helpers
 * ========================================================================== */

/*
 * 函数名称：AnxProcCaptureRegName
 * 函数作用：从文档化 UNICODE_STRING 或未文档化 Object 安全读取键路径并分配
 * 非分页缓冲（调用方以 ANX_PROC_TAG_PAYLOAD 释放）。读取失败返回 NULL。
 * Purpose: Safely reads a key path from a documented UNICODE_STRING or an
 *          undocumented Object into a non-paged buffer (caller frees with
 *          ANX_PROC_TAG_PAYLOAD). NULL on failure.
 * IRQL：<= DISPATCH_LEVEL
 */
static PUINT8 AnxProcCaptureRegName(_In_opt_ PCUNICODE_STRING Direct,
                                    _In_opt_ PVOID Object,
                                    _Out_ ULONG* OutBytes)
{
    PUNICODE_STRING name = NULL;
    ULONG           chars;
    PUINT8          buffer;

    *OutBytes = 0;

    __try {
        if (Direct != NULL && Direct->Buffer != NULL && Direct->Length > 0) {
            name = (PUNICODE_STRING)Direct;
        } else if (Object != NULL) {
            PANX_PROC_REGOBJECT_HEADER head =
                (PANX_PROC_REGOBJECT_HEADER)Object;
            if (head->KeyName != NULL && head->KeyName->Buffer != NULL &&
                head->KeyName->Length > 0) {
                name = head->KeyName;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }

    if (name == NULL) {
        return NULL;
    }

    chars = name->Length / sizeof(WCHAR);
    if (chars > ANX_PROC_MAX_PATH - 1) {
        chars = ANX_PROC_MAX_PATH - 1;
    }

    buffer = (PUINT8)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                     (chars + 1) * sizeof(WCHAR),
                                     ANX_PROC_TAG_PAYLOAD);
    if (buffer == NULL) {
        return NULL;
    }

    __try {
        RtlCopyMemory(buffer, name->Buffer, chars * sizeof(WCHAR));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        ExFreePoolWithTag(buffer, ANX_PROC_TAG_PAYLOAD);
        return NULL;
    }
    ((PWCHAR)buffer)[chars] = L'\0';

    *OutBytes = chars * sizeof(WCHAR);
    return buffer;
}

/*
 * 函数名称：AnxProcGetRegObjectName
 * 函数作用：从未文档化 KEY 对象读取 KeyName（__try 保护，失败返回 NULL）。
 * 内部无分配。
 * Purpose: Reads KeyName from an undocumented key object under __try;
 *          returns NULL on failure. No allocation.
 * IRQL：<= DISPATCH_LEVEL
 */
static PCUNICODE_STRING AnxProcGetRegObjectName(_In_opt_ PVOID Object)
{
    PCUNICODE_STRING name = NULL;

    __try {
        if (Object != NULL) {
            PANX_PROC_REGOBJECT_HEADER head =
                (PANX_PROC_REGOBJECT_HEADER)Object;
            if (head->KeyName != NULL && head->KeyName->Buffer != NULL &&
                head->KeyName->Length > 0) {
                name = head->KeyName;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        name = NULL;
    }
    return name;
}

/*
 * 函数名称：AnxProcCaptureRenamePayload
 * 函数作用：RENAME 事件负载 = "旧名\n新名"（UTF-16，均以 NUL 结尾的完整
 * 字符串，两段之间加一个 L'\n'）。调用方以 ANX_PROC_TAG_PAYLOAD 释放。
 * 失败返回 NULL。
 * Purpose: RENAME payload = "oldname\nnewname" (UTF-16 NUL-terminated strings
 *          joined by a single L'\n'). Caller frees with ANX_PROC_TAG_PAYLOAD.
 * IRQL：<= DISPATCH_LEVEL
 */
static PUINT8 AnxProcCaptureRenamePayload(_In_opt_ PCUNICODE_STRING OldName,
                                          _In_opt_ PCUNICODE_STRING NewName,
                                          _Out_ ULONG* OutBytes)
{
    ULONG  oldChars = 0;
    ULONG  newChars = 0;
    ULONG  totalChars;
    PUINT8 buffer;
    PWCHAR cursor;

    *OutBytes = 0;

    if (OldName != NULL && OldName->Buffer != NULL && OldName->Length > 0) {
        oldChars = OldName->Length / sizeof(WCHAR);
    }
    if (NewName != NULL && NewName->Buffer != NULL && NewName->Length > 0) {
        newChars = NewName->Length / sizeof(WCHAR);
    }
    if (oldChars == 0 && newChars == 0) {
        return NULL;
    }

    totalChars = oldChars + 1 + newChars;   /* 旧名 + '\n' + 新名 */
    if (totalChars > ANX_PROC_MAX_PATH * 2) {
        totalChars = ANX_PROC_MAX_PATH * 2;
    }

    buffer = (PUINT8)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                     (totalChars + 1) * sizeof(WCHAR),
                                     ANX_PROC_TAG_PAYLOAD);
    if (buffer == NULL) {
        return NULL;
    }

    cursor = (PWCHAR)buffer;
    __try {
        if (oldChars > 0) {
            RtlCopyMemory(cursor, OldName->Buffer, oldChars * sizeof(WCHAR));
            cursor += oldChars;
        }
        *cursor++ = L'\n';
        if (newChars > 0) {
            RtlCopyMemory(cursor, NewName->Buffer, newChars * sizeof(WCHAR));
            cursor += newChars;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        ExFreePoolWithTag(buffer, ANX_PROC_TAG_PAYLOAD);
        return NULL;
    }
    *cursor = L'\0';

    *OutBytes = (ULONG)((PUINT8)cursor - buffer);
    return buffer;
}

/* ==========================================================================
 * Cm 回调 / Cm callback
 * ========================================================================== */

/*
 * 函数名称：AnxProcRegistryNotify
 * 函数作用：注册表操作回调（CmRegisterCallbackEx）。
 * - SETVALUE / PRECREATE / DELETE / RENAME → 对应事件；其余不采集。
 * - 防呆：System PID（4/8）不采集。
 * - REG_KEY_PREFIX 过滤规则（DROP 命中丢弃）。
 * - 不修改任何操作结果（采集侧语义）。
 * Purpose: Registry operation callback (CmRegisterCallbackEx).
 * IRQL：<= DISPATCH_LEVEL
 */
static NTSTATUS AnxProcRegistryNotify(_In_ PVOID CallbackContext,
                                      _In_opt_ PVOID Argument1,
                                      _In_opt_ PVOID Argument2)
{
    REG_NOTIFY_CLASS notifyClass;
    ULONG            pid;
    UINT16           eventType = 0;
    PUINT8           path = NULL;
    ULONG            pathBytes = 0;

    UNREFERENCED_PARAMETER(CallbackContext);

    if (AnxProcIsShuttingDown() || !AnxProcIsAttached()) {
        return STATUS_SUCCESS;   /* 不拦截 */
    }
    if (!AnxProcIsCollectEnabled()) {
        return STATUS_SUCCESS;
    }

    notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();

    if (pid == 0 || AnxProcIsSystemPid(pid)) {
        return STATUS_SUCCESS;
    }

    switch (notifyClass) {
    case RegNtSetValueKey:
        eventType = ANX_PROC_EVT_REG_SETVALUE;
        break;
    case RegNtPreCreateKey:
        eventType = ANX_PROC_EVT_REG_CREATEKEY;
        break;
    case RegNtDeleteKey:
        eventType = ANX_PROC_EVT_REG_DELETE;
        break;
    case RegNtRenameKey:
        eventType = ANX_PROC_EVT_REG_RENAME;
        break;
    default:
        return STATUS_SUCCESS;
    }

    __try {
        switch (notifyClass) {
        case RegNtSetValueKey: {
            PREG_SET_VALUE_KEY_INFORMATION info =
                (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
            if (info != NULL) {
                path = AnxProcCaptureRegName(NULL, info->Object, &pathBytes);
            }
            break;
        }
        case RegNtPreCreateKey: {
            PREG_CREATE_KEY_INFORMATION info =
                (PREG_CREATE_KEY_INFORMATION)Argument2;
            if (info != NULL) {
                path = AnxProcCaptureRegName(info->CompleteName, NULL,
                                             &pathBytes);
            }
            break;
        }
        case RegNtDeleteKey: {
            PREG_DELETE_KEY_INFORMATION info =
                (PREG_DELETE_KEY_INFORMATION)Argument2;
            if (info != NULL) {
                path = AnxProcCaptureRegName(NULL, info->Object, &pathBytes);
            }
            break;
        }
        case RegNtRenameKey: {
            PREG_RENAME_KEY_INFORMATION info =
                (PREG_RENAME_KEY_INFORMATION)Argument2;
            if (info != NULL) {
                path = AnxProcCaptureRenamePayload(
                    AnxProcGetRegObjectName(info->Object), info->NewName,
                    &pathBytes);
            }
            break;
        }
        default:
            return STATUS_SUCCESS;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        path = NULL;
        pathBytes = 0;
    }

    if (path != NULL) {
        PCWSTR p = (PCWSTR)path;
        SIZE_T chars = pathBytes / sizeof(WCHAR);

        if (AnxProcFilterDecide(ANX_PROC_RULE_REG_KEY_PREFIX, p, chars)) {
            AnxProcPostEvent(&g_AnxProc.BehaviorQueue, eventType,
                             0, pid, 0, 0, 0, 0, 0, path, pathBytes);
        }
        ExFreePoolWithTag(path, ANX_PROC_TAG_PAYLOAD);
    }

    return STATUS_SUCCESS;
}

/* ==========================================================================
 * 初始化 / Initialization
 * ========================================================================== */

/*
 * 函数名称：AnxProcRegistryInitialize
 * 函数作用：注册 Cm 回调。
 * Purpose: Registers the Cm callback.
 * IRQL：PASSIVE_LEVEL
 */
NTSTATUS AnxProcRegistryInitialize(void)
{
    NTSTATUS       status;
    UNICODE_STRING altitude;

    /*
     * altitude 必须高于 AnXinProcProtect 的注册表自保回调（采集侧在下层）
     * 且小于文件保护驱动的自保 altitude（防御侧在上层），避免冲突。
     * 数值以字符串形式传给 CmRegisterCallbackEx。
     */
    RtlInitUnicodeString(&altitude, ANX_PROC_REG_ALTITUDE);
    status = CmRegisterCallbackEx(AnxProcRegistryNotify, &altitude,
                                  g_AnxProc.DriverObject, NULL, &g_RegCookie,
                                  NULL);
    if (!NT_SUCCESS(status)) {
        AnxProcError("CmRegisterCallbackEx failed 0x%08X\n", status);
        return status;
    }
    g_RegRegistered = TRUE;
    return STATUS_SUCCESS;
}

/*
 * 函数名称：AnxProcRegistryShutdown
 * 函数作用：注销 Cm 回调。
 * Purpose: Unregisters the Cm callback.
 * IRQL：PASSIVE_LEVEL
 */
void AnxProcRegistryShutdown(void)
{
    if (g_RegRegistered) {
        CmUnRegisterCallback(g_RegCookie);
        g_RegRegistered = FALSE;
    }
}
