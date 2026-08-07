/*++
Copyright (c) AnXin Security. All rights reserved.

Module Name:
    util.c

Abstract:
    AnXinNetFilter 通用小工具：时间、哈希、地址比较、字符串处理。
    Small shared helpers for AnXinNetFilter: time, hashing, address comparison
    and string handling.

    本文件中的函数全部可在 DISPATCH_LEVEL 调用，不做任何分页内存访问。
    Every function here is DISPATCH_LEVEL-safe and touches no paged memory.

Environment:
    Kernel mode only.

--*/

#include "anx_net_internal.h"

/* Windows FILETIME 纪元(1601-01-01) 到 Unix 纪元(1970-01-01) 的 100ns 间隔数 */
#define ANX_UNIX_EPOCH_DELTA_100NS  116444736000000000LL

/* FNV-1a 64 位常量 / FNV-1a 64-bit constants */
#define ANX_FNV_OFFSET_BASIS        0xcbf29ce484222325ULL
#define ANX_FNV_PRIME               0x00000100000001b3ULL

/*
 * 函数名称：AnxGetSystemTimeMs
 * 函数作用：返回当前 Unix 毫秒时间戳，用于事件时间与缓存过期。
 * Purpose: Returns the current Unix timestamp in milliseconds, used for event
 *          timestamps and cache expiry.
 * 调用方：事件构造、缓存插入/查找、挂起超时扫描
 * Called by: event construction, cache insert/lookup, pending-timeout sweep
 * IRQL：<= DISPATCH_LEVEL（KeQuerySystemTimePrecise 在任意 IRQL 可调用）
 * 中文关键词：系统时间，毫秒时间戳，Unix 纪元
 * English keywords: system time, millisecond timestamp, Unix epoch
 */
UINT64 AnxGetSystemTimeMs(void)
{
    LARGE_INTEGER systemTime;

    KeQuerySystemTimePrecise(&systemTime);

    if (systemTime.QuadPart <= ANX_UNIX_EPOCH_DELTA_100NS) {
        return 0;
    }

    return (UINT64)((systemTime.QuadPart - ANX_UNIX_EPOCH_DELTA_100NS) / 10000LL);
}

/*
 * 函数名称：AnxHashImagePath
 * 函数作用：对映像 NT 路径做 ASCII 大写折叠后的 FNV-1a 64 位哈希。
 * Purpose: FNV-1a 64 hash of an image NT path after ASCII-only upper-casing.
 *
 * 大小写折叠只处理 ASCII 'a'-'z'。这是刻意的：用户态 Rust 侧必须用完全相同的
 * 规则计算哈希，ASCII-only 折叠在两侧都能零歧义复现，而依赖 NT 大写表会引入
 * 内核版本相关的差异。非 ASCII 字符按原码元参与哈希。
 * Case folding covers ASCII 'a'-'z' only. This is deliberate: the Rust side
 * must reproduce the hash exactly, and ASCII-only folding is unambiguous on
 * both sides, whereas the NT upcase table is kernel-version dependent.
 * Non-ASCII code units are hashed as-is.
 *
 * 每个 WCHAR 按小端两字节喂入哈希，Rust 侧必须一致。
 * Each WCHAR is fed to the hash as two little-endian bytes; Rust must match.
 *
 * 调用方：AnxHashAppIdBytes、规则编译
 * Called by: AnxHashAppIdBytes, rule compilation
 * 中文关键词：路径哈希，FNV-1a，大小写折叠
 * English keywords: path hash, FNV-1a, case folding
 */
UINT64 AnxHashImagePath(_In_ PCWSTR Path, _In_ SIZE_T CharCount)
{
    UINT64 hash = ANX_FNV_OFFSET_BASIS;
    SIZE_T i;

    if (Path == NULL || CharCount == 0) {
        return 0;
    }

    for (i = 0; i < CharCount; i++) {
        WCHAR c = Path[i];

        if (c >= L'a' && c <= L'z') {
            c = (WCHAR)(c - L'a' + L'A');
        }

        hash ^= (UINT64)(c & 0x00FF);
        hash *= ANX_FNV_PRIME;
        hash ^= (UINT64)((c >> 8) & 0x00FF);
        hash *= ANX_FNV_PRIME;
    }

    /* 0 被保留用于“任意进程”，极低概率的碰撞退化为 1 */
    /* 0 is reserved for "any process"; fold the improbable collision to 1 */
    return (hash == 0) ? 1ULL : hash;
}

/*
 * 函数名称：AnxHashAppIdBytes
 * 函数作用：对 WFP 的 ALE_APP_ID 字节块（UTF-16 NT 路径）计算哈希。
 * Purpose: Hashes a WFP ALE_APP_ID byte blob (a UTF-16 NT path).
 *
 * WFP 给出的 app id 通常带一个结尾 NUL，必须剥掉后再哈希，否则与用户态
 * FwpmGetAppIdFromFileName0 的结果不一致。
 * The app id WFP hands out usually carries a trailing NUL which must be
 * stripped, otherwise the hash disagrees with the user-mode value derived
 * from FwpmGetAppIdFromFileName0.
 *
 * 调用方：ALE 分类回调
 * Called by: ALE classify callbacks
 * 中文关键词：应用标识，字节块，哈希归一
 * English keywords: app id, byte blob, hash normalization
 */
UINT64 AnxHashAppIdBytes(_In_reads_bytes_(ByteLength) const void* Bytes, _In_ SIZE_T ByteLength)
{
    const WCHAR* chars;
    SIZE_T       count;

    if (Bytes == NULL || ByteLength < sizeof(WCHAR)) {
        return 0;
    }

    chars = (const WCHAR*)Bytes;
    count = ByteLength / sizeof(WCHAR);

    /* 剥掉全部结尾 NUL / strip every trailing NUL */
    while (count > 0 && chars[count - 1] == L'\0') {
        count--;
    }

    if (count == 0) {
        return 0;
    }

    return AnxHashImagePath(chars, count);
}

/*
 * 函数名称：AnxAddrIsLoopback
 * 函数作用：判断地址是否为回环地址（IPv4 127.0.0.0/8 或 IPv6 ::1）。
 * Purpose: Tests whether an address is loopback (IPv4 127.0.0.0/8 or IPv6 ::1).
 * 调用方：ALE 分类回调（回环流量默认直接放行）
 * Called by: ALE classify callbacks (loopback is permitted by default)
 * 中文关键词：回环地址，本地环回，放行豁免
 * English keywords: loopback address, local loopback, permit exemption
 */
BOOLEAN AnxAddrIsLoopback(_In_ const ANX_NET_ADDR* Addr)
{
    ULONG i;

    if (Addr == NULL) {
        return FALSE;
    }

    if (Addr->Family == ANX_NET_AF_INET) {
        return (BOOLEAN)(Addr->Bytes[0] == 127);
    }

    if (Addr->Family == ANX_NET_AF_INET6) {
        for (i = 0; i < 15; i++) {
            if (Addr->Bytes[i] != 0) {
                /* 也接受 IPv4 映射的回环 ::ffff:127.x.x.x */
                /* also accept the IPv4-mapped loopback ::ffff:127.x.x.x */
                if (i == 10 && Addr->Bytes[10] == 0xFF && Addr->Bytes[11] == 0xFF) {
                    return (BOOLEAN)(Addr->Bytes[12] == 127);
                }
                return FALSE;
            }
        }
        return (BOOLEAN)(Addr->Bytes[15] == 1);
    }

    return FALSE;
}

/*
 * 函数名称：AnxAddrMatchesCidr
 * 函数作用：按 CIDR 前缀长度比较地址是否落在网段内。
 * Purpose: Tests whether an address falls inside a CIDR network.
 *
 * PrefixLen 为 0 时视为匹配任意地址；地址族不同直接判否。
 * A PrefixLen of 0 matches any address; differing families never match.
 *
 * 调用方：AnxRulesEvaluate
 * Called by: AnxRulesEvaluate
 * 中文关键词：CIDR 匹配，网段比较，前缀长度
 * English keywords: CIDR match, network comparison, prefix length
 */
BOOLEAN AnxAddrMatchesCidr(_In_ const ANX_NET_ADDR* Addr,
                           _In_ const ANX_NET_ADDR* Network,
                           _In_ UINT8 PrefixLen)
{
    ULONG addrBits;
    ULONG fullBytes;
    ULONG remainderBits;

    if (Addr == NULL || Network == NULL) {
        return FALSE;
    }

    /* Family == 0 表示规则不限制地址 / family 0 means "any address" */
    if (Network->Family == 0) {
        return TRUE;
    }

    if (Addr->Family != Network->Family) {
        return FALSE;
    }

    addrBits = (Network->Family == ANX_NET_AF_INET) ? 32u : 128u;

    if (PrefixLen == 0) {
        return TRUE;
    }
    if (PrefixLen > addrBits) {
        PrefixLen = (UINT8)addrBits;
    }

    fullBytes     = PrefixLen / 8u;
    remainderBits = PrefixLen % 8u;

    if (fullBytes > 0 &&
        RtlCompareMemory(Addr->Bytes, Network->Bytes, fullBytes) != fullBytes) {
        return FALSE;
    }

    if (remainderBits != 0) {
        UINT8 mask = (UINT8)(0xFFu << (8u - remainderBits));
        if ((Addr->Bytes[fullBytes] & mask) != (Network->Bytes[fullBytes] & mask)) {
            return FALSE;
        }
    }

    return TRUE;
}

/*
 * 函数名称：AnxCopyPathToBuffer
 * 函数作用：把源字符串按上限截断复制到目标缓冲并保证 NUL 结尾。
 * Purpose: Copies a source string into a bounded destination, always NUL-terminated.
 *
 * 目标缓冲会被整体清零，避免把上一次事件的残留内容泄漏给用户态。
 * The destination is zeroed first so leftovers from a previous event are never
 * leaked to user mode.
 *
 * 调用方：事件构造、连接信息填充
 * Called by: event construction, connection-info population
 * 中文关键词：字符串截断，缓冲复制，信息泄漏防护
 * English keywords: string truncation, buffer copy, info-leak prevention
 */
void AnxCopyPathToBuffer(_Out_writes_(DestChars) PWCHAR Dest,
                         _In_ SIZE_T DestChars,
                         _In_opt_ PCWSTR Source,
                         _In_ SIZE_T SourceChars)
{
    SIZE_T copyChars;

    if (Dest == NULL || DestChars == 0) {
        return;
    }

    RtlZeroMemory(Dest, DestChars * sizeof(WCHAR));

    if (Source == NULL || SourceChars == 0) {
        return;
    }

    copyChars = SourceChars;
    if (copyChars > DestChars - 1) {
        copyChars = DestChars - 1;
    }

    RtlCopyMemory(Dest, Source, copyChars * sizeof(WCHAR));
    Dest[copyChars] = L'\0';
}

/*
 * 函数名称：AnxDomainToLower
 * 函数作用：把域名就地转为 ASCII 小写，遇到 NUL 提前结束。
 * Purpose: Lower-cases a domain in place (ASCII only), stopping at NUL.
 *
 * 域名规范只允许 LDH（字母/数字/连字符）与 punycode 前缀，全部是 ASCII，
 * 因此不需要 Unicode 大小写表。
 * Domain names are LDH plus punycode prefixes — all ASCII — so no Unicode
 * case table is needed.
 *
 * 调用方：DNS/SNI/Host 解析后
 * Called by: after DNS/SNI/Host parsing
 * 中文关键词：域名归一，小写转换，ASCII
 * English keywords: domain normalization, lower-case, ASCII
 */
void AnxDomainToLower(_Inout_updates_(CharCount) PWCHAR Domain, _In_ SIZE_T CharCount)
{
    SIZE_T i;

    if (Domain == NULL) {
        return;
    }

    for (i = 0; i < CharCount; i++) {
        if (Domain[i] == L'\0') {
            return;
        }
        if (Domain[i] >= L'A' && Domain[i] <= L'Z') {
            Domain[i] = (WCHAR)(Domain[i] - L'A' + L'a');
        }
    }
}
