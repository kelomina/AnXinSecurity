/*++
Copyright (c) AnXin Security. All rights reserved.

Module Name:
    inspect.c

Abstract:
    载荷解析器：DNS 查询名、TLS ClientHello 的 SNI、明文 HTTP 的 Host。
    Payload parsers: the DNS query name, the SNI from a TLS ClientHello, and
    the Host header of plaintext HTTP.

    ！！安全前提 ！！
    本文件解析的全部是攻击者可控的网络数据，且运行在内核态。
    因此这里的每一次偏移推进都必须先做边界检查，任何一处漏检都是可远程触发的
    内核内存越界读。所有解析器都遵循同一条纪律：
      - 只用「剩余长度」做判断，不用「结束指针」做算术
      - 先检查再读，绝不先读后检查
      - 遇到任何不符合规范的取值一律放弃解析并返回 FALSE，不做任何猜测修复
    !! SECURITY PREMISE !!
    Everything parsed here is attacker-controlled network data processed in
    kernel mode. Every offset advance is bounds-checked first; a single missing
    check is a remotely triggerable kernel out-of-bounds read. All parsers obey
    the same discipline:
      - reason about remaining length, never do end-pointer arithmetic
      - check before reading, never read then check
      - on any out-of-spec value, abandon parsing and return FALSE — never guess

Environment:
    Kernel mode only.

--*/

#include "anx_net_internal.h"

/* 域名总长上限（RFC 1035 规定 255 字节，含长度前缀） */
/* Maximum domain length (RFC 1035 allows 255 bytes including length prefixes) */
#define ANX_DNS_MAX_NAME_CHARS   253u
#define ANX_DNS_HEADER_SIZE      12u
#define ANX_DNS_MAX_LABEL        63u

/*
 * 把 ASCII 字节按域名合法字符集转成 WCHAR。
 * 非法字符直接判定为解析失败，避免把二进制垃圾当成域名喂给匹配器。
 * Converts ASCII bytes to WCHAR restricted to the legal host-name character
 * set. Illegal bytes fail the parse instead of feeding binary garbage to the
 * matcher.
 */
static FORCEINLINE BOOLEAN AnxIsHostChar(_In_ UINT8 c)
{
    return (BOOLEAN)((c >= 'a' && c <= 'z') ||
                     (c >= 'A' && c <= 'Z') ||
                     (c >= '0' && c <= '9') ||
                     c == '-' || c == '.' || c == '_');
}

/*
 * 函数名称：AnxParseDnsQuery
 * 函数作用：从 UDP 载荷中提取 DNS 查询报文的第一个 QNAME。
 * Purpose: Extracts the first QNAME from a DNS query message in a UDP payload.
 *
 * 只处理查询（QR=0）且 QDCOUNT >= 1 的报文；压缩指针在查询区不合法，遇到即放弃。
 * Only messages with QR=0 and QDCOUNT >= 1 are handled. Compression pointers are
 * illegal in the question section, so encountering one abandons the parse.
 *
 * 调用方：DATAGRAM_DATA 层分类回调
 * Called by: the DATAGRAM_DATA layer classify callback
 * IRQL：<= DISPATCH_LEVEL
 * 中文关键词：DNS 解析，查询名，标签长度前缀
 * English keywords: DNS parsing, query name, label length prefix
 */
BOOLEAN AnxParseDnsQuery(_In_reads_bytes_(Length) const UINT8* Data, _In_ SIZE_T Length,
                         _Out_writes_(DomainChars) PWCHAR Domain, _In_ SIZE_T DomainChars)
{
    SIZE_T offset;
    SIZE_T outIndex = 0;
    UINT16 flags;
    UINT16 questionCount;
    SIZE_T maxOut;

    if (Domain == NULL || DomainChars == 0) {
        return FALSE;
    }
    RtlZeroMemory(Domain, DomainChars * sizeof(WCHAR));

    if (Data == NULL || Length < ANX_DNS_HEADER_SIZE + 1) {
        return FALSE;
    }

    /* 大端读取 / big-endian reads */
    flags         = (UINT16)((Data[2] << 8) | Data[3]);
    questionCount = (UINT16)((Data[4] << 8) | Data[5]);

    /* QR 位为 1 表示响应，本函数只解析查询 / QR=1 is a response; queries only */
    if ((flags & 0x8000u) != 0) {
        return FALSE;
    }
    if (questionCount == 0) {
        return FALSE;
    }

    maxOut = DomainChars - 1;
    if (maxOut > ANX_DNS_MAX_NAME_CHARS) {
        maxOut = ANX_DNS_MAX_NAME_CHARS;
    }

    offset = ANX_DNS_HEADER_SIZE;

    for (;;) {
        UINT8  labelLen;
        SIZE_T i;

        if (offset >= Length) {
            return FALSE;   /* 越界即失败 / running off the end is a failure */
        }

        labelLen = Data[offset];
        offset++;

        if (labelLen == 0) {
            break;          /* 名字结束 / end of name */
        }

        /* 高两位为 11 是压缩指针，查询区不允许 / 0b11 prefix is a pointer */
        if ((labelLen & 0xC0u) != 0) {
            return FALSE;
        }
        if (labelLen > ANX_DNS_MAX_LABEL) {
            return FALSE;
        }
        if (offset + labelLen > Length) {
            return FALSE;
        }

        /* 非首个标签前补点 / insert a dot before every label but the first */
        if (outIndex > 0) {
            if (outIndex >= maxOut) {
                return FALSE;
            }
            Domain[outIndex++] = L'.';
        }

        for (i = 0; i < labelLen; i++) {
            UINT8 c = Data[offset + i];

            if (!AnxIsHostChar(c)) {
                return FALSE;
            }
            if (outIndex >= maxOut) {
                return FALSE;
            }
            Domain[outIndex++] = (WCHAR)c;
        }

        offset += labelLen;
    }

    if (outIndex == 0) {
        return FALSE;
    }

    Domain[outIndex] = L'\0';
    AnxDomainToLower(Domain, outIndex);
    return TRUE;
}

/*
 * 函数名称：AnxParseTlsSni
 * 函数作用：从 TLS ClientHello 中提取 server_name 扩展里的主机名。
 * Purpose: Extracts the host name from the server_name extension of a TLS
 *          ClientHello.
 *
 * 只解析单条完整落在缓冲内的 TLS 记录；跨记录分片一律放弃（返回 FALSE），
 * 由调用方按「未识别域名」处理，绝不做跨包重组。
 * Only a single TLS record fully contained in the buffer is parsed. Records
 * split across segments are abandoned (FALSE) and treated by the caller as
 * "no domain identified" — no cross-packet reassembly is attempted.
 *
 * 调用方：STREAM 层分类回调
 * Called by: the STREAM layer classify callback
 * IRQL：<= DISPATCH_LEVEL
 * 中文关键词：TLS SNI，ClientHello，扩展解析
 * English keywords: TLS SNI, ClientHello, extension parsing
 */
BOOLEAN AnxParseTlsSni(_In_reads_bytes_(Length) const UINT8* Data, _In_ SIZE_T Length,
                       _Out_writes_(DomainChars) PWCHAR Domain, _In_ SIZE_T DomainChars)
{
    SIZE_T offset;
    SIZE_T handshakeEnd;
    SIZE_T extensionsEnd;
    UINT32 handshakeLen;
    UINT16 extensionsLen;
    UINT8  sessionIdLen;
    UINT16 cipherSuitesLen;
    UINT8  compressionLen;

    if (Domain == NULL || DomainChars == 0) {
        return FALSE;
    }
    RtlZeroMemory(Domain, DomainChars * sizeof(WCHAR));

    /* TLS 记录头 5 字节 + 握手头 4 字节 / 5-byte record header + 4-byte handshake */
    if (Data == NULL || Length < 9) {
        return FALSE;
    }

    /* content_type 必须是 handshake(22) / content_type must be handshake (22) */
    if (Data[0] != 0x16) {
        return FALSE;
    }
    /* handshake_type 必须是 client_hello(1) */
    if (Data[5] != 0x01) {
        return FALSE;
    }

    handshakeLen = ((UINT32)Data[6] << 16) | ((UINT32)Data[7] << 8) | (UINT32)Data[8];

    /* 握手体必须完整落在缓冲内 / the handshake body must be fully present */
    if (handshakeLen > Length - 9) {
        return FALSE;
    }
    handshakeEnd = 9 + handshakeLen;

    /* client_version(2) + random(32) */
    offset = 9 + 2 + 32;
    if (offset + 1 > handshakeEnd) {
        return FALSE;
    }

    sessionIdLen = Data[offset];
    offset++;
    if (offset + sessionIdLen > handshakeEnd) {
        return FALSE;
    }
    offset += sessionIdLen;

    if (offset + 2 > handshakeEnd) {
        return FALSE;
    }
    cipherSuitesLen = (UINT16)((Data[offset] << 8) | Data[offset + 1]);
    offset += 2;
    if (offset + cipherSuitesLen > handshakeEnd) {
        return FALSE;
    }
    offset += cipherSuitesLen;

    if (offset + 1 > handshakeEnd) {
        return FALSE;
    }
    compressionLen = Data[offset];
    offset++;
    if (offset + compressionLen > handshakeEnd) {
        return FALSE;
    }
    offset += compressionLen;

    /* 没有扩展段说明没有 SNI / no extension block means no SNI */
    if (offset + 2 > handshakeEnd) {
        return FALSE;
    }
    extensionsLen = (UINT16)((Data[offset] << 8) | Data[offset + 1]);
    offset += 2;
    if (offset + extensionsLen > handshakeEnd) {
        return FALSE;
    }
    extensionsEnd = offset + extensionsLen;

    while (offset + 4 <= extensionsEnd) {
        UINT16 extType = (UINT16)((Data[offset] << 8) | Data[offset + 1]);
        UINT16 extLen  = (UINT16)((Data[offset + 2] << 8) | Data[offset + 3]);
        SIZE_T extBody = offset + 4;

        if (extBody + extLen > extensionsEnd) {
            return FALSE;
        }

        if (extType == 0x0000) {                 /* server_name */
            SIZE_T listEnd;
            SIZE_T cursor;
            UINT16 listLen;

            if (extLen < 2) {
                return FALSE;
            }
            listLen = (UINT16)((Data[extBody] << 8) | Data[extBody + 1]);
            cursor  = extBody + 2;
            listEnd = cursor + listLen;
            if (listEnd > extBody + extLen) {
                return FALSE;
            }

            while (cursor + 3 <= listEnd) {
                UINT8  nameType = Data[cursor];
                UINT16 nameLen  = (UINT16)((Data[cursor + 1] << 8) | Data[cursor + 2]);
                SIZE_T nameStart = cursor + 3;
                SIZE_T i;
                SIZE_T maxOut;

                if (nameStart + nameLen > listEnd) {
                    return FALSE;
                }

                if (nameType != 0x00) {          /* 只要 host_name / host_name only */
                    cursor = nameStart + nameLen;
                    continue;
                }

                maxOut = DomainChars - 1;
                if (nameLen == 0 || nameLen > maxOut) {
                    return FALSE;
                }

                for (i = 0; i < nameLen; i++) {
                    UINT8 c = Data[nameStart + i];
                    if (!AnxIsHostChar(c)) {
                        return FALSE;
                    }
                    Domain[i] = (WCHAR)c;
                }
                Domain[nameLen] = L'\0';
                AnxDomainToLower(Domain, nameLen);
                return TRUE;
            }

            return FALSE;
        }

        offset = extBody + extLen;
    }

    return FALSE;
}

/*
 * 函数名称：AnxParseHttpHost
 * 函数作用：从明文 HTTP 请求头中提取 Host 字段的值。
 * Purpose: Extracts the value of the Host header from a plaintext HTTP request.
 *
 * 只在缓冲的前若干字节里找首行之后的 Host 行；不做续行（obs-fold）处理，
 * 不接受端口以外的任何附加内容。
 * Only the leading bytes are scanned for a Host line after the request line.
 * Line folding (obs-fold) is not honoured and nothing but an optional port is
 * accepted after the host.
 *
 * 调用方：STREAM 层分类回调
 * Called by: the STREAM layer classify callback
 * IRQL：<= DISPATCH_LEVEL
 * 中文关键词：HTTP Host，明文头部，请求行
 * English keywords: HTTP Host, plaintext header, request line
 */
BOOLEAN AnxParseHttpHost(_In_reads_bytes_(Length) const UINT8* Data, _In_ SIZE_T Length,
                         _Out_writes_(DomainChars) PWCHAR Domain, _In_ SIZE_T DomainChars)
{
    static const UINT8 kHost[5] = { 'h', 'o', 's', 't', ':' };

    SIZE_T i;
    SIZE_T maxOut;

    if (Domain == NULL || DomainChars == 0) {
        return FALSE;
    }
    RtlZeroMemory(Domain, DomainChars * sizeof(WCHAR));

    if (Data == NULL || Length < 16) {
        return FALSE;
    }

    maxOut = DomainChars - 1;

    /* i 从 1 开始：Host 头不可能出现在第 0 字节（那是请求行） */
    /* Start at 1: a Host header can never begin at byte 0 (that's the request line) */
    for (i = 1; i + sizeof(kHost) < Length; i++) {
        SIZE_T cursor;
        SIZE_T outIndex = 0;
        SIZE_T k;
        BOOLEAN matched = TRUE;

        /* 必须处在行首 / must sit at the start of a line */
        if (Data[i - 1] != '\n') {
            continue;
        }

        for (k = 0; k < sizeof(kHost); k++) {
            UINT8 c = Data[i + k];
            if (c >= 'A' && c <= 'Z') {
                c = (UINT8)(c - 'A' + 'a');
            }
            if (c != kHost[k]) {
                matched = FALSE;
                break;
            }
        }
        if (!matched) {
            continue;
        }

        cursor = i + sizeof(kHost);

        /* 跳过冒号后的空白 / skip the whitespace after the colon */
        while (cursor < Length && (Data[cursor] == ' ' || Data[cursor] == '\t')) {
            cursor++;
        }

        while (cursor < Length) {
            UINT8 c = Data[cursor];

            if (c == '\r' || c == '\n') {
                break;
            }
            if (c == ':') {
                /* 端口部分不参与域名匹配 / the port is not part of the domain */
                break;
            }
            if (!AnxIsHostChar(c)) {
                return FALSE;
            }
            if (outIndex >= maxOut) {
                return FALSE;
            }
            Domain[outIndex++] = (WCHAR)c;
            cursor++;
        }

        if (outIndex == 0) {
            return FALSE;
        }

        Domain[outIndex] = L'\0';
        AnxDomainToLower(Domain, outIndex);
        return TRUE;
    }

    return FALSE;
}
