/*
 * AnXinHypervisor - Serial Debug Output
 * Module: native/hypervisor/src/debug.c
 *
 * VMX root / SVM host cannot call DbgPrint or any Windows API.
 * All diagnostic output goes through COM1 (0x3F8) via direct I/O port access.
 * The I/O bitmap (Intel) or IOPM (AMD) must allow COM1 ports without exit.
 */

#include "../include/platform.h"
#include <stdarg.h>

#define COM1_PORT       0x3F8
#define COM1_THR        (COM1_PORT + 0)   /* Transmitter Holding Register */
#define COM1_IER        (COM1_PORT + 1)   /* Interrupt Enable Register */
#define COM1_FCR        (COM1_PORT + 2)   /* FIFO Control Register */
#define COM1_LCR        (COM1_PORT + 3)   /* Line Control Register */
#define COM1_MCR        (COM1_PORT + 4)   /* Modem Control Register */
#define COM1_LSR        (COM1_PORT + 5)   /* Line Status Register */

#define COM1_LSR_THRE   0x20              /* THR Empty - ready to transmit */

static BOOLEAN g_SerialInitialized = FALSE;

/*
 * Initialize COM1 for 115200 8N1.
 * Called once in DriverEntry (PASSIVE_LEVEL, before entering virtualization).
 */
VOID
AnxDebugInit(VOID)
{
    if (g_SerialInitialized) return;

    __outbyte(COM1_IER, 0x00);    /* Disable all interrupts */
    __outbyte(COM1_LCR, 0x80);    /* Enable DLAB (set baud rate divisor) */
    __outbyte(COM1_PORT + 0, 0x01); /* Divisor lo: 115200 baud */
    __outbyte(COM1_PORT + 1, 0x00); /* Divisor hi */
    __outbyte(COM1_LCR, 0x03);    /* 8 bits, no parity, one stop bit */
    __outbyte(COM1_FCR, 0xC7);    /* Enable FIFO, clear them, 14-byte threshold */
    __outbyte(COM1_MCR, 0x0B);    /* IRQs enabled, RTS/DSR set */

    g_SerialInitialized = TRUE;
}

/*
 * Write a single character to COM1.
 * Safe to call from VMX root / SVM host (pure port I/O, no API calls).
 */
static
VOID
AnxSerialPutChar(
    _In_ CHAR c
)
{
    ULONG spin = 0;
    while (!(__inbyte(COM1_LSR) & COM1_LSR_THRE)) {
        _mm_pause();
        if (++spin > 100000) return;  /* Timeout: don't hang the hypervisor */
    }
    __outbyte(COM1_THR, (UCHAR)c);
}

/*
 * Write a null-terminated string to COM1.
 */
static
VOID
AnxSerialPutString(
    _In_ const char* s
)
{
    while (*s) {
        if (*s == '\n') AnxSerialPutChar('\r');
        AnxSerialPutChar(*s);
        s++;
    }
}

/*
 * Minimal integer-to-hex conversion (no CRT).
 */
static
VOID
AnxSerialPutHex64(
    _In_ ULONG64 Value
)
{
    char buf[19]; /* "0x" + 16 hex digits + null */
    int i;

    buf[0] = '0';
    buf[1] = 'x';
    for (i = 15; i >= 0; i--) {
        UCHAR nibble = (UCHAR)(Value & 0xF);
        buf[2 + (15 - i)] = (nibble < 10) ? ('0' + nibble) : ('A' + nibble - 10);
        Value >>= 4;
    }
    buf[18] = '\0';
    AnxSerialPutString(buf);
}

static
VOID
AnxSerialPutDec(
    _In_ ULONG64 Value
)
{
    char buf[21];
    int i = 20;

    buf[i] = '\0';
    if (Value == 0) {
        buf[--i] = '0';
    } else {
        while (Value > 0 && i > 0) {
            buf[--i] = '0' + (char)(Value % 10);
            Value /= 10;
        }
    }
    AnxSerialPutString(&buf[i]);
}

/*
 * Mini printf for VMX root context.
 * Supports: %s (string), %d/%u (ULONG64 decimal), %x/%p (hex), %c (char), %% (literal)
 * Does NOT support: width, precision, %f, %lld (all integers treated as ULONG64).
 */
VOID
AnxDebugPrint(
    _In_ const char* Fmt,
    ...
)
{
    va_list args;
    va_start(args, Fmt);

    while (*Fmt) {
        if (*Fmt != '%') {
            if (*Fmt == '\n') AnxSerialPutChar('\r');
            AnxSerialPutChar(*Fmt);
            Fmt++;
            continue;
        }

        Fmt++; /* skip '%' */
        switch (*Fmt) {
        case 's': {
            typedef const char* PCSTR_VA;
            AnxSerialPutString(va_arg(args, PCSTR_VA));
            break;
        }
        case 'd':
        case 'u':
            AnxSerialPutDec(va_arg(args, ULONG64));
            break;
        case 'x':
        case 'p':
            AnxSerialPutHex64(va_arg(args, ULONG64));
            break;
        case 'c':
            AnxSerialPutChar((CHAR)va_arg(args, int));
            break;
        case '%':
            AnxSerialPutChar('%');
            break;
        default:
            AnxSerialPutChar('%');
            AnxSerialPutChar(*Fmt);
            break;
        }
        Fmt++;
    }

    va_end(args);
}

/* Convenience macros matching design doc log levels */
#define HV_LOG_ERR(fmt, ...) AnxDebugPrint("[HV:ERR] " fmt "\n", ##__VA_ARGS__)
#define HV_LOG_WRN(fmt, ...) AnxDebugPrint("[HV:WRN] " fmt "\n", ##__VA_ARGS__)
#define HV_LOG_INF(fmt, ...) AnxDebugPrint("[HV:INF] " fmt "\n", ##__VA_ARGS__)

#ifdef DBG
#define HV_LOG_DBG(fmt, ...) AnxDebugPrint("[HV:DBG] " fmt "\n", ##__VA_ARGS__)
#else
#define HV_LOG_DBG(fmt, ...)
#endif
