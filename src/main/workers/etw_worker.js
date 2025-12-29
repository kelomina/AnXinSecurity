const { parentPort } = require('worker_threads');
const fs = require('fs');
const path = require('path');
const koffi = require('koffi');

const libAdvapi32 = koffi.load('advapi32.dll');
const libKernel32 = koffi.load('kernel32.dll');

const ERROR_SUCCESS = 0;
const ERROR_ALREADY_EXISTS = 183;
const ERROR_ACCESS_DENIED = 5;
const PROCESS_TRACE_MODE_REAL_TIME = 0x00000100;
const PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000;
const EVENT_TRACE_REAL_TIME_MODE = 0x00000100;
const EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1;
const TRACE_LEVEL_INFORMATION = 4;
const EVENT_TRACE_CONTROL_STOP = 1;
const WNODE_FLAG_TRACED_GUID = 0x00020000;

const GUID_KernelProcess = {
    Data1: 0x22FB2CD6,
    Data2: 0x0E7B,
    Data3: 0x422B,
    Data4: [0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16]
};

const GUID_KernelFile = {
    Data1: 0xEDD08927,
    Data2: 0x9CC4,
    Data3: 0x4E65,
    Data4: [0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89]
};

const GUID_KernelRegistry = {
    Data1: 0x70EB4F03,
    Data2: 0xC1DE,
    Data3: 0x4F73,
    Data4: [0xA0, 0x51, 0x33, 0xD1, 0x3D, 0x54, 0x13, 0xBD]
};

const GUID_KernelNetwork = {
    Data1: 0x7DD42A49,
    Data2: 0x5329,
    Data3: 0x4832,
    Data4: [0x8D, 0xFD, 0x43, 0xD9, 0x79, 0x15, 0x3A, 0x88]
};

const ULONG = 'uint32_t';
const ULONG64 = 'uint64_t';
const USHORT = 'uint16_t';
const UCHAR = 'uint8_t';
const LONGLONG = 'int64_t';
const HANDLE = koffi.pointer('HANDLE', koffi.opaque());
const PVOID = 'void *';

const GUID = koffi.struct('GUID', {
    Data1: 'uint32_t',
    Data2: 'uint16_t',
    Data3: 'uint16_t',
    Data4: koffi.array('uint8_t', 8)
});

const WNODE_HEADER = koffi.struct('WNODE_HEADER', {
    BufferSize: ULONG,
    ProviderId: ULONG,
    HistoricalContext: ULONG64,
    TimeStamp: LONGLONG,
    Guid: GUID,
    ClientContext: ULONG,
    Flags: ULONG
});

const EVENT_TRACE_PROPERTIES = koffi.struct('EVENT_TRACE_PROPERTIES', {
    Wnode: WNODE_HEADER,
    BufferSize: ULONG,
    MinimumBuffers: ULONG,
    MaximumBuffers: ULONG,
    MaximumFileSize: ULONG,
    LogFileMode: ULONG,
    FlushTimer: ULONG,
    EnableFlags: ULONG,
    AgeLimit: 'int32_t',
    NumberOfBuffers: ULONG,
    FreeBuffers: ULONG,
    EventsLost: ULONG,
    BuffersWritten: ULONG,
    LogBuffersLost: ULONG,
    RealTimeBuffersLost: ULONG,
    LoggerThreadId: HANDLE,
    LogFileNameOffset: ULONG,
    LoggerNameOffset: ULONG
});

const EVENT_HEADER = koffi.struct('EVENT_HEADER', {
    Size: USHORT,
    HeaderType: USHORT,
    Flags: USHORT,
    EventProperty: USHORT,
    ThreadId: ULONG,
    ProcessId: ULONG,
    TimeStamp: LONGLONG,
    ProviderId: GUID,
    EventDescriptor: koffi.struct({
        Id: USHORT,
        Version: UCHAR,
        Channel: UCHAR,
        Level: UCHAR,
        Opcode: UCHAR,
        Task: USHORT,
        Keyword: ULONG64
    }),
    KernelTime: ULONG,
    UserTime: ULONG,
    ActivityId: GUID
});

const EVENT_TRACE_HEADER = koffi.struct('EVENT_TRACE_HEADER', {
    Size: USHORT,
    FieldTypeFlags: USHORT,
    Version: ULONG,
    ThreadId: ULONG,
    ProcessId: ULONG,
    TimeStamp: LONGLONG,
    Guid: GUID,
    ProcessorTime: ULONG64
});

const EVENT_TRACE = koffi.struct('EVENT_TRACE', {
    Header: EVENT_TRACE_HEADER,
    InstanceId: ULONG,
    ParentInstanceId: ULONG,
    ParentGuid: GUID,
    MofData: PVOID,
    MofLength: ULONG,
    ClientContext: ULONG
});

const EVENT_RECORD = koffi.struct('EVENT_RECORD', {
    EventHeader: EVENT_HEADER,
    BufferContext: koffi.struct({
        ProcessorNumber: UCHAR,
        Alignment: UCHAR,
        LoggerId: USHORT
    }),
    ExtendedDataCount: USHORT,
    UserDataLength: USHORT,
    ExtendedData: PVOID,
    UserData: PVOID,
    UserContext: PVOID
});

const EventRecordCallbackType = koffi.pointer('EventRecordCallback', koffi.proto('void', [koffi.pointer(EVENT_RECORD)]));

const EVENT_TRACE_LOGFILEW = koffi.struct('EVENT_TRACE_LOGFILEW', {
    LogFileName: 'string16',
    LoggerName: 'string16',
    CurrentTime: LONGLONG,
    BuffersRead: ULONG,
    ProcessTraceMode: ULONG,
    CurrentEvent: EVENT_TRACE,
    LogfileHeader: koffi.struct({
        BufferSize: ULONG,
        Version: ULONG,
        ProviderVersion: ULONG,
        NumberOfProcessors: ULONG,
        EndTime: LONGLONG,
        TimerResolution: ULONG,
        MaximumFileSize: ULONG,
        LogFileMode: ULONG,
        BuffersWritten: ULONG,
        StartBuffers: ULONG,
        PointerSize: ULONG,
        EventsLost: ULONG,
        CpuSpeedInMHz: ULONG,
        LoggerName: PVOID,
        LogFileName: PVOID,
        TimeZone: koffi.struct({
            Bias: 'long',
            StandardName: koffi.array('uint16_t', 32),
            StandardDate: koffi.struct({
                wYear: USHORT,
                wMonth: USHORT,
                wDayOfWeek: USHORT,
                wDay: USHORT,
                wHour: USHORT,
                wMinute: USHORT,
                wSecond: USHORT,
                wMilliseconds: USHORT
            }),
            StandardBias: 'long',
            DaylightName: koffi.array('uint16_t', 32),
            DaylightDate: koffi.struct({
                 wYear: USHORT,
                wMonth: USHORT,
                wDayOfWeek: USHORT,
                wDay: USHORT,
                wHour: USHORT,
                wMinute: USHORT,
                wSecond: USHORT,
                wMilliseconds: USHORT
            }),
            DaylightBias: 'long'
        }),
        BootTime: LONGLONG,
        PerfFreq: LONGLONG,
        StartTime: LONGLONG,
        ReservedFlags: ULONG,
        BuffersLost: ULONG
    }),
    BufferCallback: PVOID,
    BufferSize: ULONG,
    Filled: ULONG,
    EventsLost: ULONG,
    EventRecordCallback: EventRecordCallbackType,
    IsKernelTrace: ULONG,
    Context: PVOID
});

const StartTraceW = libAdvapi32.func('__stdcall', 'StartTraceW', ULONG, [koffi.out('uint64_t *'), 'string16', 'uint8_t *']);
const ControlTraceW = libAdvapi32.func('__stdcall', 'ControlTraceW', ULONG, ['uint64_t', 'string16', 'uint8_t *', ULONG]);
const EnableTraceEx2 = libAdvapi32.func('__stdcall', 'EnableTraceEx2', ULONG, ['uint64_t', koffi.pointer(GUID), ULONG, UCHAR, ULONG64, ULONG64, ULONG, PVOID]);
const OpenTraceW = libAdvapi32.func('__stdcall', 'OpenTraceW', 'uint64_t', [koffi.inout(koffi.pointer(EVENT_TRACE_LOGFILEW))]);
const ProcessTrace = libAdvapi32.func('__stdcall', 'ProcessTrace', ULONG, ['uint64_t *', ULONG, PVOID, PVOID]);
const CloseTrace = libAdvapi32.func('__stdcall', 'CloseTrace', ULONG, ['uint64_t']);
const GetLastError = libKernel32.func('__stdcall', 'GetLastError', ULONG, []);
const GetCurrentProcess = libKernel32.func('__stdcall', 'GetCurrentProcess', HANDLE, []);
const CloseHandle = libKernel32.func('__stdcall', 'CloseHandle', 'int', [HANDLE]);
const OpenProcessToken = libAdvapi32.func('__stdcall', 'OpenProcessToken', 'int', [HANDLE, ULONG, koffi.out(HANDLE)]);
const GetTokenInformation = libAdvapi32.func('__stdcall', 'GetTokenInformation', 'int', [HANDLE, ULONG, PVOID, ULONG, koffi.out('uint32_t *')]);

let sessionHandle = 0n;
let traceHandle = 0n;
let currentHandleBuffer = null;
let logfile = null;
let eventCallback = null;
let isSessionRunning = false;
let isStopping = false;
let stopPromise = null;
let processTraceDone = null;
let resolveProcessTraceDone = null;
let lastCallbackErrorAt = 0;
let etwCfg = null;
let lastPayloadCfg = null;

const DEFAULT_ETW_CFG = {
    enabled: true,
    sessionName: 'AnXinSecuritySession',
    userDataMaxBytes: 65536,
    stopTimeoutMs: 2500,
    startRetries: 2,
    retryDelayMs: 150,
    emitRegistryRawHex: false,
    network: {
        enabled: true,
        filterPrivateIps: true,
        skipLoopback: true
    }
};

function loadAppConfig() {
    const p = path.join(__dirname, '../../../config/app.json');
    try {
        const raw = fs.readFileSync(p, 'utf-8');
        return JSON.parse(raw);
    } catch {
        return {};
    }
}

function resolveEtwCfg(payloadCfg) {
    const fromFile = loadAppConfig();
    const cfg = (fromFile && typeof fromFile === 'object' ? fromFile : {});
    const etw = (cfg.etw && typeof cfg.etw === 'object') ? cfg.etw : {};
    const filters = (cfg.behaviorAnalyzer && cfg.behaviorAnalyzer.filters && typeof cfg.behaviorAnalyzer.filters === 'object') ? cfg.behaviorAnalyzer.filters : {};
    const incoming = (payloadCfg && typeof payloadCfg === 'object') ? payloadCfg : {};
    const merged = { ...DEFAULT_ETW_CFG, ...etw, ...incoming, filters };
    merged.enabled = merged.enabled !== false;
    merged.sessionName = typeof merged.sessionName === 'string' && merged.sessionName.trim() ? merged.sessionName.trim() : DEFAULT_ETW_CFG.sessionName;
    merged.userDataMaxBytes = Number.isFinite(merged.userDataMaxBytes) ? Math.max(1024, Math.min(1024 * 1024, merged.userDataMaxBytes)) : DEFAULT_ETW_CFG.userDataMaxBytes;
    merged.stopTimeoutMs = Number.isFinite(merged.stopTimeoutMs) ? Math.max(250, Math.min(30000, merged.stopTimeoutMs)) : DEFAULT_ETW_CFG.stopTimeoutMs;
    merged.startRetries = Number.isFinite(merged.startRetries) ? Math.max(0, Math.min(20, merged.startRetries)) : DEFAULT_ETW_CFG.startRetries;
    merged.retryDelayMs = Number.isFinite(merged.retryDelayMs) ? Math.max(0, Math.min(5000, merged.retryDelayMs)) : DEFAULT_ETW_CFG.retryDelayMs;
    merged.emitRegistryRawHex = !!merged.emitRegistryRawHex;

    const baseNet = (DEFAULT_ETW_CFG.network && typeof DEFAULT_ETW_CFG.network === 'object') ? DEFAULT_ETW_CFG.network : {};
    const fileNet = (etw.network && typeof etw.network === 'object') ? etw.network : {};
    const incomingNet = (incoming.network && typeof incoming.network === 'object') ? incoming.network : {};
    const network = { ...baseNet, ...fileNet, ...incomingNet };
    network.enabled = network.enabled !== false;
    network.filterPrivateIps = network.filterPrivateIps !== false;
    network.skipLoopback = network.skipLoopback !== false;
    merged.network = network;

    return merged;
}

function postMessage(msg) {
    if (!parentPort) return;
    if (msg && typeof msg === 'object' && msg.type === 'log' && msg.event) {
        const ev = msg.event;
        if (ev.provider) ev.provider = String(ev.provider);
        if (ev.data) {
            for (const k in ev.data) {
                if (typeof ev.data[k] === 'string') {
                    ev.data[k] = ev.data[k].replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\uFFFD]/g, '').trim();
                }
            }
        }
    }
    parentPort.postMessage(msg);
}

function postError(code, message, details) {
    const payload = { type: 'error', code: code || 'ETW_ERROR', message: String(message || '') };
    if (details && typeof details === 'object') payload.details = details;
    postMessage(payload);
}

function sleepSync(ms) {
    const dur = Math.max(0, Math.floor(ms || 0));
    if (!dur) return;
    try {
        const arr = new Int32Array(new SharedArrayBuffer(4));
        Atomics.wait(arr, 0, 0, dur);
    } catch {}
}

function createPropertyBuffer() {
    const propsSize = koffi.sizeof(EVENT_TRACE_PROPERTIES);
    const sessionName = (etwCfg && etwCfg.sessionName) ? etwCfg.sessionName : DEFAULT_ETW_CFG.sessionName;
    const nameSize = (sessionName.length + 1) * 2;
    const totalSize = propsSize + nameSize + 1024;
    
    const buffer = Buffer.alloc(totalSize);
    
    buffer.writeUInt32LE(totalSize, koffi.offsetof(WNODE_HEADER, 'BufferSize'));
    buffer.writeUInt32LE(1, koffi.offsetof(WNODE_HEADER, 'ClientContext'));
    buffer.writeUInt32LE(WNODE_FLAG_TRACED_GUID, koffi.offsetof(WNODE_HEADER, 'Flags'));

    buffer.writeUInt32LE(EVENT_TRACE_REAL_TIME_MODE, koffi.offsetof(EVENT_TRACE_PROPERTIES, 'LogFileMode'));
    buffer.writeUInt32LE(0, koffi.offsetof(EVENT_TRACE_PROPERTIES, 'LogFileNameOffset'));
    buffer.writeUInt32LE(propsSize, koffi.offsetof(EVENT_TRACE_PROPERTIES, 'LoggerNameOffset'));
    
    buffer.write(sessionName, propsSize, 'utf16le');
    
    return buffer;
}

function createTraceHandleArrayBuffer(handle) {
    const traceHandles = Buffer.alloc(8);
    traceHandles.writeBigUInt64LE(BigInt(handle), 0);
    return traceHandles;
}

function sameGuid(a, b) {
    if (!a || !b) return false;
    if (a.Data1 !== b.Data1) return false;
    if (a.Data2 !== b.Data2) return false;
    if (a.Data3 !== b.Data3) return false;
    if (!a.Data4 || !b.Data4) return false;
    for (let i = 0; i < 8; i++) {
        if ((a.Data4[i] >>> 0) !== (b.Data4[i] >>> 0)) return false;
    }
    return true;
}

function extractUtf16Strings(bytes, minLen = 3) {
    const buf = Buffer.from(bytes);
    let utf16 = [];
    let utf8 = [];
    try {
        const textUtf16 = buf.toString('utf16le');
        utf16 = textUtf16.split('\u0000').map(s => s.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\uFFFD]/g, '').trim()).filter(Boolean).filter(s => s.length >= minLen);
    } catch {}
    try {
        const textUtf8 = buf.toString('utf8');
        utf8 = textUtf8.split('\u0000').map(s => s.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\uFFFD]/g, '').trim()).filter(Boolean).filter(s => s.length >= minLen);
    } catch {}

    const a = filterLikelyStrings(utf8);
    const b = filterLikelyStrings(utf16);
    const hasRegHint = (list) => {
        for (const s of list) {
            if (!s) continue;
            if (s.startsWith('\\REGISTRY\\')) return true;
            if (/^HK(LM|CU|CR|U|CC)\\/i.test(s)) return true;
        }
        return false;
    };
    const ha = hasRegHint(a);
    const hb = hasRegHint(b);
    if (hb && !ha) return utf16;
    if (ha && !hb) return utf8;
    const score = (list) => {
        let sc = 0;
        for (const s of list) {
            if (!s) continue;
            if (s.startsWith('\\REGISTRY\\')) sc += 80;
            if (/^HK(LM|CU|CR|U|CC)\\/i.test(s)) sc += 70;
            const bs = (s.match(/\\/g) || []).length;
            sc += Math.min(60, bs * 6);
            sc += Math.min(30, Math.floor(s.length / 6));
        }
        return sc;
    };
    const sa = score(a);
    const sb = score(b);
    if (sb > sa) return utf16;
    if (sa > sb) return utf8;
    if (b.length > a.length) return utf16;
    if (a.length > b.length) return utf8;
    return b.length ? utf16 : utf8;
}

function readUtf16leZFromBytes(bytes, startOffset, maxChars = 2048) {
    const buf = Buffer.from(bytes);
    let off = (startOffset >>> 0);
    if (off >= buf.length) return { text: '', endOffset: off };
    let end = off;
    let chars = 0;
    while (end + 1 < buf.length && chars < maxChars) {
        if (buf[end] === 0 && buf[end + 1] === 0) {
            end += 2;
            break;
        }
        end += 2;
        chars++;
    }
    let text = '';
    try {
        text = buf.slice(off, Math.min(end, buf.length)).toString('utf16le');
    } catch {}
    text = (text || '').replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\uFFFD]/g, '').trim();
    return { text, endOffset: end };
}

function scanRegistryKeyPathFromBinary(bytes) {
    const buf = Buffer.from(bytes);
    const patterns = ['\\REGISTRY\\', 'HKLM\\', 'HKCU\\', 'HKCR\\', 'HKU\\', 'HKCC\\'];
    let bestIdx = -1;
    let bestPat = '';
    for (const p of patterns) {
        let idx = -1;
        try {
            idx = buf.indexOf(Buffer.from(p, 'utf16le'));
        } catch {}
        if (idx >= 0 && (bestIdx < 0 || idx < bestIdx)) {
            bestIdx = idx;
            bestPat = p;
        }
    }
    if (bestIdx < 0) return null;
    const { text, endOffset } = readUtf16leZFromBytes(buf, bestIdx, 4096);
    const normalized = (text || '').trim();
    if (!normalized) return null;
    const m1 = /\\REGISTRY\\[^\u0000]+/i.exec(normalized);
    if (m1 && m1[0]) return { keyPath: m1[0].trim(), endOffset };
    const m2 = /HK(LM|CU|CR|U|CC)\\[^\u0000]+/i.exec(normalized);
    if (m2 && m2[0]) return { keyPath: m2[0].trim(), endOffset };
    if (bestPat && normalized.toUpperCase().startsWith(bestPat.toUpperCase())) return { keyPath: normalized, endOffset };
    return { keyPath: normalized, endOffset };
}

function scanRegistryValueNameFromBinary(bytes, startOffset, keyPath) {
    const buf = Buffer.from(bytes);
    let off = (startOffset >>> 0);
    while (off + 1 < buf.length && buf[off] === 0 && buf[off + 1] === 0) off += 2;
    const { text } = readUtf16leZFromBytes(buf, off, 512);
    const s = (text || '').trim();
    if (!s) return null;
    if (s.includes('\\')) return null;
    if (keyPath && s === keyPath) return null;
    return s;
}

function pickBestRegistryKeyPath(strings, bytes) {
    const list = filterLikelyStrings(strings);
    const scored = list.map((s) => {
        const hasSlash = s.includes('\\');
        const isReg = s.startsWith('\\REGISTRY\\') ? 1 : 0;
        const isHk = /^HK(LM|CU|CR|U|CC)\\/i.test(s) ? 1 : 0;
        const slashes = (s.match(/\\/g) || []).length;
        const score = (isReg ? 120 : 0) + (isHk ? 100 : 0) + (hasSlash ? 10 : 0) + Math.min(60, slashes * 6) + Math.min(40, Math.floor(s.length / 6));
        return { s, score };
    });
    scored.sort((a, b) => b.score - a.score);
    if (scored.length) {
        const best = scored[0].s;
        const m = /\\REGISTRY\\[^\u0000]+/i.exec(best);
        if (m && m[0]) return m[0].trim();
        const m2 = /HK(LM|CU|CR|U|CC)\\[^\u0000]+/i.exec(best);
        if (m2 && m2[0]) return m2[0].trim();
        return best;
    }

    const buf = Buffer.from(bytes);
    let text = '';
    try { text = buf.toString('utf16le'); } catch {}
    if (text) {
        const m = /\\REGISTRY\\[^\u0000]+/i.exec(text);
        if (m && m[0]) return m[0].trim();
        const m2 = /HK(LM|CU|CR|U|CC)\\[^\u0000]+/i.exec(text);
        if (m2 && m2[0]) return m2[0].trim();
    }
    return null;
}

function pickBestRegistryValueName(strings, keyPath) {
    const list = filterLikelyStrings(strings);
    const cands = list.filter(s => s && s !== keyPath && !s.includes('\\'));
    return cands.length ? cands[0] : null;
}

function parseRegistryUserData(bytes, descriptor, cfg) {
    const strings = extractUtf16Strings(bytes, 3);
    const type = mapRegistryOp(descriptor.Opcode, descriptor.Id);
    let keyPath = pickBestRegistryKeyPath(strings, bytes);
    let valueName = pickBestRegistryValueName(strings, keyPath);
    let keyEndOffset = null;
    if (!keyPath) {
        const scanned = scanRegistryKeyPathFromBinary(bytes);
        if (scanned && scanned.keyPath) {
            keyPath = scanned.keyPath;
            keyEndOffset = scanned.endOffset;
        }
    }
    if (!valueName && keyEndOffset == null) {
        const scanned = scanRegistryKeyPathFromBinary(bytes);
        if (scanned && scanned.keyPath) {
            if (!keyPath) keyPath = scanned.keyPath;
            keyEndOffset = scanned.endOffset;
        }
    }
    if (!valueName && keyEndOffset != null) {
        valueName = scanRegistryValueNameFromBinary(bytes, keyEndOffset, keyPath);
    }
    const data = { type, keyPath: keyPath || null, valueName: valueName || null };
    if (cfg && cfg.emitRegistryRawHex) data.rawHex = Buffer.from(bytes).toString('hex');
    return data;
}

function isLikelyReadableText(s) {
    if (typeof s !== 'string' || !s) return false;
    if (s.includes('\uFFFD')) return false;
    let bad = 0;
    let nul = 0;
    for (let i = 0; i < s.length; i++) {
        const code = s.charCodeAt(i);
        if (code === 0) {
            nul++;
            continue;
        }
        if (code < 0x20) {
            if (code !== 0x09 && code !== 0x0A && code !== 0x0D) bad++;
            continue;
        }
        if (code >= 0xD800 && code <= 0xDFFF) bad++;
        if (code === 0xFFFF) bad++;
    }
    if (nul) return false;
    return (bad / Math.max(1, s.length)) <= 0.05;
}

function filterLikelyStrings(strings) {
    if (!Array.isArray(strings)) return [];
    return strings
        .filter(isLikelyReadableText)
        .map(s => s.trim())
        .filter(Boolean)
        .slice(0, 64);
}

function filetimeToIso(ts) {
    try {
        if (typeof ts === 'bigint') {
            const unixMs = (ts / 10000n) - 11644473600000n;
            return new Date(Number(unixMs)).toISOString();
        }
        const n = Number(ts);
        if (!Number.isFinite(n)) return new Date().toISOString();
        const unixMs = (n / 10000) - 11644473600000;
        return new Date(unixMs).toISOString();
    } catch {
        return new Date().toISOString();
    }
}

function readUInt32LESafe(bytes, offset) {
    const off = offset >>> 0;
    if (!bytes || off + 4 > bytes.length) return null;
    return Buffer.from(bytes.slice(off, off + 4)).readUInt32LE(0);
}

function readUInt16BESafe(bytes, offset) {
    const off = offset >>> 0;
    if (!bytes || off + 2 > bytes.length) return null;
    return Buffer.from(bytes.slice(off, off + 2)).readUInt16BE(0);
}

function ipv4ToString(a, b, c, d) {
    return `${a >>> 0}.${b >>> 0}.${c >>> 0}.${d >>> 0}`;
}

function isLoopbackIpv4(a) {
    return (a >>> 0) === 127;
}

function isPrivateIpv4(a, b) {
    const x = a >>> 0;
    const y = b >>> 0;
    if (x === 10) return true;
    if (x === 172 && y >= 16 && y <= 31) return true;
    if (x === 192 && y === 168) return true;
    if (x === 169 && y === 254) return true;
    return false;
}

function isBadIpv4(a, b, c, d) {
    const x = a >>> 0;
    const y = b >>> 0;
    const z = c >>> 0;
    const w = d >>> 0;
    if (x === 0) return true;
    if (x === 255) return true;
    if (x === 224) return true;
    if (x === 239) return true;
    if (x === 127 && y === 0 && z === 0 && w === 1) return false;
    return false;
}

function parseNetworkUserDataHeuristic(bytes, cfg) {
    const netCfg = (cfg && cfg.network && typeof cfg.network === 'object') ? cfg.network : (DEFAULT_ETW_CFG.network || {});
    if (!netCfg || netCfg.enabled === false) return null;

    const buf = Buffer.from(bytes);
    const limit = Math.max(0, buf.length - 12);
    let best = null;

    for (let off = 0; off <= limit; off++) {
        const a1 = buf[off];
        const b1 = buf[off + 1];
        const c1 = buf[off + 2];
        const d1 = buf[off + 3];
        const a2 = buf[off + 4];
        const b2 = buf[off + 5];
        const c2 = buf[off + 6];
        const d2 = buf[off + 7];

        if (isBadIpv4(a1, b1, c1, d1) || isBadIpv4(a2, b2, c2, d2)) continue;

        const sport = readUInt16BESafe(buf, off + 8);
        const dport = readUInt16BESafe(buf, off + 10);
        if (!sport || !dport) continue;
        if (sport < 1 || sport > 65535) continue;
        if (dport < 1 || dport > 65535) continue;

        const localIsLoop = isLoopbackIpv4(a1);
        const remoteIsLoop = isLoopbackIpv4(a2);
        if (netCfg.skipLoopback && (localIsLoop || remoteIsLoop)) continue;

        const localIsPrivate = isPrivateIpv4(a1, b1);
        const remoteIsPrivate = isPrivateIpv4(a2, b2);
        if (netCfg.filterPrivateIps && remoteIsPrivate) continue;

        let score = 0;
        if (localIsPrivate && !remoteIsPrivate) score += 20;
        if (!localIsPrivate && !remoteIsPrivate) score += 10;
        if (dport === 80 || dport === 443 || dport === 53) score += 6;
        score += Math.min(20, Math.floor(dport / 1000));

        const candidate = {
            protocol: 'TCP',
            remoteIp: ipv4ToString(a2, b2, c2, d2),
            remotePort: dport,
            direction: 'outbound',
            target: `TCP ${ipv4ToString(a2, b2, c2, d2)}:${dport}`
        };

        if (!best || score > best.score) best = { score, data: candidate };
    }

    return best ? best.data : null;
}

function mapNetworkOp(descriptor) {
    const opcode = descriptor && Number.isFinite(descriptor.Opcode) ? descriptor.Opcode : null;
    const id = descriptor && Number.isFinite(descriptor.Id) ? descriptor.Id : null;
    const candidates = new Set([10, 11, 12, 13, 14, 15, 16]);
    if (opcode != null && candidates.has(opcode)) return 'Connect';
    if (id != null && candidates.has(id)) return 'Connect';
    return null;
}

function pickBestPathCandidate(strings) {
    const list = filterLikelyStrings(strings);
    const scored = list.map((s) => {
        const hasSlash = s.includes('\\');
        const hasDrive = /^[a-zA-Z]:\\/.test(s);
        const hasDevice = s.startsWith('\\Device\\') || s.startsWith('\\\\?\\');
        const looksLikeExe = s.toLowerCase().endsWith('.exe');
        const score = (hasDrive ? 50 : 0) + (hasDevice ? 30 : 0) + (hasSlash ? 10 : 0) + (looksLikeExe ? 10 : 0) + Math.min(20, Math.floor(s.length / 10));
        return { s, score };
    });
    scored.sort((a, b) => b.score - a.score);
    const isPathLike = (s) => {
        if (typeof s !== 'string' || !s) return false;
        if (s.includes('\\')) return true;
        if (/\.exe$/i.test(s)) return true;
        return false;
    };
    for (const it of scored) {
        if (isPathLike(it.s)) return it.s;
    }
    return null;
}

function tryDecodeEventRecord(ptr) {
    try {
        return koffi.decode(ptr, EVENT_RECORD);
    } catch {
        return null;
    }
}

function normalizeEventRecordPtr(recordPtr) {
    if (!recordPtr) return null;
    if (recordPtr && recordPtr.EventHeader) return recordPtr;
    return tryDecodeEventRecord(recordPtr);
}

function shouldSkipByFilters(filters, provider, type) {
    try {
        const p = typeof provider === 'string' ? provider : '';
        const t = typeof type === 'string' ? type : '';
        if (!p || !t) return false;
        const f = (filters && typeof filters === 'object') ? filters : {};
        const rule = f[p] && typeof f[p] === 'object' ? f[p] : {};
        const skipOps = Array.isArray(rule.skipOps) ? rule.skipOps.map(String) : [];
        return skipOps.includes(t);
    } catch { return false; }
}

function shouldSkipByCfg(provider, type) {
    try {
        const filters = (etwCfg && etwCfg.filters && typeof etwCfg.filters === 'object') ? etwCfg.filters : {};
        return shouldSkipByFilters(filters, provider, type);
    } catch { return false; }
}

function mapRegistryOp(opcode, id) {
    const m = {
        1: 'CreateKey',
        2: 'OpenKey',
        3: 'DeleteKey',
        4: 'QueryValue',
        5: 'SetValue',
        6: 'DeleteValue',
        7: 'QueryKey',
        8: 'EnumerateKey',
        9: 'EnumerateValue',
        10: 'QueryMultipleValue',
        11: 'SetInformationKey',
        12: 'FlushKey',
        13: 'CloseKey',
        14: 'SetSecurityKey',
        15: 'QuerySecurityKey',
        16: 'RenameKey'
    };
    if (m[id]) return m[id];
    if (m[opcode]) return m[opcode];
    if (Number.isFinite(id) && id) return 'EventId_' + id;
    return 'Opcode_' + opcode;
}

function createEventCallback() {
    if (eventCallback) return eventCallback;
    eventCallback = koffi.register((recordPtr) => {
        try {
            if (isStopping) return;
            try {
                const record = normalizeEventRecordPtr(recordPtr);
                if (!record) return;
                const header = record.EventHeader;
                if (!header) return;
                const providerId = header.ProviderId;
                const descriptor = header.EventDescriptor;
                if (!providerId || !descriptor) return;

                const isProcess = sameGuid(providerId, GUID_KernelProcess);
                const isFile = sameGuid(providerId, GUID_KernelFile);
                const isRegistry = sameGuid(providerId, GUID_KernelRegistry);
                const isNetwork = !!(etwCfg && etwCfg.network && etwCfg.network.enabled !== false) && sameGuid(providerId, GUID_KernelNetwork);

                if (!isProcess && !isFile && !isRegistry && !isNetwork) return;

                const eventData = {
                    timestamp: filetimeToIso(header.TimeStamp),
                    pid: header.ProcessId,
                    tid: header.ThreadId,
                    provider: isProcess ? 'Process' : (isFile ? 'File' : (isRegistry ? 'Registry' : 'Network')),
                    opcode: descriptor.Opcode,
                    id: descriptor.Id,
                    data: {}
                };

                const userDataPtr = record.UserData;
                const userDataLen = (record.UserDataLength >>> 0);
                const maxBytes = (etwCfg && Number.isFinite(etwCfg.userDataMaxBytes)) ? etwCfg.userDataMaxBytes : DEFAULT_ETW_CFG.userDataMaxBytes;
                const cappedLen = Math.min(userDataLen, maxBytes);

                if (cappedLen > 0 && userDataPtr) {
                    const bytes = koffi.decode(userDataPtr, koffi.array('uint8_t', cappedLen));

                    if (isProcess) {
                        if (descriptor.Opcode === 1 || descriptor.Opcode === 2) {
                            const pid = readUInt32LESafe(bytes, 0);
                            const ppid = readUInt32LESafe(bytes, 4);
                            const strings = extractUtf16Strings(bytes, 3);
                            const imageName = pickBestPathCandidate(strings);
                            eventData.data = {
                                processId: pid,
                                parentProcessId: ppid,
                                imageName,
                                type: descriptor.Opcode === 1 ? 'Start' : 'Stop'
                            };
                            postMessage({ type: 'log', event: eventData });
                        }
                    } else if (isFile) {
                        if (descriptor.Opcode === 32 || descriptor.Opcode === 35 || descriptor.Opcode === 36) {
                            const strings = extractUtf16Strings(bytes, 3);
                            const fileName = pickBestPathCandidate(strings);
                            if (fileName) {
                                eventData.data = {
                                    fileName,
                                    type: descriptor.Opcode === 32 ? 'Create' : (descriptor.Opcode === 35 ? 'Delete' : 'Rename')
                                };
                                postMessage({ type: 'log', event: eventData });
                            }
                        }
                    } else if (isRegistry) {
                        const regType = mapRegistryOp(descriptor.Opcode, descriptor.Id);
                        if (shouldSkipByCfg('Registry', regType)) {
                            return;
                        }
                        eventData.data = parseRegistryUserData(bytes, descriptor, etwCfg);
                        postMessage({ type: 'log', event: eventData });
                    } else if (isNetwork) {
                        const netType = mapNetworkOp(descriptor);
                        if (!netType) return;
                        if (shouldSkipByCfg('Network', netType)) return;
                        const parsed = parseNetworkUserDataHeuristic(bytes, etwCfg);
                        if (!parsed) return;
                        eventData.data = Object.assign({ type: netType }, parsed);
                        postMessage({ type: 'log', event: eventData });
                    }
                }
            } catch (e) {
                const now = Date.now();
                if (now - lastCallbackErrorAt > 1000) {
                    lastCallbackErrorAt = now;
                    postError('ETW_CALLBACK_ERROR', (e && e.message) ? e.message : String(e || 'callback_error'), { stack: e && e.stack ? String(e.stack) : '' });
                }
            }
        } catch (fatal) {
        }
    }, EventRecordCallbackType);
    return eventCallback;
}

function unregisterCallback() {
    if (!eventCallback) return;
    try { koffi.unregister(eventCallback); } catch {}
    eventCallback = null;
}

function getElevationState() {
    const TOKEN_QUERY = 0x0008;
    const TokenElevation = 20;
    const DWORD = 'uint32_t';
    const TOKEN_ELEVATION = koffi.struct('TOKEN_ELEVATION', { TokenIsElevated: DWORD });

    let token = null;
    try {
        const proc = GetCurrentProcess();
        const tokenOut = [null];
        const ok = OpenProcessToken(proc, TOKEN_QUERY, tokenOut);
        if (!ok) {
            return { ok: false, isElevated: false, error: 'OpenProcessToken: ' + GetLastError() };
        }
        token = tokenOut[0];
        const elevation = Buffer.alloc(koffi.sizeof(TOKEN_ELEVATION));
        const retLen = [0];
        const ok2 = GetTokenInformation(token, TokenElevation, elevation, elevation.length, retLen);
        if (!ok2) {
            return { ok: false, isElevated: false, error: 'GetTokenInformation: ' + GetLastError() };
        }
        const isElevated = elevation.readUInt32LE(0) !== 0;
        return { ok: true, isElevated };
    } catch (e) {
        return { ok: false, isElevated: false, error: (e && e.message) ? e.message : String(e || 'TOKEN_ERROR') };
    } finally {
        if (token) {
            try { CloseHandle(token); } catch {}
        }
    }
}

function checkStatus(api, status, extra) {
    if (status === ERROR_SUCCESS) return true;
    const details = { api, status };
    if (extra && typeof extra === 'object') Object.assign(details, extra);
    const message = api + ' failed: ' + status + (status === ERROR_ACCESS_DENIED ? '，可能需要以管理员权限运行' : '');
    postError('ETW_API_FAILED', message, details);
    return false;
}

function stopSessionInternal() {
    const sessionName = (etwCfg && etwCfg.sessionName) ? etwCfg.sessionName : DEFAULT_ETW_CFG.sessionName;
    let status = ERROR_SUCCESS;
    try {
        status = ControlTraceW(sessionHandle || 0n, sessionName, createPropertyBuffer(), EVENT_TRACE_CONTROL_STOP);
    } catch (e) {
        postError('ETW_CONTROLTRACE_EXCEPTION', (e && e.message) ? e.message : String(e || 'ControlTrace'), { stack: e && e.stack ? String(e.stack) : '' });
        return false;
    }
    return checkStatus('ControlTraceW(stop)', status, { sessionName });
}

async function waitForProcessTraceDone(timeoutMs) {
    if (!processTraceDone) return true;
    const deadline = Date.now() + Math.max(0, timeoutMs || 0);
    while (Date.now() < deadline) {
        const done = await Promise.race([processTraceDone.then(() => true).catch(() => true), new Promise((r) => setTimeout(() => r(false), 50))]);
        if (done) return true;
    }
    return false;
}

function cleanupResources() {
    if (traceHandle && traceHandle !== 0n) {
        try { CloseTrace(traceHandle); } catch {}
    }
    traceHandle = 0n;
    sessionHandle = 0n;
    logfile = null;
    currentHandleBuffer = null;
}

async function stopSession(timeoutMs) {
    if (stopPromise) return stopPromise;
    stopPromise = (async () => {
        isStopping = true;
        try { stopSessionInternal(); } catch {}
        const ok = await waitForProcessTraceDone(timeoutMs);
        cleanupResources();
        postMessage({ type: 'status', message: ok ? 'Monitoring stopped' : 'Monitoring stopped (timeout)' });
        return ok;
    })();
    return stopPromise;
}

async function startWithRetry(payloadCfg) {
    lastPayloadCfg = payloadCfg || lastPayloadCfg;
    etwCfg = resolveEtwCfg(payloadCfg);
    if (!etwCfg.enabled) {
        postMessage({ type: 'status', message: 'ETW disabled by config' });
        return;
    }

    const elev = getElevationState();
    if (elev.ok && !elev.isElevated) {
        postError('ETW_PERMISSION', '权限不足：需要管理员权限才能启动 ETW 监听', { suggestion: '请以管理员身份运行程序或启用安装包的提权选项', isElevated: false });
        return;
    }

    let attempt = 0;
    const retries = etwCfg.startRetries;
    const delayMs = etwCfg.retryDelayMs;
    while (true) {
        attempt++;
        try {
            await startSessionOnce();
            return;
        } catch (e) {
            const msg = (e && e.message) ? e.message : String(e || 'START_FAILED');
            const canRetry = attempt <= retries;
            postError('ETW_START_FAILED', msg, { attempt, retries, stack: e && e.stack ? String(e.stack) : '' });
            if (!canRetry) return;
            sleepSync(delayMs);
        }
    }
}

function guidToBuffer(g) {
    const b = Buffer.alloc(16);
    b.writeUInt32LE(g.Data1, 0);
    b.writeUInt16LE(g.Data2, 4);
    b.writeUInt16LE(g.Data3, 6);
    Buffer.from(g.Data4).copy(b, 8);
    return b;
}

async function startSessionOnce() {
    if (isSessionRunning) return;
    isStopping = false;
    stopPromise = null;

    const sessionName = (etwCfg && etwCfg.sessionName) ? etwCfg.sessionName : DEFAULT_ETW_CFG.sessionName;
    try {
        try { ControlTraceW(0n, sessionName, createPropertyBuffer(), EVENT_TRACE_CONTROL_STOP); } catch {}

        const handlePtr = [0n];
        let status = ERROR_SUCCESS;
        status = StartTraceW(handlePtr, sessionName, createPropertyBuffer());

        if (status === ERROR_ALREADY_EXISTS) {
            try { ControlTraceW(0n, sessionName, createPropertyBuffer(), EVENT_TRACE_CONTROL_STOP); } catch {}
            sleepSync((etwCfg && etwCfg.retryDelayMs) ? etwCfg.retryDelayMs : DEFAULT_ETW_CFG.retryDelayMs);
            status = StartTraceW(handlePtr, sessionName, createPropertyBuffer());
        }

        if (!checkStatus('StartTraceW', status, { sessionName })) {
            throw new Error('StartTraceW failed: ' + status);
        }
        sessionHandle = handlePtr[0];

        const s1 = EnableTraceEx2(sessionHandle, guidToBuffer(GUID_KernelProcess), EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 0n, 0n, 0, null);
        if (!checkStatus('EnableTraceEx2(Process)', s1, { sessionName })) throw new Error('EnableTraceEx2(Process) failed: ' + s1);

        const s2 = EnableTraceEx2(sessionHandle, guidToBuffer(GUID_KernelFile), EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 0n, 0n, 0, null);
        if (!checkStatus('EnableTraceEx2(File)', s2, { sessionName })) throw new Error('EnableTraceEx2(File) failed: ' + s2);

        const s3 = EnableTraceEx2(sessionHandle, guidToBuffer(GUID_KernelRegistry), EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 0n, 0n, 0, null);
        if (!checkStatus('EnableTraceEx2(Registry)', s3, { sessionName })) throw new Error('EnableTraceEx2(Registry) failed: ' + s3);

        if (etwCfg && etwCfg.network && etwCfg.network.enabled !== false) {
            const s4 = EnableTraceEx2(sessionHandle, guidToBuffer(GUID_KernelNetwork), EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 0n, 0n, 0, null);
            if (!checkStatus('EnableTraceEx2(Network)', s4, { sessionName })) throw new Error('EnableTraceEx2(Network) failed: ' + s4);
        }

        logfile = {
            LogFileName: null,
            LoggerName: sessionName,
            CurrentTime: 0n,
            BuffersRead: 0,
            ProcessTraceMode: PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD,
            CurrentEvent: {},
            LogfileHeader: {},
            BufferCallback: null,
            BufferSize: 0,
            Filled: 0,
            EventsLost: 0,
            EventRecordCallback: createEventCallback(),
            IsKernelTrace: 0,
            Context: null
        };

        traceHandle = OpenTraceW(logfile);
        if (traceHandle === 0xFFFFFFFFFFFFFFFFn || traceHandle === -1n) {
            const le = GetLastError();
            checkStatus('OpenTraceW', le, { lastError: le, sessionName });
            throw new Error('OpenTraceW failed: ' + le);
        }

        currentHandleBuffer = createTraceHandleArrayBuffer(traceHandle);
        isSessionRunning = true;
        processTraceDone = new Promise((resolve) => { resolveProcessTraceDone = resolve; });

        postMessage({ type: 'status', message: 'Monitoring started' });

        ProcessTrace.async(currentHandleBuffer, 1, null, null, (err, st) => {
            currentHandleBuffer = null;
            isSessionRunning = false;

            if (err) {
                postError('ETW_PROCESSTRACE_EXCEPTION', (err && err.message) ? err.message : String(err || 'ProcessTrace'), { stack: err && err.stack ? String(err.stack) : '' });
            } else if (st !== ERROR_SUCCESS && !isStopping) {
                postError('ETW_PROCESSTRACE_FAILED', 'ProcessTrace failed: ' + st + (st === ERROR_ACCESS_DENIED ? '，可能需要以管理员权限运行' : ''), { status: st });
            }

            try { if (typeof resolveProcessTraceDone === 'function') resolveProcessTraceDone(); } catch {}
            resolveProcessTraceDone = null;
        });
    } catch (e) {
        try { isStopping = true; } catch {}
        try { stopSessionInternal(); } catch {}
        try { cleanupResources(); } catch {}
        throw e;
    }
}

if (parentPort) {
    parentPort.on('message', (msg) => {
        try {
            if (msg === 'start' || (msg && typeof msg === 'object' && msg.type === 'start')) {
                const cfg = (msg && typeof msg === 'object' && msg.type === 'start') ? msg.config : null;
                startWithRetry(cfg);
                return;
            }
            if (msg === 'stop' || (msg && typeof msg === 'object' && msg.type === 'stop')) {
                const timeoutMs = (etwCfg && etwCfg.stopTimeoutMs) ? etwCfg.stopTimeoutMs : DEFAULT_ETW_CFG.stopTimeoutMs;
                stopSession(timeoutMs).finally(() => {
                    setImmediate(() => process.exit(0));
                });
                return;
            }
            if (msg && typeof msg === 'object' && msg.type === 'pause') {
                const timeoutMs = (etwCfg && etwCfg.stopTimeoutMs) ? etwCfg.stopTimeoutMs : DEFAULT_ETW_CFG.stopTimeoutMs;
                const reqId = msg.requestId || null;
                Promise.resolve()
                    .then(() => stopSession(timeoutMs))
                    .then((ok) => postMessage({ type: 'paused', requestId: reqId, ok: !!ok }))
                    .catch(() => postMessage({ type: 'paused', requestId: reqId, ok: false }));
                return;
            }
            if (msg && typeof msg === 'object' && msg.type === 'resume') {
                const reqId = msg.requestId || null;
                Promise.resolve()
                    .then(() => startWithRetry(lastPayloadCfg))
                    .then(() => postMessage({ type: 'resumed', requestId: reqId, ok: !!isSessionRunning }))
                    .catch(() => postMessage({ type: 'resumed', requestId: reqId, ok: false }));
                return;
            }
            if (msg && typeof msg === 'object' && msg.type === 'config') {
                lastPayloadCfg = msg.config || lastPayloadCfg;
                etwCfg = resolveEtwCfg(msg.config);
                return;
            }
        } catch (e) {
            postError('ETW_MESSAGE_HANDLER_ERROR', (e && e.message) ? e.message : String(e || 'message_error'), { stack: e && e.stack ? String(e.stack) : '' });
        }
    });
}

module.exports = {
    createPropertyBuffer,
    createTraceHandleArrayBuffer,
    EVENT_TRACE_PROPERTIES,
    WNODE_HEADER,
    EVENT_TRACE_REAL_TIME_MODE,
    __test: {
        filetimeToIso,
        extractUtf16Strings,
        parseRegistryUserData,
        parseNetworkUserDataHeuristic,
        pickBestPathCandidate,
        resolveEtwCfg,
        mapRegistryOp,
        mapNetworkOp,
        readUInt32LESafe,
        tryDecodeEventRecord,
        normalizeEventRecordPtr,
        shouldSkipByFilters
    }
};
