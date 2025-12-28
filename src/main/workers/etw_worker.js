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

const DEFAULT_ETW_CFG = {
    enabled: true,
    sessionName: 'AnXinSecuritySession',
    userDataMaxBytes: 65536,
    stopTimeoutMs: 2500,
    startRetries: 2,
    retryDelayMs: 150,
    emitRegistryRawHex: false
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
    const merged = { ...DEFAULT_ETW_CFG, ...etw, ...(payloadCfg && typeof payloadCfg === 'object' ? payloadCfg : {}) };
    merged.enabled = merged.enabled !== false;
    merged.sessionName = typeof merged.sessionName === 'string' && merged.sessionName.trim() ? merged.sessionName.trim() : DEFAULT_ETW_CFG.sessionName;
    merged.userDataMaxBytes = Number.isFinite(merged.userDataMaxBytes) ? Math.max(1024, Math.min(1024 * 1024, merged.userDataMaxBytes)) : DEFAULT_ETW_CFG.userDataMaxBytes;
    merged.stopTimeoutMs = Number.isFinite(merged.stopTimeoutMs) ? Math.max(250, Math.min(30000, merged.stopTimeoutMs)) : DEFAULT_ETW_CFG.stopTimeoutMs;
    merged.startRetries = Number.isFinite(merged.startRetries) ? Math.max(0, Math.min(20, merged.startRetries)) : DEFAULT_ETW_CFG.startRetries;
    merged.retryDelayMs = Number.isFinite(merged.retryDelayMs) ? Math.max(0, Math.min(5000, merged.retryDelayMs)) : DEFAULT_ETW_CFG.retryDelayMs;
    merged.emitRegistryRawHex = !!merged.emitRegistryRawHex;
    return merged;
}

function postMessage(msg) {
    if (!parentPort) return;
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
    try {
        const textUtf8 = Buffer.from(bytes).toString('utf8');
        const partsUtf8 = textUtf8.split('\u0000').map(s => s.trim()).filter(Boolean);
        const filteredUtf8 = partsUtf8.filter(s => s.length >= minLen);
        if (filteredUtf8.length) return filteredUtf8;
    } catch {}
    try {
        const textUtf16 = Buffer.from(bytes).toString('utf16le');
        const partsUtf16 = textUtf16.split('\u0000').map(s => s.trim()).filter(Boolean);
        return partsUtf16.filter(s => s.length >= minLen);
    } catch {
        return [];
    }
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
    return scored.length ? scored[0].s : null;
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

            if (!isProcess && !isFile && !isRegistry) return;

            const eventData = {
                timestamp: filetimeToIso(header.TimeStamp),
                pid: header.ProcessId,
                tid: header.ThreadId,
                provider: isProcess ? 'Process' : (isFile ? 'File' : 'Registry'),
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
                    const strings = filterLikelyStrings(extractUtf16Strings(bytes, 3));
                    const keyCandidates = strings.filter(s => s.includes('\\'));
                    const keyPath = keyCandidates.sort((a, b) => b.length - a.length)[0] || null;
                    let valueName = null;
                    if (strings.length > 0) {
                        const others = strings.filter(s => s !== keyPath && !s.includes('\\'));
                        valueName = others[0] || null;
                    }
                    const data = {
                        type: mapRegistryOp(descriptor.Opcode, descriptor.Id),
                        keyPath,
                        valueName
                    };
                    if (etwCfg && etwCfg.emitRegistryRawHex) data.rawHex = Buffer.from(bytes).toString('hex');
                    eventData.data = data;
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
    unregisterCallback();
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
            if (msg && typeof msg === 'object' && msg.type === 'config') {
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
        pickBestPathCandidate,
        resolveEtwCfg,
        mapRegistryOp,
        readUInt32LESafe,
        tryDecodeEventRecord,
        normalizeEventRecordPtr
    }
};
