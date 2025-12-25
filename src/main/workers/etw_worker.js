const { parentPort } = require('worker_threads');
const koffi = require('koffi');

const libAdvapi32 = koffi.load('advapi32.dll');
const libKernel32 = koffi.load('kernel32.dll');

const ERROR_SUCCESS = 0;
const ERROR_ALREADY_EXISTS = 183;
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

const ULONG = 'uint32_t';
const ULONG64 = 'uint64_t';
const USHORT = 'uint16_t';
const UCHAR = 'uint8_t';
const LONGLONG = 'int64_t';
const HANDLE = koffi.pointer('HANDLE', koffi.opaque());
const LPWSTR = koffi.pointer('LPWSTR', 'uint16_t');
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

let sessionHandle = 0n;
let traceHandle = 0n;
const SESSION_NAME = 'AnXinSecuritySession';
let currentHandleBuffer = null;
let logfile = null;

function postMessage(msg) {
    if (!parentPort) return;
    parentPort.postMessage(msg);
}

function createPropertyBuffer() {
    const propsSize = koffi.sizeof(EVENT_TRACE_PROPERTIES);
    const nameSize = (SESSION_NAME.length + 1) * 2;
    const totalSize = propsSize + nameSize + 1024;
    
    const buffer = Buffer.alloc(totalSize);
    
    buffer.writeUInt32LE(totalSize, koffi.offsetof(WNODE_HEADER, 'BufferSize'));
    buffer.writeUInt32LE(1, koffi.offsetof(WNODE_HEADER, 'ClientContext'));
    buffer.writeUInt32LE(WNODE_FLAG_TRACED_GUID, koffi.offsetof(WNODE_HEADER, 'Flags'));

    buffer.writeUInt32LE(EVENT_TRACE_REAL_TIME_MODE, koffi.offsetof(EVENT_TRACE_PROPERTIES, 'LogFileMode'));
    buffer.writeUInt32LE(0, koffi.offsetof(EVENT_TRACE_PROPERTIES, 'LogFileNameOffset'));
    buffer.writeUInt32LE(propsSize, koffi.offsetof(EVENT_TRACE_PROPERTIES, 'LoggerNameOffset'));
    
    buffer.write(SESSION_NAME, propsSize, 'utf16le');
    
    return buffer;
}

function createTraceHandleArrayBuffer(handle) {
    const traceHandles = Buffer.alloc(8);
    traceHandles.writeBigUInt64LE(BigInt(handle), 0);
    return traceHandles;
}

let isSessionRunning = false;
let isStopping = false;

const eventCallback = koffi.register((recordPtr) => {
    if (isStopping) return;

    try {
        if (!recordPtr) return;
        const record = recordPtr;
        const header = record.EventHeader;
        const providerId = header.ProviderId;
        const descriptor = header.EventDescriptor;
        
        const isProcess = (providerId.Data1 === GUID_KernelProcess.Data1 && providerId.Data4[7] === GUID_KernelProcess.Data4[7]);
        const isFile = (providerId.Data1 === GUID_KernelFile.Data1 && providerId.Data4[7] === GUID_KernelFile.Data4[7]);
        
        if (!isProcess && !isFile) return;
        
        const eventData = {
            timestamp: new Date(Number(header.TimeStamp) / 10000 - 11644473600000).toISOString(),
            pid: header.ProcessId,
            tid: header.ThreadId,
            provider: isProcess ? 'Process' : 'File',
            opcode: descriptor.Opcode,
            id: descriptor.Id,
            data: {}
        };

        const userDataPtr = record.UserData;
        const userDataLen = record.UserDataLength;
        
        if (userDataLen > 0 && userDataPtr) {
            const bytes = koffi.decode(userDataPtr, koffi.array('uint8_t', userDataLen));
            if (isProcess) {
                if (descriptor.Opcode === 1 || descriptor.Opcode === 2) {
                    const pid = Buffer.from(bytes.slice(0, 4)).readUInt32LE(0);
                    const ppid = Buffer.from(bytes.slice(4, 8)).readUInt32LE(0);
                    
                    let offset = 16;
                    if (offset + 1 < userDataLen) {
                        const subAuthCount = bytes[offset + 1] >>> 0;
                        const sidSize = 8 + (subAuthCount * 4);
                        offset += sidSize;
                        
                        let strEnd = offset;
                        while (strEnd + 1 < userDataLen && (bytes[strEnd] !== 0 || bytes[strEnd + 1] !== 0)) {
                            strEnd += 2;
                        }
                        const imageFileNameBuf = Buffer.from(bytes.slice(offset, strEnd));
                        const imageFileName = imageFileNameBuf.toString('utf16le');
                        
                        eventData.data = {
                            processId: pid,
                            parentProcessId: ppid,
                            imageName: imageFileName,
                            type: descriptor.Opcode === 1 ? 'Start' : 'Stop'
                        };
                        
                        postMessage({ type: 'log', event: eventData });
                    }
                }
            } else if (isFile) {
                const ptrSize = 8; 
                
                if (descriptor.Opcode === 32 || descriptor.Opcode === 35 || descriptor.Opcode === 36) {
                    let startOffset = 0;
                    if (descriptor.Opcode === 32) startOffset = 28;
                    else if (descriptor.Opcode === 35) startOffset = 16;
                    
                    if (startOffset < userDataLen) {
                        let strEnd = startOffset;
                        while (strEnd + 1 < userDataLen && (bytes[strEnd] !== 0 || bytes[strEnd + 1] !== 0)) {
                            strEnd += 2;
                        }
                        const fileNameBuf = Buffer.from(bytes.slice(startOffset, strEnd));
                        const fileName = fileNameBuf.toString('utf16le');
                        
                        if (fileName && fileName.length > 0) {
                             eventData.data = {
                                fileName: fileName,
                                type: descriptor.Opcode === 32 ? 'Create' : (descriptor.Opcode === 35 ? 'Delete' : 'Rename')
                            };
                            postMessage({ type: 'log', event: eventData });
                        }
                    }
                }
            }
        }
    } catch (e) {
    }
}, EventRecordCallbackType);

function startSession() {
    try { ControlTraceW(0n, SESSION_NAME, createPropertyBuffer(), EVENT_TRACE_CONTROL_STOP); } catch {}
    
    const handlePtr = [0n];
    let status = StartTraceW(handlePtr, SESSION_NAME, createPropertyBuffer());
    if (status !== ERROR_SUCCESS && status !== ERROR_ALREADY_EXISTS) {
        postMessage({ type: 'error', message: 'StartTrace failed: ' + status });
        return;
    }
    sessionHandle = handlePtr[0];
    
    const createGuidBuf = (g) => {
        const b = Buffer.alloc(16);
        b.writeUInt32LE(g.Data1, 0);
        b.writeUInt16LE(g.Data2, 4);
        b.writeUInt16LE(g.Data3, 6);
        Buffer.from(g.Data4).copy(b, 8);
        return b;
    };

    EnableTraceEx2(sessionHandle, createGuidBuf(GUID_KernelProcess), EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 0n, 0n, 0, null);
    
    EnableTraceEx2(sessionHandle, createGuidBuf(GUID_KernelFile), EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 0n, 0n, 0, null);
    
    logfile = {
        LogFileName: null,
        LoggerName: SESSION_NAME,
        CurrentTime: 0n,
        BuffersRead: 0,
        ProcessTraceMode: PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD,
        CurrentEvent: {},
        LogfileHeader: {},
        BufferCallback: null,
        BufferSize: 0,
        Filled: 0,
        EventsLost: 0,
        EventRecordCallback: eventCallback,
        IsKernelTrace: 0,
        Context: null
    };
    
    traceHandle = OpenTraceW(logfile);
    if (traceHandle === 0xFFFFFFFFFFFFFFFFn || traceHandle === -1n) {
         postMessage({ type: 'error', message: 'OpenTrace failed: ' + GetLastError() });
         return;
    }
    
    postMessage({ type: 'status', message: 'Monitoring started' });
    
    currentHandleBuffer = createTraceHandleArrayBuffer(traceHandle);
    
    isSessionRunning = true;
    
    ProcessTrace.async(currentHandleBuffer, 1, null, null, (err, status) => {
        currentHandleBuffer = null;
        isSessionRunning = false;
        
        if (err) {
             postMessage({ type: 'error', message: 'ProcessTrace exception: ' + err.message });
        } else if (status !== ERROR_SUCCESS) {
            if (!isStopping) {
                const extra = status === 5 ? '，可能需要以管理员权限运行' : '';
                postMessage({ type: 'error', message: 'ProcessTrace failed: ' + status + extra });
            }
        }
        
        if (isStopping) {
            setImmediate(() => {
                process.exit(0);
            });
        }
    });
}

if (parentPort) {
    parentPort.on('message', (msg) => {
        if (msg === 'start') {
            startSession();
        } else if (msg === 'stop') {
            isStopping = true;
            
            if (sessionHandle) {
                try { ControlTraceW(sessionHandle, null, createPropertyBuffer(), EVENT_TRACE_CONTROL_STOP); } catch {}
            }

            if (!isSessionRunning) {
                setImmediate(() => {
                    process.exit(0);
                });
            } 
        }
    });
}

module.exports = {
    createPropertyBuffer,
    createTraceHandleArrayBuffer,
    EVENT_TRACE_PROPERTIES,
    WNODE_HEADER,
    SESSION_NAME,
    EVENT_TRACE_REAL_TIME_MODE
};
