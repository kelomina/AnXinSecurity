const { parentPort } = require('worker_threads');
const koffi = require('koffi');

// Load libraries
const libAdvapi32 = koffi.load('advapi32.dll');
const libKernel32 = koffi.load('kernel32.dll');

// Constants
const ERROR_SUCCESS = 0;
const ERROR_ALREADY_EXISTS = 183;
const PROCESS_TRACE_MODE_REAL_TIME = 0x00000100;
const PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000;
const EVENT_TRACE_REAL_TIME_MODE = 0x00000100;
const EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1;
const TRACE_LEVEL_INFORMATION = 4;
const EVENT_TRACE_CONTROL_STOP = 1;
const WNODE_FLAG_TRACED_GUID = 0x00020000;

// GUIDs
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

// Types
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
    TimeStamp: LONGLONG, // LARGE_INTEGER
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
    KernelTime: ULONG, // partial
    UserTime: ULONG,   // partial
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

// We only need a pointer to this
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
    LogfileHeader: koffi.struct({ // TRACE_LOGFILE_HEADER
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
        TimeZone: koffi.struct({ // TIME_ZONE_INFORMATION
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
            DaylightDate: koffi.struct({ // SYSTEMTIME again
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

// Functions
const StartTraceW = libAdvapi32.func('__stdcall', 'StartTraceW', ULONG, [koffi.out('uint64_t *'), 'string16', 'uint8_t *']);
const ControlTraceW = libAdvapi32.func('__stdcall', 'ControlTraceW', ULONG, ['uint64_t', 'string16', 'uint8_t *', ULONG]);
const EnableTraceEx2 = libAdvapi32.func('__stdcall', 'EnableTraceEx2', ULONG, ['uint64_t', koffi.pointer(GUID), ULONG, UCHAR, ULONG64, ULONG64, ULONG, PVOID]);
const OpenTraceW = libAdvapi32.func('__stdcall', 'OpenTraceW', 'uint64_t', [koffi.inout(koffi.pointer(EVENT_TRACE_LOGFILEW))]);
const ProcessTrace = libAdvapi32.func('__stdcall', 'ProcessTrace', ULONG, ['uint64_t *', ULONG, PVOID, PVOID]);
const CloseTrace = libAdvapi32.func('__stdcall', 'CloseTrace', ULONG, ['uint64_t']);
const GetLastError = libKernel32.func('__stdcall', 'GetLastError', ULONG, []);

// State
let sessionHandle = 0n; // TRACEHANDLE
let traceHandle = 0n; // TRACEHANDLE
const SESSION_NAME = 'AnXinSecuritySession';
let currentHandleBuffer = null; // Keep reference to prevent GC during async call
let logfile = null; // Keep reference to prevent GC

function postMessage(msg) {
    if (!parentPort) return;
    parentPort.postMessage(msg);
}

function createPropertyBuffer() {
    // EVENT_TRACE_PROPERTIES + LoggerName + LogFileName
    const propsSize = koffi.sizeof(EVENT_TRACE_PROPERTIES);
    const nameSize = (SESSION_NAME.length + 1) * 2;
    const totalSize = propsSize + nameSize + 1024; // Extra space
    
    const buffer = Buffer.alloc(totalSize);
    
    buffer.writeUInt32LE(totalSize, koffi.offsetof(WNODE_HEADER, 'BufferSize'));
    buffer.writeUInt32LE(1, koffi.offsetof(WNODE_HEADER, 'ClientContext'));
    buffer.writeUInt32LE(WNODE_FLAG_TRACED_GUID, koffi.offsetof(WNODE_HEADER, 'Flags'));

    buffer.writeUInt32LE(EVENT_TRACE_REAL_TIME_MODE, koffi.offsetof(EVENT_TRACE_PROPERTIES, 'LogFileMode'));
    buffer.writeUInt32LE(0, koffi.offsetof(EVENT_TRACE_PROPERTIES, 'LogFileNameOffset'));
    buffer.writeUInt32LE(propsSize, koffi.offsetof(EVENT_TRACE_PROPERTIES, 'LoggerNameOffset'));
    
    // Copy name
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

// Callback
const eventCallback = koffi.register((recordPtr) => {
    // If we are stopping, do not process events to avoid potential crashes
    if (isStopping) return;

    try {
        if (!recordPtr) return;
        const record = recordPtr; // It's already decoded as struct by koffi? No, it's a pointer.
        // Wait, koffi callback receives the value according to the definition.
        // definition: koffi.pointer(EVENT_RECORD)
        // So recordPtr is the pointer/object.
        
        // Since EVENT_RECORD has pointers (UserData), we need to be careful.
        // Accessing fields:
        const header = record.EventHeader;
        const providerId = header.ProviderId;
        const descriptor = header.EventDescriptor;
        
        // Check Provider
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

        // Parse Data
        const userDataPtr = record.UserData;
        const userDataLen = record.UserDataLength;
        
        if (userDataLen > 0 && userDataPtr) {
            const bytes = koffi.decode(userDataPtr, koffi.array('uint8_t', userDataLen));
            if (isProcess) {
                // Process Start (1) / Stop (2)
                if (descriptor.Opcode === 1 || descriptor.Opcode === 2) { // Start / Stop
                    // Struct: ProcessId (4), ParentId (4), ...
                    // Let's assume standard layout for Kernel-Process V1/V2
                    // We need to read raw bytes from userDataPtr
                    
                    // Manual parsing
                    // ProcessId: 0-3
                    // ParentId: 4-7
                    // SessionId: 8-11
                    // ExitStatus: 12-15
                    // UserSID: 16... (Variable)
                    // ImageFileName: string (after SID)
                    // CommandLine: string (after ImageFileName)
                    
                    const pid = Buffer.from(bytes.slice(0, 4)).readUInt32LE(0);
                    const ppid = Buffer.from(bytes.slice(4, 8)).readUInt32LE(0);
                    
                    // Skip UserSID
                    // SID length is variable. offset 16.
                    // SID struct: Revision(1), SubAuthorityCount(1), IdentifierAuthority(6), SubAuthorities(4 * count)
                    let offset = 16;
                    if (offset + 1 < userDataLen) {
                        const subAuthCount = bytes[offset + 1] >>> 0;
                        const sidSize = 8 + (subAuthCount * 4);
                        offset += sidSize;
                        
                        // ImageFileName
                        // It is usually an ANSI string or Unicode string? 
                        // Microsoft-Windows-Kernel-Process usually uses Unicode for ImageFileName
                        // Let's try to find null terminator
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
                // File Create (Opcode 64? or 32?) 
                // Using Microsoft-Windows-Kernel-File
                // Opcode 32 = Create (FileCreate)
                // Opcode 35 = Delete (FileDelete)
                // Opcode 36 = Rename (FileRename)
                // Opcode 14 = Read
                // Opcode 15 = Write
                
                // We care about Create, Delete, Rename, maybe Write (Modify)
                
                // File Create (32)
                // Struct: IrpPtr(8/4), FileObject(8/4), CreateOptions(4), FileAttributes(4), ShareAccess(4), FileName(string)
                
                // Note: Pointers size depends on arch (x64)
                const ptrSize = 8; 
                
                if (descriptor.Opcode === 32 || descriptor.Opcode === 35 || descriptor.Opcode === 36) {
                    // But wait, the schema varies.
                    // Let's assume common fields: FileName is usually at the end.
                    // For Create:
                    // ... fixed fields ... FileName
                    
                    // We can scan for the string? No, dangerous.
                    
                    // Let's try to parse the string from the end or known offset?
                    // For Create: Irp(8), FileObj(8), CreateOptions(4), FileAttributes(4), ShareAccess(4) = 28 bytes
                    // Then FileName
                    
                    let startOffset = 0;
                    if (descriptor.Opcode === 32) startOffset = 28;
                    else if (descriptor.Opcode === 35) startOffset = 16; // Irp(8), FileObj(8) -> FileName?
                    
                    if (startOffset < userDataLen) {
                         // Find null terminator
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
        // console.error(e);
    }
}, EventRecordCallbackType);

function startSession() {
    // 1. Stop existing session if any
    try { ControlTraceW(0n, SESSION_NAME, createPropertyBuffer(), EVENT_TRACE_CONTROL_STOP); } catch {}
    
    // 2. StartTrace
    const handlePtr = [0n];
    let status = StartTraceW(handlePtr, SESSION_NAME, createPropertyBuffer());
    if (status !== ERROR_SUCCESS && status !== ERROR_ALREADY_EXISTS) {
        postMessage({ type: 'error', message: 'StartTrace failed: ' + status });
        return;
    }
    sessionHandle = handlePtr[0];
    
    // 3. Enable Providers
    // Need a pointer to GUID
    // Koffi struct can be passed by value or pointer? 
    // EnableTraceEx2 takes LPCGUID (pointer).
    // We can allocate a GUID struct and pass it.
    
    // Helper to create GUID buffer
    const createGuidBuf = (g) => {
        const b = Buffer.alloc(16);
        b.writeUInt32LE(g.Data1, 0);
        b.writeUInt16LE(g.Data2, 4);
        b.writeUInt16LE(g.Data3, 6);
        Buffer.from(g.Data4).copy(b, 8);
        return b;
    };

    // Enable Process (Start/Stop)
    // Keywords: ProcessStart(0x10), ProcessStop(0x40) -> 0x50 ?
    // Or just 0 (All)
    EnableTraceEx2(sessionHandle, createGuidBuf(GUID_KernelProcess), EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 0n, 0n, 0, null);
    
    // Enable File (Create/Delete)
    // Keywords: 0 (All)
    EnableTraceEx2(sessionHandle, createGuidBuf(GUID_KernelFile), EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 0n, 0n, 0, null);
    
    // 4. OpenTrace
    // LOGFILE structure
    logfile = {
        LogFileName: null,
        LoggerName: SESSION_NAME,
        CurrentTime: 0n,
        BuffersRead: 0,
        ProcessTraceMode: PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD,
        CurrentEvent: {}, // ignored
        LogfileHeader: {}, // ignored
        BufferCallback: null,
        BufferSize: 0,
        Filled: 0,
        EventsLost: 0,
        EventRecordCallback: eventCallback,
        IsKernelTrace: 0,
        Context: null
    };
    
    // We need to pass this struct. Koffi will marshal it.
    // Note: LogFileName and LoggerName are strings (LPWSTR).
    
    traceHandle = OpenTraceW(logfile);
    if (traceHandle === 0xFFFFFFFFFFFFFFFFn || traceHandle === -1n) {
         postMessage({ type: 'error', message: 'OpenTrace failed: ' + GetLastError() });
         return;
    }
    
    postMessage({ type: 'status', message: 'Monitoring started' });
    
    // 5. ProcessTrace (Async)
    // We must keep the handle buffer alive during the async call
    currentHandleBuffer = createTraceHandleArrayBuffer(traceHandle);
    
    // Flag that session is running
    isSessionRunning = true;
    
    ProcessTrace.async(currentHandleBuffer, 1, null, null, (err, status) => {
        currentHandleBuffer = null;
        isSessionRunning = false;
        
        if (err) {
             postMessage({ type: 'error', message: 'ProcessTrace exception: ' + err.message });
        } else if (status !== ERROR_SUCCESS) {
            // Ignore error if we are stopping (usually caused by CloseTrace)
            if (!isStopping) {
                const extra = status === 5 ? '，可能需要以管理员权限运行' : '';
                postMessage({ type: 'error', message: 'ProcessTrace failed: ' + status + extra });
            }
        }
        
        // If we were stopping, now it is safe to exit
        if (isStopping) {
            // Use setImmediate to unwind the stack before exiting to prevent N-API fatal errors
            setImmediate(() => {
                process.exit(0);
            });
        }
    });
}

// Listen for stop
if (parentPort) {
    parentPort.on('message', (msg) => {
        if (msg === 'start') {
            startSession();
        } else if (msg === 'stop') {
            isStopping = true;
            
            // Try to stop session first
            // This should signal ProcessTrace to return eventually
            if (sessionHandle) {
                try { ControlTraceW(sessionHandle, null, createPropertyBuffer(), EVENT_TRACE_CONTROL_STOP); } catch {}
            }

            // DO NOT call CloseTrace here. 
            // CloseTrace causes ProcessTrace to return immediately, but in async mode + koffi + worker threads, 
            // this seems to trigger a race condition leading to Fatal Error::ThrowAsJavaScriptException napi_throw.
            // By stopping the session, ProcessTrace will drain the buffer and return naturally.
            
            // If session is not running, exit immediately
            if (!isSessionRunning) {
                setImmediate(() => {
                    process.exit(0);
                });
            } 
            // If session IS running, we wait for ProcessTrace.async callback to exit the process.
            // Do NOT force exit here, as it may crash N-API if callback is pending.
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
