const { parentPort } = require('worker_threads');
const fs = require('fs');
const path = require('path');
const koffi = require('koffi');
const { createEtwTrustedPidFilter } = require('../etw_trusted_pid_filter');
const winapi = require('../winapi');

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
const HANDLE = koffi.pointer('ETW_HANDLE', koffi.opaque());
const PVOID = 'void *';

const GUID = koffi.struct('ETW_GUID', {
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
const lstrlenA = libKernel32.func('__stdcall', 'lstrlenA', 'int', ['void *']);
const GetCurrentProcess = libKernel32.func('__stdcall', 'GetCurrentProcess', HANDLE, []);
const CloseHandle = libKernel32.func('__stdcall', 'CloseHandle', 'int', [HANDLE]);
const OpenProcessToken = libAdvapi32.func('__stdcall', 'OpenProcessToken', 'int', [HANDLE, ULONG, koffi.out(HANDLE)]);
const GetTokenInformation = libAdvapi32.func('__stdcall', 'GetTokenInformation', 'int', [HANDLE, ULONG, PVOID, ULONG, koffi.out('uint32_t *')]);

let etwBridgeLib = null;
let etwBridgeHandle = null;
let EtwBridge_Create = null;
let EtwBridge_Start = null;
let EtwBridge_Stop = null;
let EtwBridge_PollJson = null;
let EtwBridge_SetRulesJson = null;
let EtwBridge_SetTrackedPids = null;
let EtwBridge_SetContextCapacity = null;
let EtwBridge_Free = null;
let EtwBridge_Destroy = null;
let bridgePollTimer = null;
let bridgePollBusy = false;

/**
 * - 函数: `resolveEtwBridgeDllPath`
 * - Function: `resolveEtwBridgeDllPath`
 * - 作用: 在打包目录与源码目录之间定位 `etw_bridge.dll`，并按“存在且较新优先”的规则选出当前 worker 应加载的 bridge DLL 路径。
 * - Purpose: Resolves `etw_bridge.dll` across packaged and source-tree locations and picks the DLL path this worker should load by preferring existing and newer candidates.
 * - 调用方: `ensureEtwBridgeLoaded` 在尝试 `koffi.load()` 前调用。
 * - Callers: Called by `ensureEtwBridgeLoaded` before attempting `koffi.load()`.
 * - 被调方: `push`、`path.join`、`fs.existsSync`、`fs.statSync`。
 * - Callees: `push`, `path.join`, `fs.existsSync`, `fs.statSync`.
 * - 变量说明: 无显式入参；`candidates` 为候选 DLL 路径列表；`existing` 为实际存在的候选集合；`p` 为当前检查的单个候选路径。
 * - Variables: No explicit parameters; `candidates` is the DLL candidate list; `existing` contains the candidates that actually exist; `p` is the candidate path currently being checked.
 * - 接入方式: 应作为 ETW bridge DLL 的统一定位入口；新增 ETW bridge 装载逻辑不要自行重复拼路径。
 * - Integration: It should remain the single resolver for the ETW bridge DLL; new ETW-bridge loading logic should not rebuild candidate paths on its own.
 * - 错误处理: 内部捕获异常并回退到安全默认值，尽量避免辅助逻辑中断主流程。
 * - Error Handling: Catches local failures and falls back to safe defaults so helper logic does not break the main flow.
 * - 关键词: ETW bridge DLL定位 | ETW bridge DLL resolution | etw_bridge.dll | packaged vs source path | koffi load input | native bridge path | candidate ranking | bridge bootstrap
 */
function resolveEtwBridgeDllPath() {
    const candidates = [];
    try {
        if (process && typeof process.resourcesPath === 'string' && process.resourcesPath) {
            candidates.push(path.join(process.resourcesPath, 'native', 'win32-x64', 'etw_bridge.dll'));
        }
    } catch {}
    try {
        candidates.push(path.join(__dirname, '../../../native/bin/win32-x64/etw_bridge.dll'));
    } catch {}
    const existing = [];
    for (const p of candidates) {
        try {
            if (p && fs.existsSync(p)) existing.push(p);
        } catch {}
    }
    if (existing.length === 0) return null;
    if (existing.length === 1) return existing[0];
    try {
        existing.sort((a, b) => {
            const am = fs.statSync(a).mtimeMs || 0;
            const bm = fs.statSync(b).mtimeMs || 0;
            if (am !== bm) return bm - am;
            return String(a).length - String(b).length;
        });
    } catch {}
    return existing[0] || null;
}

/**
 * - 函数: `ensureEtwBridgeLoaded`
 * - Function: `ensureEtwBridgeLoaded`
 * - 作用: 确保 `etw_bridge.dll` 已被 koffi 成功加载，并把 native 导出函数绑定到当前模块的 `EtwBridge_*` 函数指针上，作为后续创建/启动/停止 ETW 会话的前置步骤。
 * - Purpose: Ensures `etw_bridge.dll` is loaded via koffi and binds native exports into this module’s `EtwBridge_*` function pointers, serving as the prerequisite for creating/starting/stopping the ETW session.
 * - 调用方: `ensureEtwBridgeHandle`（创建 session 句柄前）、`startSessionOnce` / `stopSessionInternal`（启动/停止会话前确保 bridge 可用）。
 * - Callers: `ensureEtwBridgeHandle` (before creating the session handle), `startSessionOnce` / `stopSessionInternal` (ensures the bridge is available before session start/stop).
 * - 被调方: `resolveEtwBridgeDllPath`、`postError`、`path.join`、`koffi.load`、`etwBridgeLib.func`、`koffi.out`、`koffi.pointer`、`String(...)`。
 * - Callees: `resolveEtwBridgeDllPath`, `postError`, `path.join`, `koffi.load`, `etwBridgeLib.func`, `koffi.out`, `koffi.pointer`, `String(...)`.
 * - 变量说明: 无显式入参；`etwBridgeLib` 为已加载的 koffi library 单例；`dllPath` 为解析到的 `etw_bridge.dll` 路径；`EtwBridge_*` 为 native 导出函数指针（含可选的 `EtwBridge_SetRulesJson/SetTrackedPids/SetContextCapacity`）。
 * - Variables: No explicit parameters; `etwBridgeLib` is the loaded koffi library singleton; `dllPath` is the resolved `etw_bridge.dll` path; `EtwBridge_*` are bound native function pointers (including optional `EtwBridge_SetRulesJson/SetTrackedPids/SetContextCapacity`).
 * - 接入方式: 在任何依赖 `EtwBridge_*` 的逻辑（创建句柄、启动会话、轮询消息）之前先调用本函数；若返回 `false` 应视为“bridge 不可用”并走降级（例如返回错误并停止启动）。
 * - Integration: Call this function before any logic that depends on `EtwBridge_*` (handle creation, session start, message polling); if it returns `false`, treat the bridge as unavailable and degrade (e.g., report error and abort startup).
 * - 错误处理: DLL 路径缺失时通过 `postError('ETW_BRIDGE_DLL_MISSING', ...)` 上报并返回 `false`；加载或绑定失败时通过 `postError('ETW_BRIDGE_LOAD_FAILED', ...)` 上报、清空已部分初始化的指针并返回 `false`；成功时返回 `true`；已加载则幂等返回 `true`。
 * - Error Handling: If the DLL is missing, reports via `postError('ETW_BRIDGE_DLL_MISSING', ...)` and returns `false`; on load/bind failure, reports via `postError('ETW_BRIDGE_LOAD_FAILED', ...)`, clears partially initialized pointers, and returns `false`; returns `true` on success; is idempotent when already loaded.
 * - 关键词: ETW桥接 | ETW bridge | etw_bridge.dll | koffi.load | FFI绑定 | native binding | EtwBridge_Create | EtwBridge_PollJson | 句柄创建前置 | handle prerequisite | 幂等加载 | idempotent load
 */
function ensureEtwBridgeLoaded() {
    if (etwBridgeLib) return true;
    const dllPath = resolveEtwBridgeDllPath();
    if (!dllPath) {
        postError('ETW_BRIDGE_DLL_MISSING', '未找到 etw_bridge.dll', { candidates: [path.join(process.resourcesPath || '', 'native', 'win32-x64', 'etw_bridge.dll'), path.join(__dirname, '../../../native/bin/win32-x64/etw_bridge.dll')] });
        return false;
    }
    try {
        etwBridgeLib = koffi.load(dllPath);
        EtwBridge_Create = etwBridgeLib.func('__cdecl', 'EtwBridge_Create', 'void *', ['string16']);
        EtwBridge_Start = etwBridgeLib.func('__cdecl', 'EtwBridge_Start', 'int', ['void *', 'uint64_t', 'uint64_t', 'uint64_t', 'uint64_t', 'uint64_t', 'uint64_t', 'uint64_t', 'uint64_t', 'int', 'int', 'int', 'uint32_t']);
        EtwBridge_Stop = etwBridgeLib.func('__cdecl', 'EtwBridge_Stop', 'int', ['void *', 'uint32_t']);
        EtwBridge_PollJson = etwBridgeLib.func('__cdecl', 'EtwBridge_PollJson', 'int', ['void *', koffi.out(koffi.pointer('void *', 2))]);
        try { EtwBridge_SetRulesJson = etwBridgeLib.func('__cdecl', 'EtwBridge_SetRulesJson', 'int', ['void *', 'string']); } catch { EtwBridge_SetRulesJson = null; }
        try { EtwBridge_SetTrackedPids = etwBridgeLib.func('__cdecl', 'EtwBridge_SetTrackedPids', 'int', ['void *', koffi.pointer('uint32_t'), 'uint32_t', 'int']); } catch { EtwBridge_SetTrackedPids = null; }
        try { EtwBridge_SetContextCapacity = etwBridgeLib.func('__cdecl', 'EtwBridge_SetContextCapacity', 'int', ['void *', 'uint32_t']); } catch { EtwBridge_SetContextCapacity = null; }
        EtwBridge_Free = etwBridgeLib.func('__cdecl', 'EtwBridge_Free', 'void', ['void *']);
        EtwBridge_Destroy = etwBridgeLib.func('__cdecl', 'EtwBridge_Destroy', 'void', ['void *']);
        return true;
    } catch (e) {
        postError('ETW_BRIDGE_LOAD_FAILED', (e && e.message) ? e.message : String(e || 'load_failed'), { dllPath });
        etwBridgeLib = null;
        EtwBridge_SetRulesJson = null;
        EtwBridge_SetTrackedPids = null;
        EtwBridge_SetContextCapacity = null;
        return false;
    }
}

/**
 * - 函数: `ensureEtwBridgeHandle`
 * - Function: `ensureEtwBridgeHandle`
 * - 作用: 确保 ETW bridge 会话句柄（`etwBridgeHandle`）已创建；若尚未创建则先保证 bridge 已加载，再调用 `EtwBridge_Create(sessionName)` 创建句柄并缓存为单例。
 * - Purpose: Ensures the ETW bridge session handle (`etwBridgeHandle`) is created; if missing, it first ensures the bridge is loaded, then calls `EtwBridge_Create(sessionName)` and caches the handle as a singleton.
 * - 调用方: `startSessionOnce`（启动会话时获取句柄）、`stopSessionInternal`（停止/清理时确保句柄存在以便调用 stop/free/destroy）。
 * - Callers: `startSessionOnce` (gets the handle during session start), `stopSessionInternal` (ensures a handle exists for stop/free/destroy during shutdown/cleanup).
 * - 被调方: `ensureEtwBridgeLoaded`、`EtwBridge_Create`、`postError`、`String(...)`。
 * - Callees: `ensureEtwBridgeLoaded`, `EtwBridge_Create`, `postError`, `String(...)`.
 * - 变量说明: 无显式入参；`etwBridgeHandle` 为模块级句柄单例；`sessionName` 来自 `etwCfg.sessionName` 或 `DEFAULT_ETW_CFG.sessionName`，用于区分 ETW session。
 * - Variables: No explicit parameters; `etwBridgeHandle` is the module-level handle singleton; `sessionName` is resolved from `etwCfg.sessionName` or `DEFAULT_ETW_CFG.sessionName` to identify the ETW session.
 * - 接入方式: 在调用 `EtwBridge_Start/Stop/PollJson` 之前调用并检查返回值；返回 `null` 时应停止后续启动/轮询逻辑并依赖 `postError` 的上报提示主进程进入降级。
 * - Integration: Call it before invoking `EtwBridge_Start/Stop/PollJson` and check the return value; when it returns `null`, abort subsequent start/poll logic and rely on `postError` reporting so the main process can degrade.
 * - 错误处理: bridge 未加载或加载失败则返回 `null`；创建返回空句柄或抛异常时通过 `postError('ETW_BRIDGE_CREATE_FAILED', ...)` 上报并返回 `null`；已创建则直接返回缓存句柄。
 * - Error Handling: Returns `null` if the bridge is not loaded/cannot be loaded; if creation returns a null handle or throws, reports via `postError('ETW_BRIDGE_CREATE_FAILED', ...)` and returns `null`; otherwise returns the cached handle.
 * - 关键词: ETW句柄 | ETW handle | EtwBridge_Create | sessionName | 句柄单例 | handle singleton | 启动前置 | start prerequisite | stopSessionInternal | startSessionOnce | 错误上报 | error reporting | ETW_BRIDGE_CREATE_FAILED | bridge handle
 */
function ensureEtwBridgeHandle() {
    if (etwBridgeHandle) return etwBridgeHandle;
    if (!ensureEtwBridgeLoaded()) return null;
    const sessionName = (etwCfg && etwCfg.sessionName) ? etwCfg.sessionName : DEFAULT_ETW_CFG.sessionName;
    try {
        etwBridgeHandle = EtwBridge_Create(sessionName);
        if (!etwBridgeHandle) {
            postError('ETW_BRIDGE_CREATE_FAILED', 'EtwBridge_Create 返回空句柄', { sessionName });
            return null;
        }
        return etwBridgeHandle;
    } catch (e) {
        postError('ETW_BRIDGE_CREATE_FAILED', (e && e.message) ? e.message : String(e || 'create_failed'), { sessionName });
        return null;
    }
}

/**
 * - 函数: `stopBridgePoller`
 * - Function: `stopBridgePoller`
 * - 作用: 停止 bridge 轮询定时器（`bridgePollTimer`），防止会话停止/回滚后仍持续调用 `drainBridgeMessages` 造成无效开销或状态竞争。
 * - Purpose: Stops the bridge polling timer (`bridgePollTimer`) to prevent continued `drainBridgeMessages` calls after session stop/rollback, avoiding wasted work and state races.
 * - 调用方: `cleanupResources`（会话停止与启动回滚的收尾清理阶段）。
 * - Callers: `cleanupResources` (teardown cleanup for session stop and startup rollback).
 * - 被调方: `clearInterval`。
 * - Callees: `clearInterval`.
 * - 变量说明: 无显式入参；`bridgePollTimer` 为模块级 interval 句柄，非空表示轮询器已启动；停止后会被置为 `null`。
 * - Variables: No explicit parameters; `bridgePollTimer` is the module-level interval handle, non-null means poller is running; it is set to `null` after stopping.
 * - 接入方式: 仅应通过 `cleanupResources` 触发（由 `stopSession`/`startSessionOnce` 回滚链路间接调用），避免在业务链路中随意 stop 导致轮询与会话状态不同步。
 * - Integration: Trigger it via `cleanupResources` only (indirectly from `stopSession` / rollback in `startSessionOnce`) to avoid desynchronizing polling and session state by stopping it arbitrarily.
 * - 错误处理: 对未启动状态直接返回；`clearInterval` 置于 `try/catch` 中以容忍无效句柄或运行时差异；不抛异常以保证停止链路幂等可重复执行。
 * - Error Handling: Returns immediately if not started; wraps `clearInterval` in `try/catch` to tolerate invalid handles/runtime differences; never throws so shutdown remains idempotent and safe to repeat.
 * - 关键词: 轮询停止 | poller stop | clearInterval | bridgePollTimer | 会话收尾 | session teardown | 回滚清理 | rollback cleanup | 幂等 | idempotent | drainBridgeMessages | 状态竞争 | race condition | ETW worker | 资源释放 | resource release
 */
function stopBridgePoller() {
    if (!bridgePollTimer) return;
    try { clearInterval(bridgePollTimer); } catch {}
    bridgePollTimer = null;
}

/**
 * - 函数: `startBridgePoller`
 * - Function: `startBridgePoller`
 * - 作用: 启动 bridge 轮询定时器，以固定间隔调用 `drainBridgeMessages` 把桥接层消息持续拉取进 worker；保证只启动一次，避免重复 setInterval 造成并发 drain 与消息重复处理。
 * - Purpose: Starts the bridge polling timer to call `drainBridgeMessages` at a fixed interval and continuously pull bridge messages into the worker; ensures it starts only once to avoid concurrent drains and duplicate processing.
 * - 调用方: `startSessionOnce`（ETW 会话成功建立后启动轮询，使桥接消息进入 worker 处理链路）。
 * - Callers: `startSessionOnce` (starts polling after the ETW session is established so bridge messages flow into the worker pipeline).
 * - 被调方: `setInterval`、`drainBridgeMessages`。
 * - Callees: `setInterval`, `drainBridgeMessages`.
 * - 变量说明: 无显式入参；`bridgePollTimer` 为模块级 interval 句柄；间隔当前固定为 10ms，用于尽快清空 bridge 队列并降低积压。
 * - Variables: No explicit parameters; `bridgePollTimer` is the module-level interval handle; the interval is currently fixed at 10ms to drain the bridge queue promptly and reduce backlog.
 * - 接入方式: 仅应在会话进入运行态后调用一次；停止流程应通过 `stopSession` → `cleanupResources` → `stopBridgePoller` 关闭轮询，确保轮询生命周期与会话生命周期对齐。
 * - Integration: Call it once only after the session enters running state; shutdown should stop it via `stopSession` → `cleanupResources` → `stopBridgePoller` so poller lifecycle stays aligned with session lifecycle.
 * - 错误处理: 若已启动则直接返回；轮询回调内对 `drainBridgeMessages` 异常进行吞掉，避免单次 drain 异常导致 interval 线程崩溃；本函数本身不抛异常。
 * - Error Handling: Returns immediately if already started; swallows exceptions from `drainBridgeMessages` inside the interval callback so a single drain failure does not break the timer; the function itself does not throw.
 * - 关键词: 轮询启动 | poller start | setInterval | drainBridgeMessages | 10ms轮询 | 10ms polling | 消息拉取 | message pulling | 队列积压 | queue backlog | 单例定时器 | singleton timer | 会话对齐 | lifecycle alignment | ETW bridge | worker循环 | worker loop
 */
function startBridgePoller() {
    if (bridgePollTimer) return;
    bridgePollTimer = setInterval(() => {
        try { drainBridgeMessages(); } catch {}
    }, 10);
}

/**
 * - 函数: `drainBridgeMessages`
 * - Function: `drainBridgeMessages`
 * - 作用: 从 ETW bridge 的内部队列中批量拉取 JSON 消息：调用 `EtwBridge_PollJson` 获取指针、拷贝并解码 UTF-8 字符串、解析为对象后交由 `handleBridgeMessage` 处理；用于定时轮询与停止阶段的“消息排空”。
 * - Purpose: Drains JSON messages from the ETW bridge queue in batches: calls `EtwBridge_PollJson` to get a pointer, copies and decodes the UTF-8 text, parses it into an object, and dispatches it to `handleBridgeMessage`; used by periodic polling and shutdown-time “message draining”.
 * - 调用方: `startBridgePoller`（定时轮询）、`stopSession`（停止时尽量排空残留消息）、`startSessionOnce`（启动/回滚阶段的排空或探测逻辑）。
 * - Callers: `startBridgePoller` (periodic polling), `stopSession` (best-effort drain before teardown), `startSessionOnce` (drain/probe during startup or rollback).
 * - 被调方: `EtwBridge_PollJson`、`lstrlenA`、`koffi.decode`、`koffi.array`、`Buffer.from`、`JSON.parse`、`EtwBridge_Free`、`handleBridgeMessage`、`postError`、`String(...)`。
 * - Callees: `EtwBridge_PollJson`, `lstrlenA`, `koffi.decode`, `koffi.array`, `Buffer.from`, `JSON.parse`, `EtwBridge_Free`, `handleBridgeMessage`, `postError`, `String(...)`.
 * - 变量说明: 无显式入参；`bridgePollBusy` 防止重入；`n` 为单次最多处理条数（上限 200）；`out` 为 koffi out 参数数组；`rc` 为 poll 返回码；`ptr` 为返回的 C 字符串指针；`len` 为字符串长度；`text` 为解码后的 JSON 文本；`obj` 为解析后的消息对象。
 * - Variables: No explicit parameters; `bridgePollBusy` prevents re-entry; `n` caps messages per drain call (max 200); `out` is the koffi out-arg array; `rc` is the poll return code; `ptr` is the returned C-string pointer; `len` is the string length; `text` is decoded JSON text; `obj` is the parsed message object.
 * - 接入方式: 只应由 `startBridgePoller` 的 interval 或停止/回滚路径调用；若后续调整 bridge 侧协议（例如返回码语义/编码方式），应优先在本函数集中适配，避免上游轮询逻辑分叉。
 * - Integration: Call it only from `startBridgePoller`’s interval or teardown/rollback paths; if the bridge protocol changes (return-code semantics/encoding), adapt centrally here to prevent polling logic from forking across call sites.
 * - 错误处理: 通过 `try/finally` 确保 `bridgePollBusy` 复位；`EtwBridge_PollJson` 抛异常时上报 `ETW_BRIDGE_POLL_FAILED` 并中止本轮；对空指针、异常长度、解码/解析失败采取“跳过或结束本轮”的策略并确保尝试 `EtwBridge_Free(ptr)`，避免内存泄漏；不向外抛异常以保证轮询器稳定运行。
 * - Error Handling: Uses `try/finally` to always reset `bridgePollBusy`; reports `ETW_BRIDGE_POLL_FAILED` on poll exceptions and aborts the current drain; skips or stops on null pointers, invalid lengths, decode/parse failures while still attempting `EtwBridge_Free(ptr)` to avoid leaks; does not throw so the poller remains stable.
 * - 关键词: 消息排空 | message drain | EtwBridge_PollJson | JSON解析 | JSON parse | 指针释放 | pointer free | EtwBridge_Free | 轮询循环 | polling loop | 批量限制 | batch cap | bridgePollBusy | 非阻塞 | non-blocking | handleBridgeMessage | ETW_BRIDGE_POLL_FAILED | UTF-8解码 | UTF-8 decode
 */
function drainBridgeMessages() {
    if (bridgePollBusy) return;
    bridgePollBusy = true;
    try {
        if (!etwBridgeHandle || !EtwBridge_PollJson) return;
        let n = 0;
        while (n < 200) {
            const out = [null];
            let rc = 0;
            try {
                rc = EtwBridge_PollJson(etwBridgeHandle, out);
            } catch (e) {
                postError('ETW_BRIDGE_POLL_FAILED', (e && e.message) ? e.message : String(e || 'poll_failed'));
                break;
            }
            if (rc !== 1) break;
            const ptr = out[0];
            let text = '';
            try {
                if (!ptr) break;
                const len = lstrlenA(ptr) | 0;
                if (len <= 0 || len > (1024 * 1024)) {
                    try { EtwBridge_Free(ptr); } catch {}
                    n++;
                    continue;
                }
                const bytes = koffi.decode(ptr, koffi.array('uint8_t', len));
                text = Buffer.from(bytes).toString('utf8');
            } catch (e) {
                try { EtwBridge_Free(ptr); } catch {}
                break;
            }
            try { EtwBridge_Free(ptr); } catch {}
            if (!text) { n++; continue; }
            let obj = null;
            try { obj = JSON.parse(String(text)); } catch { obj = null; }
            if (!obj || typeof obj !== 'object') { n++; continue; }
            handleBridgeMessage(obj);
            n++;
        }
    } finally {
        bridgePollBusy = false;
    }
}

/**
 * - 函数: `handleBridgeMessage`
 * - Function: `handleBridgeMessage`
 * - 作用: 作为 bridge → worker 的核心“清洗/路由”节点，处理 `status`/`error`/`match`/`log` 四类消息：对路径字段做标准化、按配置与可信 PID 规则过滤事件，并将最终事件以 `postMessage({type:'log', event})` 的形式转发到主进程。
 * - Purpose: Acts as the core bridge→worker “sanitize & route” node for `status`/`error`/`match`/`log` messages: normalizes path fields, filters events using config and trusted-PID rules, and forwards accepted events to the main process via `postMessage({type:'log', event})`.
 * - 调用方: `drainBridgeMessages`（每次从 `EtwBridge_PollJson` 拉取并解析出对象后逐条调用）。
 * - Callers: `drainBridgeMessages` (invoked per parsed message object drained from `EtwBridge_PollJson`).
 * - 被调方: `postMessage`、`normalizeEtwPathValue`、`shouldSkipByCfg`、`asPid`、`trustedPidFilter.onProcessStart`、`trustedPidFilter.onProcessStop`、`shouldSkipTrustedEvent`、`postError`、`String(...)`。
 * - Callees: `postMessage`, `normalizeEtwPathValue`, `shouldSkipByCfg`, `asPid`, `trustedPidFilter.onProcessStart`, `trustedPidFilter.onProcessStop`, `shouldSkipTrustedEvent`, `postError`, `String(...)`.
 * - 变量说明: `msg` 为 bridge 回传的单条消息对象；`ev` 为 `log` 消息中的事件体；`provider` 为事件源（`Process`/`File`/`Registry`/`Network`）；`data` 为事件字段集合；`typ` 为 provider 内部子类型（如 Process.Start/Stop）；`pid`/`img` 用于维护可信进程状态与过滤决策。
 * - Variables: `msg` is one bridge message object; `ev` is the event payload inside `log` messages; `provider` is the source stream (`Process`/`File`/`Registry`/`Network`); `data` is the field bag; `typ` is the provider-specific subtype (e.g., Process.Start/Stop); `pid`/`img` are used to maintain trusted-process state and filtering decisions.
 * - 接入方式: 仅供 worker 内部 bridge 消费链路使用；新增 provider/字段时应先在此处定义标准化与过滤策略（尤其是可信 PID 行为），再决定是否上行；不要在其他地方直接 `postMessage({type:'log', event})` 绕过过滤，避免策略分散。
 * - Integration: Use it only from the internal bridge-consumption chain; when adding providers/fields, define normalization and filtering here (especially trusted-PID behavior) before forwarding; avoid bypassing this logic by posting `log` events elsewhere, so policy remains centralized.
 * - 错误处理: 对无效/不支持消息静默忽略；任何运行时异常会被捕获并通过 `postError('ETW_BRIDGE_MESSAGE_ERROR', ...)` 上报（附带 stack），不把异常抛出到 `drainBridgeMessages`，从而保持轮询链路健壮。
 * - Error Handling: Silently ignores invalid/unsupported messages; any runtime exception is caught and reported via `postError('ETW_BRIDGE_MESSAGE_ERROR', ...)` (with stack) without throwing back to `drainBridgeMessages`, keeping the polling chain robust.
 * - 关键词: 桥接消息 | bridge message | 日志事件 | log event | provider过滤 | provider filtering | 可信PID | trusted PID | 路径标准化 | path normalization | shouldSkipByCfg | shouldSkipTrustedEvent | postMessage | 事件路由 | event routing | ETW_BRIDGE_MESSAGE_ERROR | 错误上报 | error reporting
 */
function handleBridgeMessage(msg) {
    try {
        if (!msg || typeof msg !== 'object') return;
        if (msg.type === 'status' || msg.type === 'error') {
            postMessage(msg);
            return;
        }
        if (msg.type === 'match') {
            postMessage(msg);
            return;
        }
        if (msg.type !== 'log' || !msg.event) return;
        const ev = msg.event;
        if (ev && ev.data && typeof ev.data === 'object') {
            if (typeof ev.data.imageName === 'string') ev.data.imageName = normalizeEtwPathValue(ev.data.imageName);
            if (typeof ev.data.fileName === 'string') ev.data.fileName = normalizeEtwPathValue(ev.data.fileName);
        }
        const provider = typeof ev.provider === 'string' ? ev.provider : '';
        const data = ev.data && typeof ev.data === 'object' ? ev.data : null;
        if (provider === 'Process' && data) {
            const typ = typeof data.type === 'string' ? data.type : '';
            if (shouldSkipByCfg('Process', typ)) return;
            const pid = asPid(data.processId);
            const img = typeof data.imageName === 'string' ? data.imageName : '';
            if (typ === 'Start') {
                try { trustedPidFilter.onProcessStart(pid, img); } catch {}
            } else if (typ === 'Stop') {
                try { trustedPidFilter.onProcessStop(pid); } catch {}
            }
            if (shouldSkipTrustedEvent(ev)) return;
            postMessage({ type: 'log', event: ev });
            return;
        }
        if (provider === 'File' && data) {
            const typ = typeof data.type === 'string' ? data.type : '';
            if (shouldSkipByCfg('File', typ)) return;
            if (shouldSkipTrustedEvent(ev)) return;
            postMessage({ type: 'log', event: ev });
            return;
        }
        if (provider === 'Registry' && data) {
            const typ = typeof data.type === 'string' ? data.type : '';
            if (shouldSkipByCfg('Registry', typ)) return;
            if (shouldSkipTrustedEvent(ev)) return;
            postMessage({ type: 'log', event: ev });
            return;
        }
        if (provider === 'Network' && data) {
            const typ = typeof data.type === 'string' ? data.type : '';
            if (shouldSkipByCfg('Network', typ)) return;
            if (shouldSkipTrustedEvent(ev)) return;
            postMessage({ type: 'log', event: ev });
        }
    } catch (e) {
        postError('ETW_BRIDGE_MESSAGE_ERROR', (e && e.message) ? e.message : String(e || 'message_error'), { stack: e && e.stack ? String(e.stack) : '' });
    }
}

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

let trustedPidFilter = createEtwTrustedPidFilter({
    verifyTrust: (p) => {
        if (!winapi || typeof winapi.verifyTrust !== 'function') return false;
        return winapi.verifyTrust(p) === true;
    },
    devicePathToDosPath: (p) => {
        if (!winapi || typeof winapi.devicePathToDosPath !== 'function') return p;
        return winapi.devicePathToDosPath(p) || p;
    }
});

let extraTrustedPids = new Set();
let trustedSkipProviders = null;
let didPrimeDeviceMap = false;

/**
 * - 函数: `primeDriveDeviceMapOnce`
 * - Function: `primeDriveDeviceMapOnce`
 * - 作用: 预热“盘符 ↔ 设备路径”映射缓存（仅执行一次），为 `normalizeEtwPathValue` 的设备路径转换提供前置数据，避免首次转换时触发额外开销或出现映射缺失。
 * - Purpose: Primes the “drive-letter ↔ device-path” mapping cache once to support `normalizeEtwPathValue` conversions, reducing first-use overhead and avoiding missing mappings.
 * - 调用方: `normalizeEtwPathValue`（标准化路径时需要设备映射）、`startWithRetry`（启动前主动预热，降低首次事件到来时延迟）。
 * - Callers: `normalizeEtwPathValue` (needs device mapping for normalization), `startWithRetry` (proactively primes before startup to reduce first-event latency).
 * - 被调方: `winapi.primeDriveDeviceMap`、`winapi.getDriveDeviceMap`。
 * - Callees: `winapi.primeDriveDeviceMap`, `winapi.getDriveDeviceMap`.
 * - 变量说明: 无显式入参；`didPrimeDeviceMap` 为模块级一次性开关，确保预热逻辑幂等；`winapi` 为 native 能力入口，可能缺少对应函数，因此需做能力检测。
 * - Variables: No explicit parameters; `didPrimeDeviceMap` is a module-level one-shot flag to keep priming idempotent; `winapi` is the native capability entry and may not provide these APIs, so capability checks are required.
 * - 接入方式: 作为路径标准化链路的内部基础设施使用；当新增任何依赖 `devicePathToDosPath` 的路径转换逻辑时，应先调用本函数以确保映射已准备。
 * - Integration: Treat it as internal infrastructure for path normalization; when adding any new logic that relies on `devicePathToDosPath`, call this first to ensure mappings are ready.
 * - 错误处理: 已预热则直接返回；对 `winapi` 缺失或调用失败进行静默吞掉（`try/catch`），允许在缺少能力时退化为“原样返回路径”的行为而不影响主链路运行。
 * - Error Handling: Returns immediately if already primed; silently swallows missing-API or call failures (`try/catch`), allowing graceful degradation (paths may remain unchanged) without breaking the main flow.
 * - 关键词: 设备映射预热 | device map prime | drive letter | 盘符 | device path | 设备路径 | normalizeEtwPathValue | winapi | didPrimeDeviceMap | 幂等 | idempotent | 启动预热 | startup prime | 延迟降低 | latency reduction | 能力检测 | capability check
 */
function primeDriveDeviceMapOnce() {
    if (didPrimeDeviceMap) return;
    didPrimeDeviceMap = true;
    try {
        if (winapi && typeof winapi.primeDriveDeviceMap === 'function') {
            winapi.primeDriveDeviceMap();
        } else if (winapi && typeof winapi.getDriveDeviceMap === 'function') {
            winapi.getDriveDeviceMap();
        }
    } catch {}
}

/**
 * - 函数: `normalizeEtwPathValue`
 * - Function: `normalizeEtwPathValue`
 * - 作用: 规范化 ETW 事件中出现的路径类字段：去除首尾空白、剥离包裹引号，并在 winapi 能力可用时把设备路径转换为盘符路径（DOS path），用于后续展示与过滤的一致性。
 * - Purpose: Normalizes path-like values in ETW events by trimming whitespace, stripping wrapping quotes, and converting device paths to DOS drive-letter paths when winapi capability is available, improving consistency for display and filtering.
 * - 调用方: `handleBridgeMessage`（对 imageName/fileName 等字段做标准化）、`createEventCallback`（从 EVENT_RECORD 抽取路径字段后做标准化）。
 * - Callers: `handleBridgeMessage` (normalizes fields like imageName/fileName), `createEventCallback` (normalizes paths extracted from EVENT_RECORD).
 * - 被调方: `primeDriveDeviceMapOnce`、`String.prototype.trim`、`String.prototype.startsWith`、`String.prototype.endsWith`、`String.prototype.slice`、`winapi.devicePathToDosPath`。
 * - Callees: `primeDriveDeviceMapOnce`, `String.prototype.trim`, `String.prototype.startsWith`, `String.prototype.endsWith`, `String.prototype.slice`, `winapi.devicePathToDosPath`.
 * - 变量说明: `v` 为输入值（预期字符串）；`s` 为清洗后的候选字符串；当 `winapi.devicePathToDosPath` 不存在时直接返回 `s`，避免引入对 native 能力的硬依赖。
 * - Variables: `v` is the input value (expected string); `s` is the cleaned candidate string; when `winapi.devicePathToDosPath` is unavailable, the function returns `s` directly to avoid hard dependency on native capability.
 * - 接入方式: 对所有来自 bridge 或 EVENT_RECORD 的路径字段在入站处理阶段统一调用本函数；新增路径字段（如 registryKey、commandLine 中的 path）时也应优先复用本函数以保持同一标准化策略。
 * - Integration: Call this function in the ingress stage for all path fields coming from the bridge or EVENT_RECORD; when adding new path fields (e.g., registryKey or paths inside commandLine), reuse this helper to keep normalization policy consistent.
 * - 错误处理: 非字符串或空值直接原样返回；引号剥离后为空则返回空串；设备路径转换包裹在 `try/catch` 中，转换失败时回退返回 `s`，不抛异常以保证事件处理链路稳定。
 * - Error Handling: Non-string or empty inputs are returned as-is; returns empty string when quote-stripping yields empty; device-path conversion is wrapped in `try/catch` and falls back to `s` on failure, never throwing to keep the event pipeline stable.
 * - 关键词: 路径标准化 | path normalization | 引号剥离 | quote stripping | 设备路径 | device path | 盘符路径 | DOS path | winapi.devicePathToDosPath | primeDriveDeviceMapOnce | handleBridgeMessage | createEventCallback | ETW事件 | ETW event | 输入清洗 | input sanitization
 */
function normalizeEtwPathValue(v) {
    if (typeof v !== 'string' || !v) return v;
    let s = v.trim();
    if (!s) return s;
    if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
        s = s.slice(1, -1).trim();
        if (!s) return s;
    }
    if (!winapi || typeof winapi.devicePathToDosPath !== 'function') return s;
    primeDriveDeviceMapOnce();
    try { return winapi.devicePathToDosPath(s) || s; } catch { return s; }
}

/**
 * - 函数: `asPid`
 * - Function: `asPid`
 * - 作用: 将来自 bridge/ETW 回调的 PID 值规整为可用的非负整数（或 `null`），统一处理 number/string 混用、NaN、负数等异常输入，为可信 PID 与事件过滤链路提供稳定的 PID 基元。
 * - Purpose: Normalizes PID values from the bridge/ETW callback into a usable non-negative integer (or `null`), handling number/string mixing, NaN, and negatives, providing a stable PID primitive for trusted-PID and filtering pipelines.
 * - 调用方: `handleBridgeMessage`（解析 data.processId）、`getRelevantPidForEvent`（推导事件关联 PID）、`applyTrustedPidCfg`（解析配置中的额外可信 PID）。
 * - Callers: `handleBridgeMessage` (parses data.processId), `getRelevantPidForEvent` (derives event-relevant PID), `applyTrustedPidCfg` (parses extra trusted PIDs from config).
 * - 被调方: `parseInt`、`String(...)`、`Number.isFinite`。
 * - Callees: `parseInt`, `String(...)`, `Number.isFinite`.
 * - 变量说明: `v` 为待转换 PID（可为 number/string/其他）；`n` 为转换后的数值；当 `n` 非有限或小于 0 时返回 `null` 表示“无有效 PID”。
 * - Variables: `v` is the PID candidate (number/string/other); `n` is the parsed numeric value; returns `null` when `n` is not finite or is negative to indicate “no valid PID”.
 * - 接入方式: 在任何需要对 PID 做集合判断（如 `extraTrustedPids.has(pid)`）或可信策略计算前调用；不要在各处重复 `parseInt`/`Number(...)`，以保持 PID 语义一致。
 * - Integration: Call it before any PID-based set checks (e.g., `extraTrustedPids.has(pid)`) or trust-policy computation; avoid duplicating `parseInt`/`Number(...)` logic across call sites to keep PID semantics consistent.
 * - 错误处理: 本函数不抛异常；对无法解析的输入回退为 `null`；调用方应将 `null` 视为“无法判定可信/过滤”，并采用保守策略（通常不跳过）。
 * - Error Handling: Never throws; invalid inputs fall back to `null`; callers should treat `null` as “cannot evaluate trust/filter” and apply conservative behavior (typically do not skip).
 * - 关键词: PID归一化 | PID normalization | parseInt | Number.isFinite | 非负校验 | non-negative | handleBridgeMessage | getRelevantPidForEvent | trusted PID | 可信PID | 输入容错 | input tolerance | 过滤基元 | filtering primitive | null回退 | null fallback
 */
function asPid(v) {
    const n = typeof v === 'number' ? v : parseInt(String(v), 10);
    if (!Number.isFinite(n) || n < 0) return null;
    return n;
}

/**
 * - 函数: `getRelevantPidForEvent`
 * - Function: `getRelevantPidForEvent`
 * - 作用: 为“可信 PID 过滤”推导当前事件应关联的 PID：对 Process.Start/Stop 事件优先使用 `data.processId`（主体进程），否则回退使用事件头部的 `ev.pid`；统一解决不同 provider 事件 PID 字段含义差异。
 * - Purpose: Derives the PID relevant for “trusted PID filtering”: for Process.Start/Stop events it prefers `data.processId` (the subject process), otherwise falls back to `ev.pid`; this unifies PID semantics across providers with differing PID fields.
 * - 调用方: `shouldSkipTrustedEvent`（判断事件是否属于可信进程并决定跳过策略）。
 * - Callers: `shouldSkipTrustedEvent` (decides whether an event belongs to a trusted process and whether to skip it).
 * - 被调方: `asPid`。
 * - Callees: `asPid`.
 * - 变量说明: `ev` 为事件对象；`provider`/`data` 从 `ev` 读取；`typ` 为 Process 事件子类型；`subjectPid` 为 Start/Stop 中的主体 PID；返回值为 PID 或 `null`（无法确定）。
 * - Variables: `ev` is the event object; `provider`/`data` are read from `ev`; `typ` is the Process subtype; `subjectPid` is the subject PID for Start/Stop; returns a PID or `null` when undetermined.
 * - 接入方式: 仅用于可信 PID/降噪过滤链路；如果以后引入更多“主体 PID”字段（例如父子进程或网络连接的 ownerPid），应在本函数集中扩展推导规则，而不是在 `shouldSkipTrustedEvent` 中写分支。
 * - Integration: Use it for the trusted-PID/noise-reduction pipeline only; if more “subject PID” fields are introduced later (parent/child processes or connection ownerPid), extend derivation rules here rather than branching inside `shouldSkipTrustedEvent`.
 * - 错误处理: 对无效事件结构直接返回 `null`；不抛异常；调用方在 `null` 场景应采取保守策略（通常不跳过事件）。
 * - Error Handling: Returns `null` for invalid event shapes; never throws; callers should apply conservative behavior (typically do not skip) when PID is `null`.
 * - 关键词: 关联PID | relevant PID | Process.Start | Process.Stop | data.processId | ev.pid | shouldSkipTrustedEvent | PID语义 | PID semantics | asPid | 可信过滤 | trusted filtering | 降噪 | noise reduction
 */
function getRelevantPidForEvent(ev) {
    const e = ev && typeof ev === 'object' ? ev : null;
    if (!e) return null;
    const provider = typeof e.provider === 'string' ? e.provider : '';
    const data = e.data && typeof e.data === 'object' ? e.data : null;
    if (provider === 'Process' && data) {
        const typ = typeof data.type === 'string' ? data.type : '';
        if (typ === 'Start' || typ === 'Stop') {
            const subjectPid = asPid(data.processId);
            if (subjectPid != null) return subjectPid;
        }
    }
    return asPid(e.pid);
}

/**
 * - 函数: `getTrustedPidCfg`
 * - Function: `getTrustedPidCfg`
 * - 作用: 从 `filters` 中安全提取 `trustedPid` 子配置对象（默认 `{}`），为可信 PID 策略（`applyTrustedPidCfg`、`shouldSkipTrustedEvent`）提供统一的配置读取入口，避免在多处做对象形状判断。
 * - Purpose: Safely extracts the `trustedPid` sub-config object from `filters` (defaults to `{}`), providing a single config-read entry for the trusted-PID policy (`applyTrustedPidCfg`, `shouldSkipTrustedEvent`) and avoiding repeated shape checks across call sites.
 * - 调用方: `applyTrustedPidCfg`（读取配置并配置 `trustedPidFilter`）、`shouldSkipTrustedEvent`（读取 enabled 开关等策略字段）。
 * - Callers: `applyTrustedPidCfg` (reads config and configures `trustedPidFilter`), `shouldSkipTrustedEvent` (reads enabled toggle and policy fields).
 * - 被调方: 无（仅做对象判定与字段返回）。
 * - Callees: None (object shape checks and field return only).
 * - 变量说明: `filters` 通常来自 `etwCfg.filters`；返回值为 `filters.trustedPid`（当其为对象时）或空对象；调用方应将返回值视为只读配置，不在此处进行写入。
 * - Variables: `filters` typically comes from `etwCfg.filters`; returns `filters.trustedPid` when it is an object, otherwise an empty object; callers should treat it as read-only config and avoid mutating it.
 * - 接入方式: 在任何需要读取 trustedPid 配置字段时先调用本函数；若未来 trustedPid 配置结构演进（字段迁移/默认值变化），优先在本函数集中适配。
 * - Integration: Call it whenever reading trustedPid fields; if the trustedPid config evolves (field migrations/default changes), adapt centrally here first.
 * - 错误处理: 本函数不抛异常；对非对象输入回退为 `{}`，保证上游过滤链路不会因配置形状异常而崩溃。
 * - Error Handling: Never throws; falls back to `{}` for non-object inputs so upstream filtering does not crash on malformed config.
 * - 关键词: trustedPid配置 | trustedPid config | etwCfg.filters | applyTrustedPidCfg | shouldSkipTrustedEvent | 形状校验 | shape check | 默认空对象 | default empty object | 配置读取入口 | config accessor | 容错 | tolerant
 */
function getTrustedPidCfg(filters) {
    const f = (filters && typeof filters === 'object') ? filters : {};
    return (f.trustedPid && typeof f.trustedPid === 'object') ? f.trustedPid : {};
}

/**
 * - 函数: `applyTrustedPidCfg`
 * - Function: `applyTrustedPidCfg`
 * - 作用: 将 `filters.trustedPid` 配置应用到 worker 运行态：配置 `trustedPidFilter` 的判定规则与用户可信路径，并同步更新 `extraTrustedPids` 与 `trustedSkipProviders` 两个集合，为 `shouldSkipTrustedEvent` 提供稳定、集中、可复用的可信降噪策略输入。
 * - Purpose: Applies the `filters.trustedPid` config to the worker runtime: configures `trustedPidFilter` rules and user trusted paths, and refreshes the `extraTrustedPids` and `trustedSkipProviders` sets, providing stable centralized inputs for `shouldSkipTrustedEvent`.
 * - 调用方: `resolveEtwCfg`（在合并默认配置/文件配置/入参配置后调用一次，确保可信策略与最终配置一致）。
 * - Callers: `resolveEtwCfg` (invoked once after merging default/file/incoming configs so trust policy matches the effective config).
 * - 被调方: `getTrustedPidCfg`、`trustedPidFilter.configure`、`trustedPidFilter.setUserTrustedPaths`、`Set`、`Array.isArray`、`String(...)`、`String.prototype.trim`、`String.prototype.toLowerCase`、`asPid`。
 * - Callees: `getTrustedPidCfg`, `trustedPidFilter.configure`, `trustedPidFilter.setUserTrustedPaths`, `Set`, `Array.isArray`, `String(...)`, `String.prototype.trim`, `String.prototype.toLowerCase`, `asPid`.
 * - 变量说明: `filters` 通常为 `etwCfg.filters`；`cfg` 为 `getTrustedPidCfg(filters)` 的返回；`extraTrustedPids` 用于补充可信 PID；`trustedSkipProviders` 为可选 provider 白名单集合（配合 `extraTrustedPids` 控制哪些 provider 事件可被跳过）。
 * - Variables: `filters` is typically `etwCfg.filters`; `cfg` is returned by `getTrustedPidCfg(filters)`; `extraTrustedPids` holds additional trusted PIDs; `trustedSkipProviders` is an optional provider allow-set (used with `extraTrustedPids` to decide which provider events are skippable).
 * - 接入方式: 每次更新/重载 ETW 配置后调用一次即可（通常由 `resolveEtwCfg` 统一触发）；若未来支持运行中动态更新 trustedPid 策略，应复用本函数完成“配置 → 运行态集合”的原子刷新，避免与 `shouldSkipTrustedEvent` 产生短暂不一致。
 * - Integration: Call once after ETW config updates/reloads (normally centralized in `resolveEtwCfg`); if runtime updates are introduced later, reuse this function to refresh “config → runtime sets” atomically to avoid transient inconsistency with `shouldSkipTrustedEvent`.
 * - 错误处理: `trustedPidFilter.configure` 与 `setUserTrustedPaths` 使用 `try/catch` 以兼容能力缺失或异常配置；无论成功与否都会重建 `extraTrustedPids` 并重置 `trustedSkipProviders`，对无效条目进行跳过；不抛异常以保证配置合并链路稳定。
 * - Error Handling: Wraps `trustedPidFilter.configure` and `setUserTrustedPaths` in `try/catch` to tolerate missing capability or malformed config; always rebuilds `extraTrustedPids` and resets `trustedSkipProviders`, skipping invalid entries; never throws to keep the config-merge pipeline stable.
 * - 关键词: 可信策略应用 | trust policy apply | applyTrustedPidCfg | trustedPidFilter.configure | userTrustedPaths | extraTrustedPids | provider白名单 | provider allowlist | 配置到运行态 | config-to-runtime | shouldSkipTrustedEvent | 降噪 | noise reduction | 幂等刷新 | idempotent refresh
 */
function applyTrustedPidCfg(filters) {
    const cfg = getTrustedPidCfg(filters);
    try { trustedPidFilter.configure(cfg); } catch {}
    try { trustedPidFilter.setUserTrustedPaths(cfg.userTrustedPaths); } catch {}
    extraTrustedPids = new Set();
    trustedSkipProviders = null;
    if (cfg && Array.isArray(cfg.skipProviders)) {
        const set = new Set();
        for (const it of cfg.skipProviders) {
            const s = String(it || '').trim().toLowerCase();
            if (s) set.add(s);
        }
        trustedSkipProviders = set;
    }
    const list = Array.isArray(cfg.extraTrustedPids) ? cfg.extraTrustedPids : [];
    for (const it of list) {
        const p = asPid(it);
        if (p != null) extraTrustedPids.add(p);
    }
}

/**
 * - 函数: `shouldSkipTrustedEvent`
 * - Function: `shouldSkipTrustedEvent`
 * - 作用: 根据“可信 PID”策略判断是否跳过当前事件：先尊重配置开关（trustedPid.enabled），再结合 `trustedPidFilter` 的规则与 `extraTrustedPids` / `trustedSkipProviders` 白名单/黑名单集合，过滤来自可信进程的事件以降低噪音。
 * - Purpose: Decides whether to skip an event based on the “trusted PID” policy: honors the config switch (trustedPid.enabled) first, then applies `trustedPidFilter` rules plus `extraTrustedPids` / `trustedSkipProviders` allow/deny sets to filter events from trusted processes and reduce noise.
 * - 调用方: `handleBridgeMessage`（bridge 消息入站过滤）、`createEventCallback`（原生 ETW 回调入站过滤）。
 * - Callers: `handleBridgeMessage` (bridge-ingress filtering), `createEventCallback` (native ETW callback ingress filtering).
 * - 被调方: `getTrustedPidCfg`、`trustedPidFilter.shouldSkipEvent`、`getRelevantPidForEvent`、`extraTrustedPids.has`、`String.prototype.trim`、`String.prototype.toLowerCase`、`trustedSkipProviders.has`。
 * - Callees: `getTrustedPidCfg`, `trustedPidFilter.shouldSkipEvent`, `getRelevantPidForEvent`, `extraTrustedPids.has`, `String.prototype.trim`, `String.prototype.toLowerCase`, `trustedSkipProviders.has`.
 * - 变量说明: `ev` 为待判定的事件对象；`filters`/`cfg` 来自 `etwCfg.filters.trustedPid`；`pid` 为事件关联 PID（由 `getRelevantPidForEvent` 推导）；`extraTrustedPids` 为额外可信 PID 集合；`trustedSkipProviders` 为可选 provider 白名单集合（为空时默认全跳过）。
 * - Variables: `ev` is the event to evaluate; `filters`/`cfg` are resolved from `etwCfg.filters.trustedPid`; `pid` is the relevant PID derived by `getRelevantPidForEvent`; `extraTrustedPids` is the additional trusted PID set; `trustedSkipProviders` is an optional provider allow-set (when absent, skip all trusted events).
 * - 接入方式: 在任何入站事件进入上行 `postMessage({type:'log', event})` 之前调用；新增可信策略字段（如按路径/签名细分）时应优先扩展 `trustedPidFilter` 或本函数的集合判断，而不要把可信过滤分散到多个 provider 分支里。
 * - Integration: Call it before forwarding any inbound event via `postMessage({type:'log', event})`; when adding new trust policy dimensions (path/signature), extend `trustedPidFilter` or this function’s set checks rather than scattering trust filtering across provider branches.
 * - 错误处理: 若配置显式关闭（`enabled === false`）则不跳过；`trustedPidFilter.shouldSkipEvent` 的异常会被吞掉并继续后续逻辑；无法解析 PID 时不跳过；对 provider 为空的事件保守地选择跳过（当命中可信 PID 且存在 provider 白名单时）。
 * - Error Handling: If config explicitly disables the feature (`enabled === false`), never skip; exceptions from `trustedPidFilter.shouldSkipEvent` are swallowed and evaluation continues; events without a resolvable PID are not skipped; for empty providers it conservatively skips when the PID is trusted and provider allow-set is being used.
 * - 关键词: 可信PID过滤 | trusted PID filter | shouldSkipTrustedEvent | trustedPidFilter | extraTrustedPids | trustedSkipProviders | provider白名单 | provider allowlist | 降噪 | noise reduction | handleBridgeMessage | createEventCallback | 事件入站 | event ingress | 配置开关 | config toggle | etwCfg.filters | 策略集中 | centralized policy
 */
function shouldSkipTrustedEvent(ev) {
    const filters = (etwCfg && etwCfg.filters && typeof etwCfg.filters === 'object') ? etwCfg.filters : {};
    const cfg = getTrustedPidCfg(filters);
    if (cfg && cfg.enabled === false) return false;
    try {
        if (trustedPidFilter.shouldSkipEvent(ev)) return true;
    } catch {}
    const pid = getRelevantPidForEvent(ev);
    if (pid == null) return false;
    if (!extraTrustedPids.has(pid)) return false;
    if (!trustedSkipProviders) return true;
    const provider = (ev && typeof ev.provider === 'string') ? ev.provider.trim().toLowerCase() : '';
    if (!provider) return true;
    return trustedSkipProviders.has(provider);
}

const DEFAULT_ETW_CFG = {
    enabled: true,
    sessionName: 'AnXinSecuritySession',
    userDataMaxBytes: 52428800,
    stopTimeoutMs: 2500,
    startRetries: 2,
    retryDelayMs: 150,
    emitRegistryRawHex: false,
    providers: {
        Process: { anyKeyword: '0x0', allKeyword: '0x0' },
        File: { anyKeyword: '0xFFFFFFFFFFFFFFFF', allKeyword: '0x0' },
        Registry: { anyKeyword: '0x0', allKeyword: '0x0' },
        Network: { anyKeyword: '0x0', allKeyword: '0x0' }
    },
    network: {
        enabled: true,
        filterPrivateIps: true,
        skipLoopback: true
    }
};

/**
 * - 函数: `canonicalProviderKey`
 * - Function: `canonicalProviderKey`
 * - 作用: 将配置中的 provider key（不区分大小写）归一化为内部统一的 provider 名称：`Process`/`File`/`Registry`/`Network`；用于配置合并与 provider 规则解析，避免大小写/别名差异导致配置失效。
 * - Purpose: Canonicalizes provider keys (case-insensitive) into internal normalized provider names: `Process`/`File`/`Registry`/`Network`; used by config merging and provider-rule parsing to prevent case/alias differences from breaking configuration.
 * - 调用方: `normalizeProvidersObj`（遍历 providers 配置对象时逐项归一化 key）。
 * - Callers: `normalizeProvidersObj` (normalizes each key while iterating providers config objects).
 * - 被调方: `String(...)`、`String.prototype.trim`、`String.prototype.toLowerCase`。
 * - Callees: `String(...)`, `String.prototype.trim`, `String.prototype.toLowerCase`.
 * - 变量说明: `k` 为输入的 provider key（可能为任意类型）；`s` 为规整后的小写字符串；返回值为规范 provider 名称或 `null`（无法识别/为空）。
 * - Variables: `k` is the input provider key (may be any type); `s` is the normalized lowercase string; returns the canonical provider name or `null` (unknown/empty).
 * - 接入方式: 仅用于解析/合并配置对象的 key；当新增 provider（或允许更多别名）时，应在此处扩展映射以保持配置入口统一，不要在多处散落字符串比较。
 * - Integration: Use it for parsing/merging provider config keys only; when adding providers (or supporting more aliases), extend mappings here to keep config entrypoints unified and avoid scattered string comparisons.
 * - 错误处理: 不抛异常；对未知 key 返回 `null` 以让上层忽略该项；这保证即使配置文件包含拼写错误也不会导致 worker 启动失败。
 * - Error Handling: Never throws; returns `null` for unknown keys so callers can ignore them; this prevents typos in config files from breaking worker startup.
 * - 关键词: provider归一化 | provider canonicalization | canonicalProviderKey | Process/File/Registry/Network | 配置解析 | config parsing | 大小写无关 | case-insensitive | 别名映射 | alias mapping | normalizeProvidersObj | 安全忽略 | safe ignore | 兼容性 | compatibility
 */
function canonicalProviderKey(k) {
    const s = String(k || '').trim().toLowerCase();
    if (s === 'process') return 'Process';
    if (s === 'file') return 'File';
    if (s === 'registry') return 'Registry';
    if (s === 'network') return 'Network';
    return null;
}

/**
 * - 函数: `normalizeProvidersObj`
 * - Function: `normalizeProvidersObj`
 * - 作用: 将输入的 providers 配置对象归一化为内部结构：只保留可识别的 provider（Process/File/Registry/Network），并对每个 provider 的值做浅拷贝，避免上游对象被后续合并逻辑意外修改。
 * - Purpose: Normalizes an input providers config object into the internal shape: keeps only recognized providers (Process/File/Registry/Network) and shallow-copies each provider value to avoid accidental mutation of upstream objects during later merges.
 * - 调用方: `mergeProviders`（合并 default/file/incoming providers 前分别对每份输入做归一化）。
 * - Callers: `mergeProviders` (normalizes each input set before merging default/file/incoming providers).
 * - 被调方: `Object.keys`、`canonicalProviderKey`、对象展开 `{ ...v }`。
 * - Callees: `Object.keys`, `canonicalProviderKey`, object spread `{ ...v }`.
 * - 变量说明: `obj` 为输入 providers 配置（任意对象或空）；`out` 为归一化输出对象；`k` 为遍历的原始 key；`ck` 为 canonical provider key；`v` 为 provider 对应的配置对象。
 * - Variables: `obj` is the input providers config (any object or nullish); `out` is the normalized output; `k` is the raw iterated key; `ck` is the canonical provider key; `v` is the provider config object.
 * - 接入方式: 作为 providers 配置合并前的标准入口使用；如果允许配置里出现大小写/别名（例如 process/PROCESS），应依赖 `canonicalProviderKey` 的映射能力而不是在上层重复处理。
 * - Integration: Use it as the standard pre-merge entry for providers configs; if configs can contain case/alias variants (e.g., process/PROCESS), rely on `canonicalProviderKey` instead of duplicating normalization upstream.
 * - 错误处理: 非对象输入直接返回空对象；未知 provider key 直接跳过；仅当 provider 值为对象时才拷贝写入，避免把非对象值带入后续合并；函数不抛异常以保证配置解析链路稳定。
 * - Error Handling: Returns `{}` for non-object input; skips unknown provider keys; only copies provider values when they are objects to avoid carrying invalid values into later merges; never throws to keep config parsing stable.
 * - 关键词: providers归一化 | providers normalization | normalizeProvidersObj | canonicalProviderKey | Process/File/Registry/Network | 浅拷贝 | shallow copy | 配置合并前置 | pre-merge | mergeProviders | 安全过滤 | safe filtering | 防止变异 | avoid mutation
 */
function normalizeProvidersObj(obj) {
    const out = {};
    if (!obj || typeof obj !== 'object') return out;
    for (const k of Object.keys(obj)) {
        const ck = canonicalProviderKey(k);
        if (!ck) continue;
        const v = obj[k];
        if (v && typeof v === 'object') out[ck] = { ...v };
    }
    return out;
}

/**
 * - 函数: `mergeProviders`
 * - Function: `mergeProviders`
 * - 作用: 合并三份 providers 配置（默认/文件/入参），并确保输出包含固定四类 provider key（Process/File/Registry/Network）；后写入者优先覆盖同名字段，用于构建最终生效的 ETW provider 监听参数。
 * - Purpose: Merges three providers configs (default/file/incoming) and ensures the output contains the fixed four provider keys (Process/File/Registry/Network); later inputs override earlier fields, producing the effective ETW provider listening parameters.
 * - 调用方: `resolveEtwCfg`（合并默认配置、配置文件与主进程下发配置时调用）。
 * - Callers: `resolveEtwCfg` (invoked while merging defaults, file config, and main-process payload config).
 * - 被调方: `normalizeProvidersObj`。
 * - Callees: `normalizeProvidersObj`.
 * - 变量说明: `base` 为默认 providers；`fromFile` 为配置文件 providers；`incoming` 为主进程下发 providers；`b/f/i` 为归一化后的输入；`keys` 为固定 provider 列表；`out` 为合并结果。
 * - Variables: `base` is default providers; `fromFile` is providers from config file; `incoming` is providers from main-process payload; `b/f/i` are normalized inputs; `keys` is the fixed provider list; `out` is the merged result.
 * - 接入方式: 作为 providers 合并的唯一入口；如果未来新增 provider 类别，应同步更新 `canonicalProviderKey`、`normalizeProvidersObj` 与本函数的 `keys` 列表，确保配置解析与合并一致。
 * - Integration: Treat it as the single entry for providers merging; if new provider categories are added later, update `canonicalProviderKey`, `normalizeProvidersObj`, and this function’s `keys` list together to keep parsing and merging consistent.
 * - 错误处理: 输入会先经 `normalizeProvidersObj` 过滤无效 key/值；合并过程中不抛异常；对缺失 provider 会自动补空对象，保证下游读取稳定且输出结构固定。
 * - Error Handling: Inputs are sanitized via `normalizeProvidersObj` before merging; the merge path does not throw; missing providers are filled with empty objects so downstream reads remain stable and output shape stays fixed.
 * - 关键词: providers合并 | providers merge | mergeProviders | resolveEtwCfg | 覆盖优先 | override | 结构固定 | fixed shape | Process/File/Registry/Network | normalizeProvidersObj | 配置优先级 | config precedence | ETW providers | 监听参数 | listen parameters
 */
function mergeProviders(base, fromFile, incoming) {
    const b = normalizeProvidersObj(base);
    const f = normalizeProvidersObj(fromFile);
    const i = normalizeProvidersObj(incoming);
    const keys = ['Process', 'File', 'Registry', 'Network'];
    const out = {};
    for (const k of keys) {
        out[k] = { ...(b[k] || {}), ...(f[k] || {}), ...(i[k] || {}) };
    }
    return out;
}

/**
 * - 函数: `parseKeyword64`
 * - Function: `parseKeyword64`
 * - 作用: 将 provider 关键字参数规整为无符号 64 位的 `BigInt`：支持 bigint/number/string 输入，字符串可为十进制或 `0x...` 形式；非法输入回退为 `0n`，用于构建 ETW provider 的 any/all keyword 掩码。
 * - Purpose: Normalizes provider keyword parameters into an unsigned 64-bit `BigInt`: accepts bigint/number/string inputs, with strings in decimal or `0x...` form; invalid inputs fall back to `0n`, used to build ETW provider any/all keyword masks.
 * - 调用方: `getProviderKeywords`（读取 providers 配置并解析 anyKeyword/allKeyword 字段）。
 * - Callers: `getProviderKeywords` (reads provider config and parses anyKeyword/allKeyword fields).
 * - 被调方: `BigInt(...)`、`Number.isFinite`、`Math.floor`、`String.prototype.trim`。
 * - Callees: `BigInt(...)`, `Number.isFinite`, `Math.floor`, `String.prototype.trim`.
 * - 变量说明: `v` 为输入值（bigint/number/string/其他）；`s` 为字符串输入的 trim 结果；返回值为非负 BigInt（`0n` 表示默认/无关键字）。
 * - Variables: `v` is the input (bigint/number/string/other); `s` is the trimmed string form; return value is a non-negative BigInt (`0n` means default/no keywords).
 * - 接入方式: 在任何需要把配置中的 keyword 字段转换为 ETW 所需数值类型时复用本函数；避免在调用处直接 `BigInt(v)` 以防抛异常导致启动链路中断。
 * - Integration: Reuse this function whenever converting keyword fields from config into ETW numeric types; avoid calling `BigInt(v)` directly at call sites because it can throw and break the startup chain.
 * - 错误处理: 对 `bigint` 原样返回；对 `number` 仅接受有限且非负值并取整；对 `string` 空串返回 `0n`，解析失败捕获后返回 `0n`；不抛异常以保证 provider 配置解析健壮。
 * - Error Handling: Returns input as-is for `bigint`; for `number` accepts only finite non-negative values and floors them; for `string` returns `0n` on empty, and catches parse failures to return `0n`; never throws to keep provider-config parsing robust.
 * - 关键词: keyword解析 | keyword parsing | parseKeyword64 | BigInt | anyKeyword/allKeyword | ETW掩码 | ETW mask | 0x十六进制 | hex string | 容错 | tolerant | 配置解析 | config parsing | getProviderKeywords | 启动健壮性 | startup robustness
 */
function parseKeyword64(v) {
    if (typeof v === 'bigint') return v;
    if (typeof v === 'number' && Number.isFinite(v) && v >= 0) return BigInt(Math.floor(v));
    const s = (typeof v === 'string') ? v.trim() : '';
    if (!s) return 0n;
    try {
        return BigInt(s);
    } catch {
        return 0n;
    }
}

/**
 * - 函数: `getProviderKeywords`
 * - Function: `getProviderKeywords`
 * - 作用: 从 `cfg.providers[providerKey]` 读取 provider 关键字配置，并将 `anyKeyword/allKeyword` 通过 `parseKeyword64` 解析为 `BigInt`，以便 `EtwBridge_Start` 直接使用统一的 64 位关键字掩码。
 * - Purpose: Reads provider keyword config from `cfg.providers[providerKey]` and parses `anyKeyword/allKeyword` into `BigInt` via `parseKeyword64` so `EtwBridge_Start` can consume a unified 64-bit keyword mask.
 * - 调用方: `startSessionOnce`（为 Process/File/Registry/Network 四类 provider 构建关键字参数）。
 * - Callers: `startSessionOnce` (builds keyword parameters for Process/File/Registry/Network providers).
 * - 被调方: `parseKeyword64`。
 * - Callees: `parseKeyword64`.
 * - 变量说明: `cfg` 为当前 ETW 配置对象；`providerKey` 为 provider 名（例如 `'Process'`）；`providers` 为 `cfg.providers` 的对象守卫结果；`p` 为 `providers[providerKey]` 的对象守卫结果；返回值为 `{ any: BigInt, all: BigInt }`。
 * - Variables: `cfg` is the current ETW config object; `providerKey` is the provider name (e.g. `'Process'`); `providers` is the guarded object form of `cfg.providers`; `p` is the guarded object form of `providers[providerKey]`; return value is `{ any: BigInt, all: BigInt }`.
 * - 接入方式: 在需要读取 providers 配置并生成关键字掩码的地方调用；新增 provider 类别时应确保 `providerKey` 与 `mergeProviders/canonicalProviderKey` 的 key 保持一致，避免取不到配置导致默认关键字 `0n`。
 * - Integration: Call it wherever providers config needs to be read and converted into keyword masks; when adding new provider categories, keep `providerKey` consistent with `mergeProviders/canonicalProviderKey` keys to avoid falling back to the default `0n` keywords.
 * - 错误处理: `cfg/providers/p` 非对象时回退为空对象并最终返回 `{ any: 0n, all: 0n }`；关键字解析异常由 `parseKeyword64` 内部吞掉并回退为 `0n`，本函数不抛异常以保证启动链路稳定。
 * - Error Handling: Falls back to empty objects when `cfg/providers/p` are not objects, ultimately returning `{ any: 0n, all: 0n }`; keyword parsing errors are swallowed by `parseKeyword64` and fall back to `0n`, and this function never throws to keep the startup chain stable.
 * - 关键词: provider关键字 | provider keywords | getProviderKeywords | parseKeyword64 | anyKeyword | allKeyword | BigInt掩码 | BigInt mask | EtwBridge_Start | startSessionOnce | 配置守卫 | config guards | 64位关键字 | 64-bit keywords
 */
function getProviderKeywords(cfg, providerKey) {
    const providers = (cfg && cfg.providers && typeof cfg.providers === 'object') ? cfg.providers : {};
    const p = (providers && providers[providerKey] && typeof providers[providerKey] === 'object') ? providers[providerKey] : {};
    return { any: parseKeyword64(p.anyKeyword), all: parseKeyword64(p.allKeyword) };
}

/**
 * - 函数: `loadAppConfig`
 * - Function: `loadAppConfig`
 * - 作用: 从 `config/app.json` 读取并解析应用配置（JSON），返回对象形式的配置根节点，供 `resolveEtwCfg` 做 ETW 配置合并与归一化的输入来源之一。
 * - Purpose: Loads and parses the app configuration from `config/app.json` (JSON) and returns the root config object, used by `resolveEtwCfg` as one of the sources for ETW config merging/normalization.
 * - 调用方: `resolveEtwCfg`（读取文件配置后与默认/入参配置做层叠合并）。
 * - Callers: `resolveEtwCfg` (loads file config and overlays it with defaults/payload).
 * - 被调方: `path.join`、`fs.readFileSync`、`JSON.parse`。
 * - Callees: `path.join`, `fs.readFileSync`, `JSON.parse`.
 * - 变量说明: `p` 为 `app.json` 的绝对路径；`raw` 为读取到的 JSON 字符串。
 * - Variables: `p` is the absolute path to `app.json`; `raw` is the loaded JSON string.
 * - 接入方式: 仅建议通过 `resolveEtwCfg` 间接使用；若配置文件路径或加载策略调整（例如迁移到其他目录或引入多配置层级），应优先修改本函数以维持单一配置读取入口。
 * - Integration: Prefer using it indirectly via `resolveEtwCfg`; if the config file location or loading strategy changes (e.g., moving directories or introducing multiple layers), update this function to keep a single config-loading entry.
 * - 错误处理: 读取或解析失败（文件不存在、权限、JSON 非法等）会被捕获并回退为 `{}`；本函数不抛异常，避免配置文件问题阻断 ETW 启动链路。
 * - Error Handling: Read/parse failures (missing file, permissions, invalid JSON, etc.) are caught and fall back to `{}`; the function never throws to avoid breaking the ETW startup chain due to config issues.
 * - 关键词: 配置加载 | config loading | loadAppConfig | app.json | JSON解析 | JSON parse | resolveEtwCfg | 文件读取 | file read | 容错回退 | fallback | ETW配置 | ETW config | 启动链路 | startup chain
 */
function loadAppConfig() {
    const p = path.join(__dirname, '../../../config/app.json');
    try {
        const raw = fs.readFileSync(p, 'utf-8');
        return JSON.parse(raw);
    } catch {
        return {};
    }
}

/**
 * - 函数: `resolveEtwCfg`
 * - Function: `resolveEtwCfg`
 * - 作用: 合并并归一化 ETW 配置：读取 `config/app.json` 的文件配置，与默认配置 `DEFAULT_ETW_CFG` 和主进程下发的 `payloadCfg` 做层叠合并；同步合并 filters（含兼容字段 `behaviorAnalyzer.filters`）；对关键数值进行边界裁剪；合并 network 子配置；最后通过 `mergeProviders` 固化 providers 结构，并调用 `applyTrustedPidCfg` 应用可信 PID 策略。
 * - Purpose: Merges and normalizes the ETW configuration: loads file config from `config/app.json`, overlays it with defaults `DEFAULT_ETW_CFG` and the main-process payload `payloadCfg`; merges filters (including the legacy `behaviorAnalyzer.filters`); clamps critical numeric fields; merges the `network` sub-config; then fixes the providers shape via `mergeProviders` and applies trusted-PID policy via `applyTrustedPidCfg`.
 * - 调用方: `startWithRetry`（每次启动/重试前生成生效配置）、`parentPort.on('message')` 的 `config` 分支（热更新配置）。
 * - Callers: `startWithRetry` (builds the effective config before each start/retry), the `config` branch inside `parentPort.on('message')` (hot config refresh).
 * - 被调方: `loadAppConfig`、`mergeProviders`、`applyTrustedPidCfg`、`String#trim`、`Number.isFinite`、`Math.max/min/floor`、对象展开 `{ ... }`。
 * - Callees: `loadAppConfig`, `mergeProviders`, `applyTrustedPidCfg`, `String#trim`, `Number.isFinite`, `Math.max/min/floor`, object spread `{ ... }`.
 * - 变量说明: `payloadCfg` 为主进程下发配置；`fromFile` 为从文件读取的 app 配置；`etw` 为文件配置中的 `cfg.etw`；`incoming` 为规范化后的 `payloadCfg`；`filters` 为兼容+文件+入参三路合并结果；`merged` 为最终 ETW 配置；`network` 为合并后的网络子配置。
 * - Variables: `payloadCfg` is the main-process payload config; `fromFile` is the app config loaded from disk; `etw` is `cfg.etw` from file config; `incoming` is the normalized payload; `filters` is the merged result from legacy+file+payload sources; `merged` is the final ETW config; `network` is the merged network sub-config.
 * - 接入方式: 作为 ETW 配置生效的唯一入口使用；新增配置字段时应在本函数中明确“来源优先级”和“边界裁剪规则”，避免把未经校验的值直接下发到 bridge 层。
 * - Integration: Use it as the single entry for effective ETW config; when adding new config fields, define the precedence and clamping rules here to avoid sending unvalidated values to the bridge layer.
 * - 错误处理: 读取配置文件失败由 `loadAppConfig` 内部回退为 `{}`；本函数对输入做对象守卫并提供默认值/边界裁剪，整体不抛异常，确保 ETW 启动链路在配置不完整或字段类型异常时仍可稳定运行。
 * - Error Handling: File read failures fall back to `{}` inside `loadAppConfig`; this function guards input types and provides defaults/clamps, and it does not throw so the ETW startup chain remains stable even with incomplete/malformed configs.
 * - 关键词: ETW配置合并 | ETW config merge | resolveEtwCfg | DEFAULT_ETW_CFG | payloadCfg | filters合并 | filters merge | mergeProviders | providers结构 | providers shape | applyTrustedPidCfg | network配置 | network config | 边界裁剪 | clamping | 配置归一化 | normalization
 */
function resolveEtwCfg(payloadCfg) {
    const fromFile = loadAppConfig();
    const cfg = (fromFile && typeof fromFile === 'object' ? fromFile : {});
    const etw = (cfg.etw && typeof cfg.etw === 'object') ? cfg.etw : {};
    const incoming = (payloadCfg && typeof payloadCfg === 'object') ? payloadCfg : {};
    const fileEtwFilters = (etw.filters && typeof etw.filters === 'object') ? etw.filters : {};
    const compatFilters = (cfg.behaviorAnalyzer && cfg.behaviorAnalyzer.filters && typeof cfg.behaviorAnalyzer.filters === 'object') ? cfg.behaviorAnalyzer.filters : {};
    const incomingFilters = (incoming.filters && typeof incoming.filters === 'object') ? incoming.filters : {};
    const filters = { ...compatFilters, ...fileEtwFilters, ...incomingFilters };

    const merged = { ...DEFAULT_ETW_CFG, ...etw, ...incoming };
    merged.filters = filters;
    merged.enabled = merged.enabled !== false;
    merged.sessionName = typeof merged.sessionName === 'string' && merged.sessionName.trim() ? merged.sessionName.trim() : DEFAULT_ETW_CFG.sessionName;
    merged.userDataMaxBytes = Number.isFinite(merged.userDataMaxBytes) ? Math.max(1024, Math.min(50 * 1024 * 1024, merged.userDataMaxBytes)) : DEFAULT_ETW_CFG.userDataMaxBytes;
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

    merged.providers = mergeProviders(DEFAULT_ETW_CFG.providers, etw.providers, incoming.providers);

    applyTrustedPidCfg(merged.filters);
    return merged;
}

/**
 * - 函数: `postMessage`
 * - Function: `postMessage`
 * - 作用: 作为 ETW worker 向主进程回传消息的统一出口，在实际 `parentPort.postMessage` 前对日志事件做最小清洗，去除 provider/data 中的非法控制字符，降低跨线程序列化和前端展示噪音。
 * - Purpose: Acts as the unified outbound channel from the ETW worker to the main process and performs minimal sanitization on log events before `parentPort.postMessage`, stripping invalid control characters to reduce serialization/display noise.
 * - 调用方: `handleBridgeMessage`、`postError`、`createEventCallback`、`startWithRetry`、`startSessionOnce`，以及 `pause/resume` 控制分支中的状态反馈。
 * - Callers: Used by `handleBridgeMessage`, `postError`, `createEventCallback`, `startWithRetry`, `startSessionOnce`, and status replies in the `pause`/`resume` control branches.
 * - 被调方: `String`、`replace`、`trim`、`parentPort.postMessage`。
 * - Callees: `String`, `replace`, `trim`, `parentPort.postMessage`.
 * - 变量说明: `msg` 为即将发送到主进程的消息对象；`ev` 为 `log` 类型中的事件负载；`k` 为遍历 `ev.data` 时的字段名，用于逐项清洗字符串值。
 * - Variables: `msg` is the outbound message object, `ev` is the event payload inside `log` messages, and `k` iterates over `ev.data` fields so each string value can be sanitized.
 * - 接入方式: 作为本 worker 唯一推荐的上行消息出口；新增状态、错误或事件通知时应优先走 `postMessage`，避免绕过清洗逻辑直接操作 `parentPort.postMessage`。
 * - Integration: Treat it as the preferred outbound path for this worker; new status, error, or event notifications should go through `postMessage` instead of calling `parentPort.postMessage` directly so sanitization remains centralized.
 * - 错误处理: 若 `parentPort` 不存在则直接返回，不抛出异常；函数本身不包裹发送异常，默认让调用方或 worker 运行时感知底层通信失败。
 * - Error Handling: It returns immediately when `parentPort` is unavailable and does not throw; send failures are not swallowed here, allowing callers or the worker runtime to observe lower-level IPC issues.
 * - 关键词: 上行消息 | outbound message | 日志清洗 | log sanitization | 控制字符 | control characters | 主线程通信 | main-thread IPC | ETW worker出口 | ETW worker egress
 */
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

/**
 * - 函数: `postError`
 * - Function: `postError`
 * - 作用: 将 worker 内部错误统一封装为 `{ type:'error', code, message, details }` 并通过 `postMessage` 回传主进程，用于 UI/日志层记录与控制链路降级决策。
 * - Purpose: Wraps worker-side errors into `{ type:'error', code, message, details }` and sends them to the main process via `postMessage`, enabling UI/log recording and control-flow degradation decisions.
 * - 调用方: `ensureEtwBridgeLoaded`/`ensureEtwBridgeHandle`（加载/创建失败上报）、`drainBridgeMessages`（轮询/解析异常）、`handleBridgeMessage`（事件处理异常）、`createEventCallback`、`checkStatus` 等错误分支。
 * - Callers: Error branches in `ensureEtwBridgeLoaded`/`ensureEtwBridgeHandle` (load/create failures), `drainBridgeMessages` (poll/parse failures), `handleBridgeMessage` (event handling failures), `createEventCallback`, `checkStatus`, etc.
 * - 被调方: `String(...)`、`postMessage`。
 * - Callees: `String(...)`, `postMessage`.
 * - 变量说明: `code` 为错误码（缺省为 `'ETW_ERROR'`）；`message` 为人类可读错误文本（会被 `String(...)` 规整）；`details` 为可选附加对象（用于携带路径、返回码、上下文）。
 * - Variables: `code` is the error code (defaults to `'ETW_ERROR'`); `message` is human-readable text normalized via `String(...)`; `details` is an optional object for extra context (paths, return codes, environment).
 * - 接入方式: 在任意需要向主进程报告错误但不希望 throw 终止 worker 的地方调用 `postError(code, message, details)`；主进程侧应监听 `msg.type === 'error'` 并决定是否重启/停止/降级。
 * - Integration: Call `postError(code, message, details)` wherever you need to report an error to the main process without throwing and terminating the worker; the main process should handle `msg.type === 'error'` and decide whether to restart/stop/degrade.
 * - 错误处理: 本函数自身不抛异常；`details` 仅在为对象时才挂载以避免非序列化数据；最终发送由 `postMessage` 承担，其内部会处理 `parentPort` 缺失场景。
 * - Error Handling: This function never throws; `details` is attached only when it is an object to avoid non-serializable data; actual sending is handled by `postMessage`, which already guards against missing `parentPort`.
 * - 关键词: 错误上报 | error reporting | ETW worker | postMessage | error code | details上下文 | 主进程通知 | main-process notify | 降级 | degrade | ETW_BRIDGE_* | bridge failures
 */
function postError(code, message, details) {
    const payload = { type: 'error', code: code || 'ETW_ERROR', message: String(message || '') };
    if (details && typeof details === 'object') payload.details = details;
    postMessage(payload);
}

/**
 * - 函数: `sleepSync`
 * - Function: `sleepSync`
 * - 作用: 在 ETW worker 内执行同步阻塞等待，用于 `startWithRetry` 的重试间隔；通过 `Atomics.wait` 在不引入额外依赖的情况下实现可控的同步 sleep。
 * - Purpose: Performs a synchronous blocking wait inside the ETW worker, used as the retry delay in `startWithRetry`; implements a controllable sync sleep via `Atomics.wait` without extra dependencies.
 * - 调用方: `startWithRetry`（一次启动失败后等待 `retryDelayMs` 再重试）。
 * - Callers: `startWithRetry` (waits `retryDelayMs` between failed attempts).
 * - 被调方: `Math.max`、`Math.floor`、`Int32Array`、`SharedArrayBuffer`、`Atomics.wait`。
 * - Callees: `Math.max`, `Math.floor`, `Int32Array`, `SharedArrayBuffer`, `Atomics.wait`.
 * - 变量说明: `ms` 为期望等待毫秒；`dur` 为规整后的非负整数等待时长；`arr` 为 `Atomics.wait` 所需的共享内存视图。
 * - Variables: `ms` is the requested delay in milliseconds; `dur` is the normalized non-negative integer delay; `arr` is the shared-memory view required by `Atomics.wait`.
 * - 接入方式: 仅适用于 worker 线程的“启动重试退避”场景；避免在主进程/渲染进程或需要处理高频消息的路径中使用，以免造成事件循环长时间阻塞。
 * - Integration: Use only for the worker-thread startup-retry backoff scenario; avoid using it in the main/renderer process or in high-frequency message paths to prevent prolonged event-loop blocking.
 * - 错误处理: 非法或负数输入会被裁剪为 `0` 并直接返回；`SharedArrayBuffer/Atomics` 不可用或调用失败时会被捕获并吞掉，使重试逻辑仍可继续（只是缺少延迟）。
 * - Error Handling: Invalid/negative inputs are clamped to `0` and return immediately; failures due to unavailable `SharedArrayBuffer/Atomics` are caught and swallowed so the retry loop can continue (without delay).
 * - 关键词: 同步等待 | sync sleep | sleepSync | Atomics.wait | SharedArrayBuffer | 启动重试 | startup retry | 退避延迟 | backoff delay | startWithRetry | 事件循环阻塞 | event-loop blocking | 容错 | tolerant
 */
function sleepSync(ms) {
    const dur = Math.max(0, Math.floor(ms || 0));
    if (!dur) return;
    try {
        const arr = new Int32Array(new SharedArrayBuffer(4));
        Atomics.wait(arr, 0, 0, dur);
    } catch {}
}

/**
 * - 函数: `createPropertyBuffer`
 * - Function: `createPropertyBuffer`
 * - 作用: 构造 ETW 的 `EVENT_TRACE_PROPERTIES` 结构体缓冲区，并按当前会话名写入 `LoggerName`（UTF-16LE）；该 buffer 通常作为 StartTrace/ControlTrace 等 native API 的入参之一，用于描述实时会话属性与日志模式。
 * - Purpose: Builds an `EVENT_TRACE_PROPERTIES` struct buffer for ETW and writes the `LoggerName` (UTF-16LE) using the current session name; this buffer is typically used as an input to native APIs such as StartTrace/ControlTrace to describe real-time session properties and log mode.
 * - 调用方: 暂无（当前文件内未发现调用点；由外部 native/ETW 控制链路或测试入口按需调用）。
 * - Callers: None currently (no call sites found in this file; invoked by external native/ETW control flows or test entrypoints when needed).
 * - 被调方: `koffi.sizeof`、`koffi.offsetof`、`Buffer.alloc`、`Buffer#writeUInt32LE`、`Buffer#write`。
 * - Callees: `koffi.sizeof`, `koffi.offsetof`, `Buffer.alloc`, `Buffer#writeUInt32LE`, `Buffer#write`.
 * - 变量说明: `propsSize` 为结构体基础大小；`sessionName` 为 ETW 会话名（来自 `etwCfg.sessionName` 或默认值）；`nameSize` 为 `LoggerName` 的 UTF-16 字节数；`totalSize` 为结构体+名字+额外尾部空间；`buffer` 为最终输出。
 * - Variables: `propsSize` is the base struct size; `sessionName` is the ETW session name (from `etwCfg.sessionName` or default); `nameSize` is the UTF-16 byte size of `LoggerName`; `totalSize` is struct+name+extra tail; `buffer` is the output.
 * - 接入方式: 在构建 ETW 会话（尤其是走 Windows ETW 原生 StartTrace/ControlTrace 路径）时复用本函数生成结构体入参；调用前应确保 `etwCfg.sessionName` 已由 `resolveEtwCfg` 归一化为非空字符串。
 * - Integration: Reuse this function when building ETW sessions (especially when using the native Windows ETW StartTrace/ControlTrace path) to generate the struct input; ensure `etwCfg.sessionName` has been normalized to a non-empty string by `resolveEtwCfg` before calling.
 * - 错误处理: 本函数不捕获异常；若 `koffi` 未就绪、结构体布局不匹配或 Buffer 写入失败，会抛错并由调用方处理；输出始终为 `Buffer`，由调用方负责传入对应 native 接口。
 * - Error Handling: This function does not catch exceptions; if `koffi` is not ready, struct layouts mismatch, or Buffer writes fail, it will throw and the caller must handle it; it always returns a `Buffer` for callers to pass to the native API.
 * - 关键词: ETW属性结构 | ETW properties | createPropertyBuffer | EVENT_TRACE_PROPERTIES | LoggerName | UTF-16LE | koffi.offsetof | StartTrace | ControlTrace | 实时会话 | real-time session | 会话名 | session name
 */
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

/**
 * - 函数: `createTraceHandleArrayBuffer`
 * - Function: `createTraceHandleArrayBuffer`
 * - 作用: 将 trace handle（通常来自 ETW 控制/消费 API）编码为 8 字节小端序无符号整数 Buffer，以便在 FFI 场景中把“句柄数组”作为指针/缓冲区参数传入 native 接口。
 * - Purpose: Encodes a trace handle (typically returned by ETW control/consume APIs) into an 8-byte little-endian unsigned integer Buffer so FFI code can pass a “handle array” as a pointer/buffer parameter to native interfaces.
 * - 调用方: 暂无（当前文件内未发现调用点；由外部 ETW 控制/消费链路或测试入口按需调用）。
 * - Callers: None currently (no call sites found in this file; invoked by external ETW control/consume flows or test entrypoints when needed).
 * - 被调方: `Buffer.alloc`、`BigInt(...)`、`Buffer#writeBigUInt64LE`。
 * - Callees: `Buffer.alloc`, `BigInt(...)`, `Buffer#writeBigUInt64LE`.
 * - 变量说明: `handle` 为可转为 BigInt 的句柄值（number/string/bigint）；`traceHandles` 为长度 8 的输出缓冲区。
 * - Variables: `handle` is a handle value convertible to BigInt (number/string/bigint); `traceHandles` is the 8-byte output buffer.
 * - 接入方式: 需要向 native API 传入“trace handle 列表/数组指针”时调用；调用方应确保 `handle` 可被 `BigInt(handle)` 正确解析（例如避免 `NaN`/`undefined`），以免抛错。
 * - Integration: Call it when a native API requires a “trace handle list/array pointer”; callers should ensure `handle` can be parsed by `BigInt(handle)` (e.g., avoid `NaN`/`undefined`) to prevent exceptions.
 * - 错误处理: 本函数不捕获异常；`BigInt(handle)` 解析失败或 `writeBigUInt64LE` 写入失败会抛错并由调用方处理。
 * - Error Handling: This function does not catch exceptions; failures in `BigInt(handle)` parsing or `writeBigUInt64LE` will throw and must be handled by callers.
 * - 关键词: trace handle | 句柄数组 | handle array | createTraceHandleArrayBuffer | 8字节 | 8 bytes | little-endian | writeBigUInt64LE | BigInt | FFI | native interop | ETW控制 | ETW control
 */
function createTraceHandleArrayBuffer(handle) {
    const traceHandles = Buffer.alloc(8);
    traceHandles.writeBigUInt64LE(BigInt(handle), 0);
    return traceHandles;
}

/**
 * - 函数: `sameGuid`
 * - Function: `sameGuid`
 * - 作用: 比较两个 GUID 结构体是否完全一致（Data1/Data2/Data3/Data4[0..7]），用于在事件解码链路中判定 provider/event 的 GUID 是否命中目标，从而选择正确的解析分支。
 * - Purpose: Compares two GUID structs for full equality (Data1/Data2/Data3/Data4[0..7]), used in the event-decoding pipeline to determine whether a provider/event GUID matches the target and thus select the correct parsing branch.
 * - 调用方: `createEventCallback`（在 startSessionOnce 建链后的事件回调中，按 GUID 匹配不同 provider 的解析逻辑）。
 * - Callers: `createEventCallback` (inside the event callback installed after `startSessionOnce`, matches GUIDs to route provider-specific parsing).
 * - 被调方: 无（仅进行字段比较与循环）。
 * - Callees: None (field comparisons and a small loop only).
 * - 变量说明: `a`/`b` 为 GUID 对象（期望包含 `Data1/Data2/Data3/Data4`，其中 `Data4` 为长度 8 的字节数组或 Buffer）；`i` 为比较 `Data4` 的索引。
 * - Variables: `a`/`b` are GUID objects (expected to have `Data1/Data2/Data3/Data4`, where `Data4` is an 8-byte array or Buffer); `i` indexes `Data4` during comparison.
 * - 接入方式: 作为 GUID 等值判断的统一入口复用；若 future GUID 表达形式发生变化（例如改为 16 字节 Buffer），应在本函数内统一适配，避免在 `createEventCallback` 到处分散比较逻辑。
 * - Integration: Reuse it as the single entry for GUID equality checks; if the GUID representation changes in the future (e.g., switching to 16-byte Buffers), adapt it here instead of spreading comparison logic across `createEventCallback`.
 * - 错误处理: 任一入参缺失或 `Data4` 不存在时返回 `false`；本函数不抛异常，保证事件回调链路在遇到异常 GUID 结构时可安全降级到“不匹配”分支。
 * - Error Handling: Returns `false` when any input is missing or `Data4` is absent; never throws so the event callback chain can safely degrade to the “not matched” path on malformed GUIDs.
 * - 关键词: GUID比较 | GUID compare | sameGuid | createEventCallback | provider匹配 | provider match | Data4数组 | Data4 array | 事件解码 | event decoding | 分支路由 | branch routing | 安全降级 | safe fallback | ETW解析 | ETW parsing | startSessionOnce | 回调链路 | callback chain
 */
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

/**
 * - 函数: `extractUtf16Strings`
 * - Function: `extractUtf16Strings`
 * - 作用: 从字节流中同时尝试按 UTF-16LE 与 UTF-8 解码，提取“像路径/注册表键名”的字符串候选并做去噪与筛选；在两种解码结果之间基于注册表特征（\\REGISTRY\\ / HKxx\）打分择优，供 `parseRegistryUserData` 与 `createEventCallback` 进行字段恢复。
 * - Purpose: Tries decoding the byte stream as both UTF-16LE and UTF-8, extracts path/registry-like string candidates with sanitization and filtering, then chooses the better decoding based on registry hints (\\REGISTRY\\ / HKxx\) scoring, feeding `parseRegistryUserData` and `createEventCallback` for field recovery.
 * - 调用方: `parseRegistryUserData`（注册表 userData 解析入口）、`createEventCallback`（事件回调中对部分 payload 做字符串启发式提取）。
 * - Callers: `parseRegistryUserData` (registry userData parsing entry), `createEventCallback` (heuristic string extraction for some payloads in the event callback).
 * - 被调方: `Buffer.from`、`Buffer#toString('utf16le'|'utf8')`、`String#split`、`String#replace`、`String#trim`、`Array#map/filter`、`filterLikelyStrings`、`String#startsWith`、`RegExp#test`、`Math.min/floor`。
 * - Callees: `Buffer.from`, `Buffer#toString('utf16le'|'utf8')`, `String#split`, `String#replace`, `String#trim`, `Array#map/filter`, `filterLikelyStrings`, `String#startsWith`, `RegExp#test`, `Math.min/floor`.
 * - 变量说明: `bytes` 为原始字节流（Buffer/Uint8Array/ArrayBuffer 等可被 `Buffer.from` 接受的类型）；`minLen` 为最小字符串长度；`utf16/utf8` 为两种解码的候选列表；`a/b` 为过滤后的候选；`sa/sb` 为启发式评分结果。
 * - Variables: `bytes` is the raw byte stream (any type accepted by `Buffer.from`); `minLen` is the minimum string length; `utf16/utf8` are candidate lists for both decodings; `a/b` are filtered candidates; `sa/sb` are heuristic scores.
 * - 接入方式: 作为“从原始 payload 提取字符串候选”的统一入口复用；若你在 `createEventCallback` 中新增对其他 provider 的解析分支并需要字符串候选，应优先调用本函数而不是重复写 decode/clean/filter 逻辑。
 * - Integration: Reuse it as the unified entry for extracting string candidates from raw payloads; if you add new provider parsing branches in `createEventCallback` that need string hints, call this function instead of duplicating decode/clean/filter logic.
 * - 错误处理: UTF-16/UTF-8 解码分别被 try/catch 包裹，任何一侧失败不会影响另一侧；最终至少返回一个数组（可能为空）；本函数不抛异常，避免影响 startSessionOnce 建链后的事件回调处理。
 * - Error Handling: UTF-16 and UTF-8 decoding are independently wrapped in try/catch so failures in one do not affect the other; it always returns an array (possibly empty); never throws to avoid impacting event callback handling after `startSessionOnce`.
 * - 关键词: 字符串提取 | string extraction | extractUtf16Strings | UTF-16LE | UTF-8 | 注册表特征 | registry hints | 评分择优 | heuristic scoring | parseRegistryUserData | createEventCallback | 去噪过滤 | sanitization | filterLikelyStrings | payload解析 | payload parsing
 */
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

/**
 * - 函数: `readUtf16leZFromBytes`
 * - Function: `readUtf16leZFromBytes`
 * - 作用: 从注册表 ETW 原始字节流的指定偏移读取一个以双零结尾的 UTF-16LE 字符串，并返回文本及终止位置，作为后续键路径/值名恢复的基础读操作。
 * - Purpose: Reads one UTF-16LE string terminated by a double zero from a given offset inside raw registry ETW bytes and returns both the text and the end position as the primitive used by key-path/value-name recovery.
 * - 调用方: `scanRegistryKeyPathFromBinary` 与 `scanRegistryValueNameFromBinary` 在从原始字节中恢复注册表文本时调用。
 * - Callers: Called by `scanRegistryKeyPathFromBinary` and `scanRegistryValueNameFromBinary` when recovering registry text from raw bytes.
 * - 被调方: `Math.min`。
 * - Callees: `Math.min`.
 * - 变量说明: `bytes` 为原始注册表事件字节流；`startOffset` 为起始偏移；`maxChars` 为最多读取的 UTF-16 字符数；`endOffset` 为终止符后的位置。
 * - Variables: `bytes` is the raw registry-event byte stream; `startOffset` is the starting offset; `maxChars` caps the number of UTF-16 characters to read; `endOffset` is the position right after the terminator.
 * - 接入方式: 仅作为注册表二进制扫描链的底层读字符串 helper 使用；新的二进制文本恢复规则应优先复用它。
 * - Integration: Use it only as the low-level string reader in the registry binary-scan chain; new binary-text recovery rules should reuse it first.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: UTF16LE零结尾读取 | UTF16LE null-terminated read | registry byte scan | keyPath recovery | valueName recovery | binary string reader | endOffset | ETW registry payload
 */
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

/**
 * - 函数: `scanRegistryKeyPathFromBinary`
 * - Function: `scanRegistryKeyPathFromBinary`
 * - 作用: 在注册表 ETW 原始字节中直接搜索 `\\REGISTRY\\` 或 `HKLM/HKCU...` 模式，尽量从不可完整解码的 payload 中抢救出键路径。
 * - Purpose: Directly searches raw registry ETW bytes for `\\REGISTRY\\` or `HKLM/HKCU...` patterns so a key path can still be salvaged from payloads that cannot be fully decoded.
 * - 调用方: `parseRegistryUserData` 在常规字符串提取未能可靠恢复键路径时调用。
 * - Callers: Called by `parseRegistryUserData` when normal string extraction cannot reliably recover the registry key path.
 * - 被调方: `readUtf16leZFromBytes`。
 * - Callees: `readUtf16leZFromBytes`.
 * - 变量说明: `bytes` 为原始字节流；`patterns` 为用于定位注册表根路径的 UTF-16 模式集合；`bestIdx` 为最早命中的模式偏移。
 * - Variables: `bytes` is the raw byte stream; `patterns` is the set of UTF-16 patterns used to locate registry roots; `bestIdx` is the earliest matching offset.
 * - 接入方式: 仅作为注册表键路径恢复的兜底扫描器使用；新规则应优先在这里扩展，而不是在解析入口重复扫字节。
 * - Integration: Use it only as the fallback scanner for registry key-path recovery; new rules should be added here rather than rescanning bytes at higher layers.
 * - 错误处理: 内部捕获异常并回退到安全默认值，尽量避免辅助逻辑中断主流程。
 * - Error Handling: Catches local failures and falls back to safe defaults so helper logic does not break the main flow.
 * - 关键词: 注册表键路径抢救 | registry key path salvage | binary scan fallback | UTF16 pattern search | \\REGISTRY\\ probe | HKLM HKCU probe | parseRegistryUserData fallback | raw payload recovery
 */
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

/**
 * - 函数: `scanRegistryValueNameFromBinary`
 * - Function: `scanRegistryValueNameFromBinary`
 * - 作用: 在已定位键路径结尾后，继续沿原始字节流读取紧随其后的 UTF-16 文本，尝试恢复注册表值名称。
 * - Purpose: After the key-path end has been located, continues reading UTF-16 text from raw bytes to recover the registry value name that follows it.
 * - 调用方: `parseRegistryUserData` 在已得到 `keyEndOffset` 但还未恢复 `valueName` 时调用。
 * - Callers: Called by `parseRegistryUserData` when `keyEndOffset` is known but `valueName` is still missing.
 * - 被调方: `readUtf16leZFromBytes`。
 * - Callees: `readUtf16leZFromBytes`.
 * - 变量说明: `bytes` 为原始字节流；`startOffset` 为键路径后的起始偏移；`keyPath` 用于排除“把键路径本身误当值名”的情况；`off` 为跳过零填充后的实际读取偏移。
 * - Variables: `bytes` is the raw byte stream; `startOffset` is the offset right after the key path; `keyPath` helps reject cases where the key path itself is misread as the value name; `off` is the actual read offset after skipping zero padding.
 * - 接入方式: 仅作为值名恢复链的二进制补救 helper 使用；不要在其他路径中重复实现这段偏移读取逻辑。
 * - Integration: Use it only as the binary-recovery helper in the value-name restoration path; other code paths should not duplicate this offset-based read logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 注册表值名恢复 | registry value name recovery | binary follow-up scan | keyEndOffset | UTF16 tail read | valueName salvage | parseRegistryUserData helper | raw bytes parsing
 */
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

/**
 * - 函数: `pickBestRegistryKeyPath`
 * - Function: `pickBestRegistryKeyPath`
 * - 作用: 在提取出的字符串候选中给注册表根样式、层级深度和长度打分，选出最像真实键路径的候选文本。
 * - Purpose: Scores extracted string candidates by registry-root shape, path depth, and length, then chooses the one most likely to be the real registry key path.
 * - 调用方: `parseRegistryUserData` 在常规字符串提取成功后优先调用，用于从候选文本中选主键路径。
 * - Callers: Called by `parseRegistryUserData` after ordinary string extraction succeeds so one primary key path can be chosen from the candidates.
 * - 被调方: `filterLikelyStrings`、`Math.min`、`Math.floor`。
 * - Callees: `filterLikelyStrings`, `Math.min`, `Math.floor`.
 * - 变量说明: `strings` 为提取出的字符串候选；`bytes` 为原始字节流，用于候选不足时直接从整段 UTF-16 文本里再匹配一次；`scored` 为带分数的候选列表。
 * - Variables: `strings` is the extracted string-candidate list; `bytes` is the raw byte stream used for one more UTF-16-wide regex pass when candidates are insufficient; `scored` is the candidate list with scores attached.
 * - 接入方式: 应作为注册表键路径候选裁决器的统一入口；新增评分规则应优先集中在这里。
 * - Integration: It should remain the shared chooser for registry key-path candidates; new scoring rules should be centralized here.
 * - 错误处理: 内部捕获异常并回退到安全默认值，尽量避免辅助逻辑中断主流程。
 * - Error Handling: Catches local failures and falls back to safe defaults so helper logic does not break the main flow.
 * - 关键词: 键路径候选裁决 | key path candidate ranking | registry root scoring | path depth score | candidate chooser | parseRegistryUserData scorer | UTF16 fallback match | best keyPath
 */
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

/**
 * - 函数: `pickBestRegistryValueName`
 * - Function: `pickBestRegistryValueName`
 * - 作用: 从候选字符串中筛出最像注册表值名的文本，排除键路径本身以及包含反斜杠的路径类字符串。
 * - Purpose: Chooses the string candidate that most resembles a registry value name, excluding the key path itself and any path-like strings containing backslashes.
 * - 调用方: `parseRegistryUserData` 在已拿到候选字符串后调用，用于优先恢复 `valueName`。
 * - Callers: Called by `parseRegistryUserData` after candidate strings are available so `valueName` can be recovered first.
 * - 被调方: `filterLikelyStrings`。
 * - Callees: `filterLikelyStrings`.
 * - 变量说明: `strings` 为候选字符串集合；`keyPath` 为已推断出的键路径，用于排除同名误判；`cands` 为过滤后的值名候选。
 * - Variables: `strings` is the candidate string set; `keyPath` is the inferred key path used to avoid same-text misclassification; `cands` is the filtered value-name candidate list.
 * - 接入方式: 应作为值名候选裁决器的统一入口；新增值名筛选条件应优先在此扩展。
 * - Integration: It should remain the shared chooser for value-name candidates; new value-name filtering rules should be added here first.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 值名候选裁决 | value name candidate ranking | registry value inference | path exclusion | keyPath dedupe | candidate filter | parseRegistryUserData helper | best valueName
 */
function pickBestRegistryValueName(strings, keyPath) {
    const list = filterLikelyStrings(strings);
    const cands = list.filter(s => s && s !== keyPath && !s.includes('\\'));
    return cands.length ? cands[0] : null;
}

/**
 * - 函数: `parseRegistryUserData`
 * - Function: `parseRegistryUserData`
 * - 作用: 解析注册表 ETW 事件的原始用户数据，综合字符串提取、操作码映射、二进制扫描和候选值打分，尽可能恢复 `keyPath`、`valueName`、`type` 等可供上游风险分析使用的结构化字段。
 * - Purpose: Parses raw registry ETW user data and combines string extraction, opcode mapping, binary scanning, and candidate scoring to recover structured fields such as `keyPath`, `valueName`, and `type` for upstream risk analysis.
 * - 调用方: `createEventCallback` 在处理 Registry provider 原始事件时调用；同时通过 `module.exports.__test` 暴露给测试侧复用。
 * - Callers: Called by `createEventCallback` when handling raw Registry-provider events and also exposed through `module.exports.__test` for test reuse.
 * - 被调方: `extractUtf16Strings`、`mapRegistryOp`、`pickBestRegistryKeyPath`、`pickBestRegistryValueName`、`scanRegistryKeyPathFromBinary`、`scanRegistryValueNameFromBinary`、`Buffer.from`、`toString`。
 * - Callees: `extractUtf16Strings`, `mapRegistryOp`, `pickBestRegistryKeyPath`, `pickBestRegistryValueName`, `scanRegistryKeyPathFromBinary`, `scanRegistryValueNameFromBinary`, `Buffer.from`, `toString`.
 * - 变量说明: `bytes` 为原始注册表事件字节流；`descriptor` 为 ETW 事件描述符；`cfg` 为当前 ETW 配置；`strings` 为提取出的 UTF-16 文本候选；`type` 为注册表操作类型；`keyPath`/`valueName` 为最终推断结果。
 * - Variables: `bytes` is the raw registry-event byte stream, `descriptor` is the ETW descriptor, `cfg` is the current ETW config, `strings` contains extracted UTF-16 text candidates, `type` is the registry operation type, and `keyPath`/`valueName` are the inferred outputs.
 * - 接入方式: 适合作为 ETW 注册表 provider 的统一解析入口；若后续新增更细粒度的注册表规则或字段，应继续在本函数集中扩展，而不是在事件回调层重复解析字节流。
 * - Integration: Use it as the unified parser for the ETW Registry provider; if more granular registry rules or fields are added later, extend this function centrally instead of reparsing bytes in the event callback.
 * - 错误处理: 主要通过候选为空时回退到 `null`/空字段维持解析继续，不依赖集中异常控制；即使部分字节内容不可解码，也尽量返回已有结构化信息而不是整条事件失效。
 * - Error Handling: It mostly falls back to `null` or empty fields when candidates cannot be derived instead of relying on centralized exception handling; even when parts of the byte payload are undecodable, it tries to preserve whatever structured information is still recoverable.
 * - 关键词: 注册表事件解析 | registry event parsing | 用户数据恢复 | user data recovery | 键路径推断 | key path inference | 值名提取 | value name extraction | ETW字段结构化 | ETW structuring
 */
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

/**
 * - 函数: `isLikelyReadableText`
 * - Function: `isLikelyReadableText`
 * - 作用: 通过控制字符、空字节和替换字符比例判断一段文本是否像“可读字符串”，用于把 ETW 原始字节中提取出的噪声候选先做一层筛洗。
 * - Purpose: Judges whether a text fragment looks like readable content by checking control characters, null bytes, and replacement-character ratio, serving as the first denoising pass for strings extracted from raw ETW bytes.
 * - 调用方: `filterLikelyStrings` 在筛洗 ETW 原始字符串候选时调用。
 * - Callers: Called by `filterLikelyStrings` when denoising ETW string candidates.
 * - 被调方: `Math.max`。
 * - Callees: `Math.max`.
 * - 变量说明: `s` 为待判定文本；`bad` 为不可读控制字符计数；`nul` 为空字节计数。
 * - Variables: `s` is the text under inspection; `bad` counts unreadable control characters; `nul` counts null-byte occurrences.
 * - 接入方式: 仅作为 ETW 字符串候选筛选 helper 使用；新的可读性判定标准应优先集中在这里。
 * - Integration: Use it only as the ETW string-candidate readability helper; new readability heuristics should be centralized here.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 可读文本判定 | readable text heuristic | ETW string noise filter | control char ratio | null byte rejection | replacement char check | candidate screening | text quality gate
 */
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

/**
 * - 函数: `filterLikelyStrings`
 * - Function: `filterLikelyStrings`
 * - 作用: 对 ETW 原始字符串候选做统一清洗，移除不可读项、去空白并限制数量，给注册表路径判定和文件路径候选排序提供更干净的输入。
 * - Purpose: Performs a shared cleanup pass over raw ETW string candidates by dropping unreadable items, trimming whitespace, and capping the count, yielding cleaner input for registry-path inference and file-path ranking.
 * - 调用方: `pickBestRegistryKeyPath`、`pickBestRegistryValueName`、`pickBestPathCandidate` 会复用本函数清洗候选文本。
 * - Callers: Reused by `pickBestRegistryKeyPath`, `pickBestRegistryValueName`, and `pickBestPathCandidate` to sanitize candidate text.
 * - 被调方: `Array.isArray`。
 * - Callees: `Array.isArray`.
 * - 变量说明: `strings` 为待清洗的原始候选字符串数组。
 * - Variables: `strings` is the raw candidate string array to sanitize.
 * - 接入方式: 应作为 ETW 字符串候选清洗的统一入口；其他解析分支不要各自实现一套可读性过滤逻辑。
 * - Integration: It should be the single cleanup entry for ETW string candidates; other parsing branches should not invent their own readability filter.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 字符串候选清洗 | string candidate cleanup | filterLikelyStrings | readable text filter | trim and cap | registry parser input | path candidate input | ETW text sanitation
 */
function filterLikelyStrings(strings) {
    if (!Array.isArray(strings)) return [];
    return strings
        .filter(isLikelyReadableText)
        .map(s => s.trim())
        .filter(Boolean)
        .slice(0, 64);
}

/**
 * - 函数: `filetimeToIso`
 * - Function: `filetimeToIso`
 * - 作用: 将 ETW 事件头中的 FILETIME 时间戳转换为 ISO8601 字符串：支持 `bigint`（以 100ns 为单位）以及可转为 number 的输入；用于 `createEventCallback` 输出统一的事件时间字段。
 * - Purpose: Converts a FILETIME timestamp from an ETW event header into an ISO8601 string: supports `bigint` (100ns units) and number-coercible inputs; used by `createEventCallback` to emit a consistent event timestamp.
 * - 调用方: `createEventCallback`（构建 `eventData.timestamp`）。
 * - Callers: `createEventCallback` (builds `eventData.timestamp`).
 * - 被调方: `Number(...)`、`Number.isFinite`、`Date`、`Date#toISOString`。
 * - Callees: `Number(...)`, `Number.isFinite`, `Date`, `Date#toISOString`.
 * - 变量说明: `ts` 为 FILETIME（`bigint` 或可转为 number）；`unixMs` 为换算后的 Unix 毫秒时间戳（1970-01-01 基准）。
 * - Variables: `ts` is the FILETIME value (`bigint` or number-coercible); `unixMs` is the converted Unix timestamp in milliseconds (since 1970-01-01).
 * - 接入方式: 仅在 ETW 解码/事件回调链路中用于时间戳格式统一；若未来需要保留原始 FILETIME 或输出不同格式，应在本函数中集中修改，避免在 `createEventCallback` 中散落时间换算逻辑。
 * - Integration: Use it in ETW decode/event-callback flows to standardize timestamps; if you later need to preserve raw FILETIME or emit a different format, change this function centrally instead of scattering conversion logic in `createEventCallback`.
 * - 错误处理: 转换过程整体 try/catch；`number` 不可用或异常时回退为 `new Date().toISOString()`，保证事件仍可被记录而不因时间字段失败中断回调链路。
 * - Error Handling: Wraps conversion in try/catch; falls back to `new Date().toISOString()` on invalid numbers or errors so events can still be logged without breaking the callback chain.
 * - 关键词: FILETIME转换 | FILETIME conversion | filetimeToIso | createEventCallback | 时间戳 | timestamp | ISO8601 | bigint | 100ns单位 | 100ns units | Unix毫秒 | Unix ms | 容错回退 | fallback | ETW事件头 | ETW header
 */
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

/**
 * - 函数: `readUInt32LESafe`
 * - Function: `readUInt32LESafe`
 * - 作用: 从字节数组的指定偏移安全读取一个小端序 `uint32`；用于 `createEventCallback` 从 Process provider 的 payload 中读取 `pid/ppid` 等固定布局字段，避免越界导致异常中断事件回调。
 * - Purpose: Safely reads a little-endian `uint32` from a byte array at a given offset; used by `createEventCallback` to parse fixed-layout fields (e.g., `pid/ppid`) from Process-provider payloads while preventing out-of-bounds errors from breaking the callback.
 * - 调用方: `createEventCallback`（Process provider 的 start/stop 事件解析）。
 * - Callers: `createEventCallback` (Process-provider start/stop event parsing).
 * - 被调方: `Buffer.from`、`Array#slice`、`Buffer#readUInt32LE`。
 * - Callees: `Buffer.from`, `Array#slice`, `Buffer#readUInt32LE`.
 * - 变量说明: `bytes` 为 `koffi.decode(...)` 得到的 `uint8_t[]`（或等价字节数组）；`offset` 为读取偏移；`off` 为无符号化后的偏移；返回 `number` 或 `null`（越界/无输入）。
 * - Variables: `bytes` is a byte array returned by `koffi.decode(...)` (or equivalent); `offset` is the read offset; `off` is the unsigned-normalized offset; returns a `number` or `null` (missing/out-of-bounds).
 * - 接入方式: 在解析 ETW userData 的固定字段时复用；调用方需要对 `null` 做容错（例如跳过该事件或回退为缺省字段），避免把不完整 payload 当成有效数据继续使用。
 * - Integration: Reuse it when parsing fixed-layout fields from ETW userData; callers should handle `null` (e.g., skip the event or fall back) to avoid treating incomplete payloads as valid data.
 * - 错误处理: 对 `bytes` 缺失或越界直接返回 `null`；本函数不抛异常，保证事件回调链路在异常 payload 下仍可继续。
 * - Error Handling: Returns `null` on missing input or out-of-bounds; never throws so the event callback chain can continue under malformed payloads.
 * - 关键词: 安全读取 | safe read | readUInt32LESafe | little-endian | uint32 | createEventCallback | pid解析 | pid parsing | 越界保护 | bounds check | koffi.decode | ETW payload | 事件回调 | event callback | 容错 | tolerant
 */
function readUInt32LESafe(bytes, offset) {
    const off = offset >>> 0;
    if (!bytes || off + 4 > bytes.length) return null;
    return Buffer.from(bytes.slice(off, off + 4)).readUInt32LE(0);
}

/**
 * - 函数: `readUInt16BESafe`
 * - Function: `readUInt16BESafe`
 * - 作用: 从网络 ETW 原始字节的指定偏移安全读取一个大端端口值，供网络事件启发式解析恢复源/目标端口。
 * - Purpose: Safely reads one big-endian port value from a given offset in raw network ETW bytes so heuristic parsing can recover source and destination ports.
 * - 调用方: `parseNetworkUserDataHeuristic` 在尝试从 payload 恢复网络四元组时调用。
 * - Callers: Called by `parseNetworkUserDataHeuristic` when recovering the network tuple from the payload.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `bytes` 为网络事件字节流；`offset` 为端口字段偏移；`off` 为无符号化后的读取偏移。
 * - Variables: `bytes` is the network-event byte stream; `offset` is the port-field offset; `off` is the unsigned-normalized read offset.
 * - 接入方式: 仅作为网络 payload 解析 helper 使用；新的端口字段读取逻辑应优先复用它。
 * - Integration: Use it only as a helper for network-payload parsing; new port-field readers should reuse it first.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 安全端口读取 | safe port read | uint16 big-endian | network payload parse | destination port | source port | bounds-safe read | ETW network helper
 */
function readUInt16BESafe(bytes, offset) {
    const off = offset >>> 0;
    if (!bytes || off + 2 > bytes.length) return null;
    return Buffer.from(bytes.slice(off, off + 2)).readUInt16BE(0);
}

/**
 * - 函数: `ipv4ToString`
 * - Function: `ipv4ToString`
 * - 作用: 把 4 个 IPv4 字节段拼成点分十进制字符串，供网络事件启发式解析输出可展示的 IP 地址。
 * - Purpose: Formats four IPv4 octets into a dotted-decimal string so heuristic network parsing can emit displayable IP addresses.
 * - 调用方: `parseNetworkUserDataHeuristic` 在恢复出 IPv4 四段地址后调用。
 * - Callers: Called by `parseNetworkUserDataHeuristic` after IPv4 octets have been recovered.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `a/b/c/d` 为 IPv4 的四个字节段。
 * - Variables: `a/b/c/d` are the four IPv4 octets.
 * - 接入方式: 仅作为网络地址格式化 helper 使用；若未来扩展 IPv6，应新增独立函数而不是把复杂逻辑塞进这里。
 * - Integration: Use it only as the IPv4 formatting helper; if IPv6 support is added later, create a separate function instead of overloading this one.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: IPv4格式化 | IPv4 formatting | dotted decimal | network event output | address string | parseNetworkUserDataHeuristic helper | octet join | remote IP display
 */
function ipv4ToString(a, b, c, d) {
    return `${a >>> 0}.${b >>> 0}.${c >>> 0}.${d >>> 0}`;
}

/**
 * - 函数: `isLoopbackIpv4`
 * - Function: `isLoopbackIpv4`
 * - 作用: 判断一个 IPv4 地址是否落在 `127.0.0.0/8` 回环段，用于过滤掉不应上报为外部通信目标的本机流量。
 * - Purpose: Determines whether an IPv4 address falls within the `127.0.0.0/8` loopback range so local-only traffic is not surfaced as an external communication target.
 * - 调用方: `parseNetworkUserDataHeuristic` 在筛选网络目标地址时调用。
 * - Callers: Called by `parseNetworkUserDataHeuristic` while filtering network target addresses.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `a` 为 IPv4 的第一段字节。
 * - Variables: `a` is the first IPv4 octet.
 * - 接入方式: 仅作为网络地址质量判定 helper 使用；新的地址类型判断应保持独立函数拆分。
 * - Integration: Use it only as a helper for network-address quality checks; new address classifications should remain separate helpers.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 回环地址判定 | loopback IPv4 check | 127/8 filter | local traffic suppression | network heuristic | remote target filter | address classifier | ETW network parsing
 */
function isLoopbackIpv4(a) {
    return (a >>> 0) === 127;
}

/**
 * - 函数: `isPrivateIpv4`
 * - Function: `isPrivateIpv4`
 * - 作用: 判断一个 IPv4 地址是否属于 RFC1918 或链路本地私有网段，用于给网络事件打上内网/本地通信语义。
 * - Purpose: Determines whether an IPv4 address belongs to RFC1918 or link-local private ranges so network events can be interpreted as internal or local traffic.
 * - 调用方: `parseNetworkUserDataHeuristic` 在评估目标地址可信度与展示语义时调用。
 * - Callers: Called by `parseNetworkUserDataHeuristic` when evaluating target-address semantics and trustworthiness.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `a/b` 为 IPv4 前两段；`x/y` 为无符号化后的比较值。
 * - Variables: `a/b` are the first two IPv4 octets; `x/y` are their unsigned-normalized comparison values.
 * - 接入方式: 仅作为网络地址语义判定 helper 使用；新增网段分类时应优先在本函数集中扩展。
 * - Integration: Use it only as the helper for network-address semantic checks; new subnet classifications should be centralized here first.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 私网地址判定 | private IPv4 check | RFC1918 ranges | link-local filter | internal traffic tag | network heuristic | address classification | ETW network helper
 */
function isPrivateIpv4(a, b) {
    const x = a >>> 0;
    const y = b >>> 0;
    if (x === 10) return true;
    if (x === 172 && y >= 16 && y <= 31) return true;
    if (x === 192 && y === 168) return true;
    if (x === 169 && y === 254) return true;
    return false;
}

/**
 * - 函数: `isBadIpv4`
 * - Function: `isBadIpv4`
 * - 作用: 过滤明显无效、广播或多播性质的 IPv4 目标地址，避免把 ETW 网络事件中的噪声地址当成真实远端目标。
 * - Purpose: Filters obviously invalid, broadcast, or multicast-style IPv4 target addresses so noisy ETW network payloads are not mistaken for real remote endpoints.
 * - 调用方: `parseNetworkUserDataHeuristic` 在筛选候选远端地址时调用。
 * - Callers: Called by `parseNetworkUserDataHeuristic` when screening candidate remote addresses.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `a/b/c/d` 为 IPv4 四段；`x/y/z/w` 为无符号化后的比较值。
 * - Variables: `a/b/c/d` are the four IPv4 octets; `x/y/z/w` are the unsigned-normalized comparison values.
 * - 接入方式: 仅作为网络目标过滤 helper 使用；新的无效地址规则应优先在这里集中维护。
 * - Integration: Use it only as the network-target filtering helper; new invalid-address rules should be maintained here first.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 无效IPv4过滤 | invalid IPv4 filter | broadcast drop | multicast drop | noisy target rejection | remote endpoint screening | network heuristic | bad address guard
 */
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

/**
 * - 函数: `parseNetworkUserDataHeuristic`
 * - Function: `parseNetworkUserDataHeuristic`
 * - 作用: 解析网络用户数据heuristic原始输入，并提取结构化结果供后续逻辑使用。
 * - Purpose: Parses the raw network user data heuristic input and extracts a structured result for downstream logic.
 * - 调用方: `createEventCallback`。
 * - Callers: `createEventCallback`.
 * - 被调方: `isBadIpv4`、`readUInt16BESafe`、`isLoopbackIpv4`、`isPrivateIpv4`、`ipv4ToString`、`Math.max`。
 * - Callees: `isBadIpv4`, `readUInt16BESafe`, `isLoopbackIpv4`, `isPrivateIpv4`, `ipv4ToString`, `Math.max`.
 * - 变量说明: `bytes` 为当前流程传入的字节数据；`cfg` 为当前流程传入的cfg；`netCfg`, `buf` 为函数内部派生的中间状态。
 * - Variables: `bytes` is the incoming byte buffer for this flow; `cfg` is the incoming cfg for this flow; `netCfg`, `buf` are derived intermediate variables inside the function.
 * - 接入方式: 可通过 `require('./etw_worker').parseNetworkUserDataHeuristic` 接入；新增外部调用方时，优先复用本函数而不是复制同类逻辑。
 * - Integration: Integrate via `require('./etw_worker').parseNetworkUserDataHeuristic`; new external consumers should reuse this function instead of duplicating the same logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 解析 | 网络 | 用户 | 数据 | heuristic | parse | network | user | data | heuristic
 */
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

/**
 * - 函数: `mapNetworkOp`
 * - Function: `mapNetworkOp`
 * - 作用: 将 ETW `descriptor` 中的 `Opcode/Id` 映射为 Network 操作类型（目前仅识别连接类事件），供 `createEventCallback` 统一构造 `eventData.data.type` 并驱动后续解析/过滤。
 * - Purpose: Maps `Opcode/Id` from an ETW `descriptor` to a Network operation type (currently only connection-like events), so `createEventCallback` can populate `eventData.data.type` and drive downstream parsing/filtering.
 * - 调用方: `createEventCallback`；测试侧可通过 `module.exports.__test.mapNetworkOp` 复用。
 * - Callers: `createEventCallback`; tests may reuse it via `module.exports.__test.mapNetworkOp`.
 * - 被调方: `Number.isFinite`、`Set`、`Set.prototype.has`。
 * - Callees: `Number.isFinite`, `Set`, `Set.prototype.has`.
 * - 变量说明: `descriptor` 为 ETW 事件描述对象（通常来自 `EVENT_HEADER`/解码后的 record），预期包含数值字段 `Opcode` 与 `Id`；`opcode/id` 为规范化后的数值或 `null`；`candidates` 为“连接类” opcode/id 的白名单集合。
 * - Variables: `descriptor` is the ETW event descriptor (typically from `EVENT_HEADER` / decoded record) expected to carry numeric `Opcode` and `Id`; `opcode/id` are normalized numbers or `null`; `candidates` is the whitelist set for connection-like opcode/id.
 * - 接入方式: 推荐仅在 `createEventCallback` 的 Network 分支中调用；测试/诊断可通过 `require(...). __test.mapNetworkOp(descriptor)` 间接调用（以 `module.exports` 暴露为准）。
 * - Integration: Use it inside the Network branch of `createEventCallback`; tests/diagnostics can call it via `require(...).__test.mapNetworkOp(descriptor)` (as exposed by `module.exports`).
 * - 错误处理: 对缺失/非数值的 `Opcode/Id` 返回 `null`；未命中白名单也返回 `null`，调用方据此快速跳过；函数不抛异常，适合高频热路径。
 * - Error Handling: Returns `null` for missing/non-numeric `Opcode/Id`; also returns `null` when not in the whitelist so callers can fast-skip; never throws and is safe for hot paths.
 * - 关键词: 网络映射 | network mapping | mapNetworkOp | ETW descriptor | Opcode/Id | Connect | createEventCallback | Number.isFinite | Set.has | 返回null
 */
function mapNetworkOp(descriptor) {
    const opcode = descriptor && Number.isFinite(descriptor.Opcode) ? descriptor.Opcode : null;
    const id = descriptor && Number.isFinite(descriptor.Id) ? descriptor.Id : null;
    const candidates = new Set([10, 11, 12, 13, 14, 15, 16]);
    if (opcode != null && candidates.has(opcode)) return 'Connect';
    if (id != null && candidates.has(id)) return 'Connect';
    return null;
}

/**
 * - 函数: `mapFileOp`
 * - Function: `mapFileOp`
 * - 作用: 将 File provider 的 ETW `descriptor`（主要使用 `Id`，其次回退到 `Opcode`）映射为文件操作类型（Create/Open/Modify/Delete/Rename），用于 `createEventCallback` 的 File 分支统一生成事件类型并配合配置过滤。
 * - Purpose: Maps an ETW File-provider `descriptor` (primarily `Id`, falling back to `Opcode`) to a file operation type (Create/Open/Modify/Delete/Rename) for `createEventCallback` to consistently label events and apply config filtering.
 * - 调用方: `createEventCallback`；测试侧可通过 `module.exports.__test.mapFileOp` 复用。
 * - Callers: `createEventCallback`; tests may reuse it via `module.exports.__test.mapFileOp`.
 * - 被调方: `Number.isFinite`。
 * - Callees: `Number.isFinite`.
 * - 变量说明: `descriptor` 为 ETW 事件描述对象，预期包含数值字段 `Opcode` 与 `Id`；`opcode/id` 为规范化后的数值或 `null`；`op` 为从 `opcode/id` 归一出来的关键码（当前仅对 32/35/36 做兼容映射）。
 * - Variables: `descriptor` is the ETW event descriptor expected to carry numeric `Opcode` and `Id`; `opcode/id` are normalized numbers or `null`; `op` is the normalized key code derived from `opcode/id` (currently only normalizes 32/35/36 for compatibility).
 * - 接入方式: 推荐由 `createEventCallback` 的 File 分支调用：`const typ = mapFileOp(descriptor)`；测试/诊断可通过 `require(...).__test.mapFileOp(descriptor)` 间接调用（以 `module.exports` 暴露为准）。
 * - Integration: Call it from the File branch of `createEventCallback`: `const typ = mapFileOp(descriptor)`; tests/diagnostics can call it via `require(...).__test.mapFileOp(descriptor)` (as exposed by `module.exports`).
 * - 错误处理: 入参缺失或无法识别时返回 `null`，由调用方决定是否跳过；函数不抛异常，保证回调链路稳定。
 * - Error Handling: Returns `null` for missing inputs or unknown codes so callers can decide to skip; never throws to keep the callback pipeline stable.
 * - 关键词: 文件映射 | file mapping | mapFileOp | File provider | Opcode/Id | Create | Delete | Rename | createEventCallback | 返回null
 */
function mapFileOp(descriptor) {
    const opcode = descriptor && Number.isFinite(descriptor.Opcode) ? descriptor.Opcode : null;
    const id = descriptor && Number.isFinite(descriptor.Id) ? descriptor.Id : null;
    if (id != null) {
        if (id === 30 || id === 12 || id === 10) return 'Create';
        if (id === 15) return 'Open';
        if (id === 16 || id === 17) return 'Modify';
        if (id === 26 || id === 11) return 'Delete';
        if (id === 27 || id === 19) return 'Rename';
    }
    const op = (opcode === 32 || opcode === 35 || opcode === 36) ? opcode : ((id === 32 || id === 35 || id === 36) ? id : null);
    if (op === 32) return 'Create';
    if (op === 35) return 'Delete';
    if (op === 36) return 'Rename';
    return null;
}

/**
 * - 函数: `pickBestPathCandidate`
 * - Function: `pickBestPathCandidate`
 * - 作用: 从候选best路径candidate中挑选最优结果，减少后续流程的歧义。
 * - Purpose: Picks the best result from candidate best path candidate values to reduce ambiguity for downstream steps.
 * - 调用方: `createEventCallback`。
 * - Callers: `createEventCallback`.
 * - 被调方: `filterLikelyStrings`、`isPathLike`、`Math.min`、`Math.floor`。
 * - Callees: `filterLikelyStrings`, `isPathLike`, `Math.min`, `Math.floor`.
 * - 变量说明: `strings` 为当前流程传入的strings；`list`, `scored` 为函数内部派生的中间状态。
 * - Variables: `strings` is the incoming strings for this flow; `list`, `scored` are derived intermediate variables inside the function.
 * - 接入方式: 可通过 `require('./etw_worker').pickBestPathCandidate` 接入；新增外部调用方时，优先复用本函数而不是复制同类逻辑。
 * - Integration: Integrate via `require('./etw_worker').pickBestPathCandidate`; new external consumers should reuse this function instead of duplicating the same logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 挑选 | best | 路径 | candidate | pick | best | path | candidate | error handling | 复用
 */
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
    /**
 * - 函数: `isPathLike`
 * - Function: `isPathLike`
 * - 作用: 判断路径like条件是否成立，并返回布尔化结果供上游守卫分支使用。
 * - Purpose: Checks whether the path like condition is satisfied and returns a boolean-style result for upstream guards.
 * - 调用方: `pickBestPathCandidate`。
 * - Callers: `pickBestPathCandidate`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `s` 为当前流程传入的s。
 * - Variables: `s` is the incoming s for this flow.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `isPathLike`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `isPathLike` through the existing returned object.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 判断 | 路径 | like | check | path | like | call chain | 错误处理 | error handling | 复用
 */
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

/**
 * - 函数: `tryDecodeEventRecord`
 * - Function: `tryDecodeEventRecord`
 * - 作用: 尝试把原始 `EVENT_RECORD*` 指针解码成 koffi 可读对象，作为原生 ETW 回调进入 JS 解析链的第一步安全包装。
 * - Purpose: Attempts to decode a raw `EVENT_RECORD*` pointer into a koffi-readable object, serving as the first safe wrapper when native ETW callbacks enter the JS parsing chain.
 * - 调用方: `normalizeEventRecordPtr`。
 * - Callers: `normalizeEventRecordPtr`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `ptr` 为原生 ETW 回调传入的 `EVENT_RECORD*` 指针。
 * - Variables: `ptr` is the `EVENT_RECORD*` pointer received from the native ETW callback.
 * - 接入方式: 主要由 `normalizeEventRecordPtr` 间接复用；新的 ETW 记录解码路径应优先复用本函数而不是直接调用 `koffi.decode`。
 * - Integration: Primarily reused through `normalizeEventRecordPtr`; new ETW-record decode paths should prefer this helper instead of calling `koffi.decode` directly.
 * - 错误处理: 内部捕获异常并回退到安全默认值，尽量避免辅助逻辑中断主流程。
 * - Error Handling: Catches local failures and falls back to safe defaults so helper logic does not break the main flow.
 * - 关键词: EVENT_RECORD解码 | EVENT_RECORD decode | koffi.decode wrapper | native callback safety | pointer to object | ETW record helper | null fallback | decode guard
 */
function tryDecodeEventRecord(ptr) {
    try {
        return koffi.decode(ptr, EVENT_RECORD);
    } catch {
        return null;
    }
}

/**
 * - 函数: `normalizeEventRecordPtr`
 * - Function: `normalizeEventRecordPtr`
 * - 作用: 标准化事件记录ptr输入，统一为当前模块后续逻辑可直接消费的结构。
 * - Purpose: Normalizes the event record ptr input into a structure that downstream logic can consume directly.
 * - 调用方: `createEventCallback`。
 * - Callers: `createEventCallback`.
 * - 被调方: `tryDecodeEventRecord`。
 * - Callees: `tryDecodeEventRecord`.
 * - 变量说明: `recordPtr` 为当前流程传入的记录ptr。
 * - Variables: `recordPtr` is the incoming record ptr for this flow.
 * - 接入方式: 可通过 `require('./etw_worker').normalizeEventRecordPtr` 接入；新增外部调用方时，优先复用本函数而不是复制同类逻辑。
 * - Integration: Integrate via `require('./etw_worker').normalizeEventRecordPtr`; new external consumers should reuse this function instead of duplicating the same logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 标准化 | 事件 | 记录 | ptr | normalize | event | record | ptr | error handling | 复用
 */
function normalizeEventRecordPtr(recordPtr) {
    if (!recordPtr) return null;
    if (recordPtr && recordPtr.EventHeader) return recordPtr;
    return tryDecodeEventRecord(recordPtr);
}

/**
 * - 函数: `shouldSkipByFilters`
 * - Function: `shouldSkipByFilters`
 * - 作用: 按 `filters[provider].skipOps` 规则判断某个 provider/type 是否应被跳过，是配置过滤的底层判定器；将规则解释与容错集中在一处，供 `shouldSkipByCfg`（以及可能的外部复用）调用。
 * - Purpose: Evaluates whether a provider/type should be skipped based on `filters[provider].skipOps`; this is the low-level config-filter decision engine, centralizing rule interpretation and tolerance for `shouldSkipByCfg` (and potential external reuse).
 * - 调用方: `shouldSkipByCfg`（从 `etwCfg.filters` 读取 filters 后调用本函数进行最终判定）。
 * - Callers: `shouldSkipByCfg` (reads filters from `etwCfg.filters` and delegates the final decision here).
 * - 被调方: `Array.isArray`、`Array.prototype.map`、`Array.prototype.includes`、`String(...)`。
 * - Callees: `Array.isArray`, `Array.prototype.map`, `Array.prototype.includes`, `String(...)`.
 * - 变量说明: `filters` 为过滤配置对象；`provider`/`type` 为待判定的 provider 与操作类型；`p`/`t` 为入参的字符串化结果；`rule` 为 `filters[p]` 子规则对象；`skipOps` 为字符串数组，表示应跳过的操作类型集合。
 * - Variables: `filters` is the filter config object; `provider`/`type` are the provider and operation type to evaluate; `p`/`t` are the normalized string forms; `rule` is the sub-rule object at `filters[p]`; `skipOps` is the string array of operation types to skip.
 * - 接入方式: 一般通过 `shouldSkipByCfg` 间接使用；若其他模块需要对同一规则结构做判断，可按导出函数使用：`shouldSkipByFilters(filters, provider, type)`；新增过滤规则字段（例如 allowOps/denyOps）时优先扩展本函数以保持解释逻辑唯一。
 * - Integration: Usually consumed indirectly via `shouldSkipByCfg`; other modules can reuse it through the export: `shouldSkipByFilters(filters, provider, type)`; when adding new rule fields (e.g., allowOps/denyOps), extend this function first so rule interpretation remains single-sourced.
 * - 错误处理: 对空 provider/type 直接返回 `false`；对非对象 filters 回退为 `{}`；任何异常都会被捕获并回退为“不跳过”（`false`），避免配置异常导致事件链路中断。
 * - Error Handling: Returns `false` for empty provider/type; falls back to `{}` for non-object filters; catches any exception and returns `false` (do not skip) to prevent malformed config from breaking the event pipeline.
 * - 关键词: 规则解释 | rule evaluation | shouldSkipByFilters | skipOps | provider/type | 配置过滤 | config filtering | shouldSkipByCfg | 容错 | tolerant | 统一判定器 | central decider | 事件裁剪 | event trimming | Array.includes | ETW filters
 */
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

/**
 * - 函数: `shouldSkipByCfg`
 * - Function: `shouldSkipByCfg`
 * - 作用: 根据当前生效配置 `etwCfg.filters` 判断是否跳过某个 provider/type 的事件，用于对 Process/File/Registry/Network 等操作类型进行“按配置裁剪”，把过滤决策集中在一处，供 bridge 入站与原生回调入站复用。
 * - Purpose: Determines whether to skip an event for a given provider/type based on the effective config `etwCfg.filters`, centralizing config-based trimming for operations across Process/File/Registry/Network and making it reusable for both bridge-ingress and native-callback ingress paths.
 * - 调用方: `handleBridgeMessage`（provider/type 分支里做快速跳过）、`createEventCallback`（从 EVENT_RECORD 解析出 provider/type 后做跳过）。
 * - Callers: `handleBridgeMessage` (fast skip within provider/type branches), `createEventCallback` (skip after parsing provider/type from EVENT_RECORD).
 * - 被调方: `shouldSkipByFilters`。
 * - Callees: `shouldSkipByFilters`.
 * - 变量说明: `provider` 为 provider 名称（如 `Process`/`File`）；`type` 为操作类型（如 `Start`/`Create`）；`filters` 为从 `etwCfg.filters` 取得的对象（缺省为空对象），最终由 `shouldSkipByFilters` 解释规则（如 `skipOps`）。
 * - Variables: `provider` is the provider name (e.g., `Process`/`File`); `type` is the operation type (e.g., `Start`/`Create`); `filters` is read from `etwCfg.filters` (defaults to `{}`) and is interpreted by `shouldSkipByFilters` (e.g., via `skipOps`).
 * - 接入方式: 在决定是否 `postMessage({type:'log', event})` 前调用；新增过滤维度（如按路径/端口/进程树）时，应在 `filters` 中扩展规则并由 `shouldSkipByFilters`/本函数统一入口承载，避免在各 provider 分支中重复判断。
 * - Integration: Call it before deciding to `postMessage({type:'log', event})`; when adding new filter dimensions (path/port/process-tree), extend rules under `filters` and keep this as the unified entry (possibly extending `shouldSkipByFilters`) to avoid duplicating checks across provider branches.
 * - 错误处理: 任何异常均回退为“不跳过”（返回 `false`），保证过滤逻辑故障不会导致事件链路完全失效；函数不抛异常，适合作为高频路径的轻量守卫。
 * - Error Handling: Any exception falls back to “do not skip” (returns `false`) so filter failures do not break the entire event pipeline; never throws and is safe for hot paths.
 * - 关键词: 配置过滤 | config filtering | shouldSkipByCfg | etwCfg.filters | skipOps | provider/type | handleBridgeMessage | createEventCallback | 事件裁剪 | event trimming | 统一入口 | unified entry | 轻量守卫 | lightweight guard | 异常回退 | exception fallback | shouldSkipByFilters | 热路径 | hot path
 */
function shouldSkipByCfg(provider, type) {
    try {
        const filters = (etwCfg && etwCfg.filters && typeof etwCfg.filters === 'object') ? etwCfg.filters : {};
        return shouldSkipByFilters(filters, provider, type);
    } catch { return false; }
}

/**
 * - 函数: `mapRegistryOp`
 * - Function: `mapRegistryOp`
 * - 作用: 将 Registry provider 的 `EventDescriptor.Opcode/Id` 映射为稳定的 Registry 操作类型字符串（优先按 `Id`，其次 `Opcode`）；用于 `parseRegistryUserData` 与 `createEventCallback` 在日志/过滤层面对 Registry 事件分类。
 * - Purpose: Maps `EventDescriptor.Opcode/Id` from the Registry provider into a stable Registry operation type string (prefers `Id`, then `Opcode`); used by `parseRegistryUserData` and `createEventCallback` to classify Registry events for logging/filtering.
 * - 调用方: `parseRegistryUserData`、`createEventCallback`；测试侧可通过 `module.exports.__test.mapRegistryOp` 复用。
 * - Callers: `parseRegistryUserData`, `createEventCallback`; tests may reuse it via `module.exports.__test.mapRegistryOp`.
 * - 被调方: `Number.isFinite`、`String`（隐式拼接）.
 * - Callees: `Number.isFinite`, `String` (implicit concatenation).
 * - 变量说明: `opcode` 为 ETW `EventDescriptor.Opcode`（可能为 `null/undefined`）；`id` 为 `EventDescriptor.Id`（可能为 `null/undefined`）；`m` 为已知 ID/Opcode 到语义名称的映射表。
 * - Variables: `opcode` is ETW `EventDescriptor.Opcode` (may be `null/undefined`); `id` is `EventDescriptor.Id` (may be `null/undefined`); `m` is the mapping table from known ID/Opcode to semantic names.
 * - 接入方式: 在 Registry 事件分支先获取类型：`const type = mapRegistryOp(descriptor.Opcode, descriptor.Id)`；测试/诊断可通过 `require(...).__test.mapRegistryOp(opcode, id)` 间接调用（以 `module.exports` 暴露为准）。
 * - Integration: Obtain the type early in the Registry event branch: `const type = mapRegistryOp(descriptor.Opcode, descriptor.Id)`; tests/diagnostics can call it via `require(...).__test.mapRegistryOp(opcode, id)` (as exposed by `module.exports`).
 * - 错误处理: 未命中映射表时回退为 `EventId_<id>` 或 `Opcode_<opcode>`，避免返回空值导致上游分类缺失；函数不抛异常。
 * - Error Handling: Falls back to `EventId_<id>` or `Opcode_<opcode>` when unmapped so upstream classification is never missing; never throws.
 * - 关键词: 注册表映射 | registry mapping | mapRegistryOp | Opcode/Id | CreateKey | SetValue | DeleteKey | RenameKey | parseRegistryUserData | 回退前缀
 */
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

/**
 * - 函数: `createEventCallback`
 * - Function: `createEventCallback`
 * - 作用: 创建并缓存 ETW 事件回调（koffi FFI callback），用于把 native bridge 推送的 `EVENT_RECORD` 解码为统一的 `eventData`（Process/File/Registry/Network）并通过 `postMessage({type:'log'})` 上报主进程；同时在回调中应用 `shouldSkipByCfg/shouldSkipTrustedEvent` 过滤策略与错误节流，避免高频异常刷屏。
 * - Purpose: Creates and caches the ETW event callback (koffi FFI callback) that decodes native `EVENT_RECORD` into a unified `eventData` (Process/File/Registry/Network) and reports it to the main process via `postMessage({type:'log'})`; it also applies `shouldSkipByCfg/shouldSkipTrustedEvent` filtering and throttles error reporting to avoid flooding on high-frequency failures.
 * - 调用方: `startSessionOnce`（在成功 `EtwBridge_Start` 前后用于向 bridge 注册/提供事件回调），以及测试/初始化路径中对回调的惰性获取。
 * - Callers: `startSessionOnce` (provides the callback to the bridge around `EtwBridge_Start`), and any test/initialization path that lazily obtains the callback.
 * - 被调方: `koffi.register`、`normalizeEventRecordPtr`、`sameGuid`、`filetimeToIso`、`readUInt32LESafe`、`extractUtf16Strings`、`pickBestPathCandidate`、`normalizeEtwPathValue`、`mapFileOp`、`mapRegistryOp`、`mapNetworkOp`、`parseRegistryUserData`、`parseNetworkUserDataHeuristic`、`shouldSkipByCfg`、`shouldSkipTrustedEvent`、`postMessage`、`postError`。
 * - Callees: `koffi.register`, `normalizeEventRecordPtr`, `sameGuid`, `filetimeToIso`, `readUInt32LESafe`, `extractUtf16Strings`, `pickBestPathCandidate`, `normalizeEtwPathValue`, `mapFileOp`, `mapRegistryOp`, `mapNetworkOp`, `parseRegistryUserData`, `parseNetworkUserDataHeuristic`, `shouldSkipByCfg`, `shouldSkipTrustedEvent`, `postMessage`, `postError`.
 * - 变量说明: 无显式入参；`eventCallback` 为模块级缓存的 koffi 回调句柄；`recordPtr` 为 native 传入的指针；`record/header/descriptor` 为解码后的 ETW 结构；`providerId` 为 Provider GUID；`eventData` 为上报对象；`bytes` 为 userData 字节数组；`cappedLen` 为按 `userDataMaxBytes` 截断后的长度；`lastCallbackErrorAt` 用于错误节流。
 * - Variables: No explicit parameters; `eventCallback` is the module-level cached koffi callback handle; `recordPtr` is the native pointer; `record/header/descriptor` are decoded ETW structs; `providerId` is the Provider GUID; `eventData` is the outbound object; `bytes` is the userData byte array; `cappedLen` is length capped by `userDataMaxBytes`; `lastCallbackErrorAt` throttles error reports.
 * - 接入方式: 仅在 ETW session 已启动、且 bridge 需要一个符合 `EventRecordCallbackType` 的函数指针时使用；调用方应先确保 `koffi` 与结构体类型已正确初始化，并在停止会话时配合 `unregisterCallback` 释放回调，避免句柄泄漏。
 * - Integration: Use only when an ETW session is running and the bridge needs a function pointer matching `EventRecordCallbackType`; callers should ensure `koffi` and struct types are initialized and call `unregisterCallback` on session stop to avoid handle leaks.
 * - 错误处理: 回调内部多层 try/catch：对单条事件解析异常做节流上报 `ETW_CALLBACK_ERROR`；对停机态 `isStopping` 直接返回；对无法识别 provider 或解析失败的事件静默跳过；最外层 fatal catch 防止异常逸出导致 native 回调崩溃。
 * - Error Handling: Uses nested try/catch: per-event parsing errors are reported as throttled `ETW_CALLBACK_ERROR`; returns early when `isStopping`; silently skips unrecognized providers or parse failures; an outer fatal catch prevents exceptions from escaping and crashing the native callback.
 * - 关键词: ETW回调 | ETW callback | createEventCallback | koffi.register | EVENT_RECORD解码 | EVENT_RECORD decode | provider分发 | provider routing | shouldSkipByCfg | shouldSkipTrustedEvent | postMessage日志 | log posting | 事件解码 | event decoding | 错误节流 | error throttling | startSessionOnce | bridge回调 | bridge callback
 */
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
                            const imageName = normalizeEtwPathValue(pickBestPathCandidate(strings));
                            const typ = descriptor.Opcode === 1 ? 'Start' : 'Stop';
                            eventData.data = {
                                processId: pid,
                                parentProcessId: ppid,
                                imageName,
                                type: typ
                            };
                            if (shouldSkipByCfg('Process', typ)) {
                                return;
                            }
                            if (typ === 'Start') {
                                try { trustedPidFilter.onProcessStart(pid, imageName); } catch {}
                            } else {
                                try { trustedPidFilter.onProcessStop(pid); } catch {}
                            }
                            if (shouldSkipTrustedEvent(eventData)) return;
                            postMessage({ type: 'log', event: eventData });
                        }
                    } else if (isFile) {
                        const typ = mapFileOp(descriptor);
                        if (!typ) return;
                        const strings = extractUtf16Strings(bytes, 3);
                        const fileName = normalizeEtwPathValue(pickBestPathCandidate(strings));
                        if (fileName) {
                            eventData.data = { fileName, type: typ };
                            if (shouldSkipByCfg('File', typ)) return;
                            if (shouldSkipTrustedEvent(eventData)) return;
                            postMessage({ type: 'log', event: eventData });
                        }
                    } else if (isRegistry) {
                        const regType = mapRegistryOp(descriptor.Opcode, descriptor.Id);
                        if (shouldSkipByCfg('Registry', regType)) {
                            return;
                        }
                        eventData.data = parseRegistryUserData(bytes, descriptor, etwCfg);
                        if (shouldSkipTrustedEvent(eventData)) return;
                        postMessage({ type: 'log', event: eventData });
                    } else if (isNetwork) {
                        const netType = mapNetworkOp(descriptor);
                        if (!netType) return;
                        if (shouldSkipByCfg('Network', netType)) return;
                        const parsed = parseNetworkUserDataHeuristic(bytes, etwCfg);
                        if (!parsed) return;
                        eventData.data = Object.assign({ type: netType }, parsed);
                        if (shouldSkipTrustedEvent(eventData)) return;
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

/**
 * - 函数: `unregisterCallback`
 * - Function: `unregisterCallback`
 * - 作用: 释放由 `createEventCallback` 创建/缓存的 koffi FFI 回调，避免 worker 生命周期内回调句柄泄漏；函数幂等（重复调用安全）。
 * - Purpose: Releases the koffi FFI callback created/cached by `createEventCallback` to avoid callback handle leaks during the worker lifecycle; idempotent and safe to call repeatedly.
 * - 调用方: 当前文件中暂无显式调用点；`createEventCallback` 的注释语义要求在会话停止路径调用本函数进行资源回收。
 * - Callers: No explicit call sites in this file currently; `createEventCallback`'s documented lifecycle expects this to be invoked on session stop to reclaim resources.
 * - 被调方: `koffi.unregister`。
 * - Callees: `koffi.unregister`.
 * - 变量说明: 无显式入参；`eventCallback` 为本文件缓存的回调函数指针/包装对象（由 `createEventCallback` 赋值），本函数在成功释放后将其置为 `null`。
 * - Variables: No explicit parameters; `eventCallback` is the cached callback function pointer/wrapper in this file (assigned by `createEventCallback`), and this function nulls it after releasing.
 * - 接入方式: 在停止 ETW 会话且不再需要事件回调时调用：`unregisterCallback()`；建议与 stop/cleanup 逻辑同一收尾阶段执行，确保不会在回调仍可能被触发时提前释放。
 * - Integration: Call it when the ETW session is stopping and the event callback is no longer needed: `unregisterCallback()`; keep it in the same teardown stage as stop/cleanup so it is not released while callbacks may still fire.
 * - 错误处理: 若 `eventCallback` 为空则直接返回；`koffi.unregister` 失败会被吞掉并继续清理引用，避免停止流程因释放失败而中断。
 * - Error Handling: Returns early if `eventCallback` is empty; swallows `koffi.unregister` failures and still clears the reference so teardown does not abort due to unregister errors.
 * - 关键词: 回调释放 | callback release | unregisterCallback | koffi.unregister | eventCallback | createEventCallback | 资源清理 | resource cleanup | 幂等 | idempotent
 */
function unregisterCallback() {
    if (!eventCallback) return;
    try { koffi.unregister(eventCallback); } catch {}
    eventCallback = null;
}

/**
 * - 函数: `getElevationState`
 * - Function: `getElevationState`
 * - 作用: 读取当前 worker 进程的 Windows 提权状态，在启动 ETW 会话前判断是否具备管理员权限，以决定是否允许继续建链或直接返回权限错误。
 * - Purpose: Reads the Windows elevation state of the current worker process so ETW startup can verify administrator privileges before attempting session bootstrap or returning a permission error.
 * - 调用方: `startWithRetry` 在真正启动 ETW 会话前调用。
 * - Callers: Called by `startWithRetry` before the ETW session is actually started.
 * - 被调方: `GetCurrentProcess`、`OpenProcessToken`、`GetLastError`、`GetTokenInformation`、`CloseHandle`、`koffi.struct`、`Buffer.alloc`、`String`。
 * - Callees: `GetCurrentProcess`, `OpenProcessToken`, `GetLastError`, `GetTokenInformation`, `CloseHandle`, `koffi.struct`, `Buffer.alloc`, `String`.
 * - 变量说明: 无显式入参；`token` 为进程访问令牌句柄；`TOKEN_ELEVATION` 定义原生返回结构；`elevation` 为读取出的缓冲区；`retLen` 保存 API 返回长度；`isElevated` 为最终提权判定结果。
 * - Variables: No explicit parameters; `token` is the process token handle, `TOKEN_ELEVATION` defines the native return struct, `elevation` is the raw buffer, `retLen` captures the API output length, and `isElevated` is the final privilege decision.
 * - 接入方式: 仅适合作为 ETW 启动前的权限守卫；如果后续有更多依赖管理员权限的 worker 操作，应优先复用本函数统一判断，而不是在多处直接拼 Windows token 调用。
 * - Integration: Use it only as the privilege guard before ETW startup; if more worker operations begin to require elevation, reuse this function instead of duplicating Windows token calls in multiple places.
 * - 错误处理: 打开 token、读取 token 信息或结构解码失败时，统一返回 `{ ok: false, isElevated: false, error }`；无论成功失败都会在 `finally` 中尝试关闭句柄，避免 token 句柄泄漏。
 * - Error Handling: Failures while opening the token, querying token information, or decoding the structure all return `{ ok: false, isElevated: false, error }`; the handle is always closed in `finally` to avoid token leaks.
 * - 关键词: 提权检测 | elevation check | 管理员权限 | admin privilege | Windows令牌 | Windows token | ETW启动守卫 | ETW startup guard | 权限探测 | privilege probe
 */
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

/**
 * - 函数: `checkStatus`
 * - Function: `checkStatus`
 * - 作用: 统一检查 Windows/ETW API 的返回状态码：当 `status !== ERROR_SUCCESS` 时构造细节对象并通过 `postError('ETW_API_FAILED', ...)` 上报（对 `ERROR_ACCESS_DENIED` 给出提权提示），同时返回布尔值供上层决定是否继续流程。
 * - Purpose: Centralized status-code checker for Windows/ETW API calls: when `status !== ERROR_SUCCESS`, it builds a details object and reports via `postError('ETW_API_FAILED', ...)` (adds an elevation hint for `ERROR_ACCESS_DENIED`) and returns a boolean for callers to decide whether to continue.
 * - 调用方: 当前文件中暂未出现显式调用点（作为 ETW API 封装/调用处的通用状态检查原语预留）。
 * - Callers: No explicit call sites currently in this file (kept as a reusable primitive for ETW API wrappers/call sites).
 * - 被调方: `Object.assign`、`postError`。
 * - Callees: `Object.assign`, `postError`.
 * - 变量说明: `api` 为 API 名称或操作标识（用于错误信息）；`status` 为 API 返回码；`extra` 为可选附加字段对象（会合并进 `details`）；`details` 最终随错误事件上报，便于主进程侧诊断。
 * - Variables: `api` is the API name/operation label (for error messages); `status` is the returned status code; `extra` is an optional object merged into `details`; `details` is reported to the main process for diagnostics.
 * - 接入方式: 在调用任意返回 Windows 错误码/ETW 状态码的函数后调用：`if (!checkStatus('StartTrace', st, { sessionName })) return;`；不要直接在多处拼接 `postError('ETW_API_FAILED', ...)`，以便保持错误格式一致。
 * - Integration: Use it after any function that returns a Windows error code/ETW status: `if (!checkStatus('StartTrace', st, { sessionName })) return;`; avoid manually duplicating `postError('ETW_API_FAILED', ...)` across call sites so the error shape stays consistent.
 * - 错误处理: `status === ERROR_SUCCESS` 直接返回 `true`；否则上报并返回 `false`；本函数不抛异常，作为“状态码 → 错误事件”的轻量适配层。
 * - Error Handling: Returns `true` when `status === ERROR_SUCCESS`; otherwise reports and returns `false`; never throws and serves as a lightweight adapter from status-codes to error events.
 * - 关键词: 状态码检查 | status check | ERROR_SUCCESS | ERROR_ACCESS_DENIED | ETW_API_FAILED | 提权提示 | elevation hint | postError | 统一上报 | unified reporting | Object.assign | 诊断细节 | diagnostics details | Windows错误码 | Windows error code
 */
function checkStatus(api, status, extra) {
    if (status === ERROR_SUCCESS) return true;
    const details = { api, status };
    if (extra && typeof extra === 'object') Object.assign(details, extra);
    const message = api + ' failed: ' + status + (status === ERROR_ACCESS_DENIED ? '，可能需要以管理员权限运行' : '');
    postError('ETW_API_FAILED', message, details);
    return false;
}

/**
 * - 函数: `stopSessionInternal`
 * - Function: `stopSessionInternal`
 * - 作用: 执行一次底层 ETW Bridge 停止调用，负责确保桥接 DLL 与句柄已就绪，然后把超时参数传给 `EtwBridge_Stop`，是所有停止流程共享的最小原语。
 * - Purpose: Performs one low-level ETW Bridge stop operation by ensuring the bridge DLL and handle are ready and then passing the timeout to `EtwBridge_Stop`, serving as the minimal primitive shared by all stop flows.
 * - 调用方: `stopSession` 在对外停止会话时调用，`startSessionOnce` 在启动失败回滚阶段调用。
 * - Callers: Called by `stopSession` during external shutdown and by `startSessionOnce` during rollback after startup failure.
 * - 被调方: `ensureEtwBridgeLoaded`、`ensureEtwBridgeHandle`、`EtwBridge_Stop`、`postError`、`String`。
 * - Callees: `ensureEtwBridgeLoaded`, `ensureEtwBridgeHandle`, `EtwBridge_Stop`, `postError`, `String`.
 * - 变量说明: `timeoutMs` 为桥接停止超时；`h` 为当前 bridge 句柄；`st` 为 `EtwBridge_Stop` 返回状态码；异常分支中的 `e` 保存调用失败信息。
 * - Variables: `timeoutMs` is the bridge stop timeout, `h` is the current bridge handle, `st` is the `EtwBridge_Stop` status code, and `e` carries exception details if the native call fails.
 * - 接入方式: 只应作为 worker 内部低层停止原语使用；外部停止语义应通过 `stopSession` 暴露，这样仍能保留 drain、清理和幂等控制。
 * - Integration: Use it only as the worker's low-level stop primitive; external stop semantics should go through `stopSession` so draining, cleanup, and idempotency stay intact.
 * - 错误处理: 桥接加载失败、句柄为空、停止返回非零状态或原生调用抛异常时统一返回 `false` 并上报错误事件，不把异常继续抛到调用方。
 * - Error Handling: Bridge-load failures, missing handles, non-zero stop statuses, or native exceptions all return `false` and emit an error event instead of bubbling exceptions to callers.
 * - 关键词: 会话停止原语 | session stop primitive | Bridge停止 | bridge stop | 原生状态码 | native status code | 回滚清理 | rollback cleanup | ETW停链 | ETW shutdown
 */
function stopSessionInternal(timeoutMs) {
    if (!ensureEtwBridgeLoaded()) return false;
    const h = ensureEtwBridgeHandle();
    if (!h) return false;
    try {
        const st = EtwBridge_Stop(h, (timeoutMs >>> 0));
        if (st !== 0) {
            postError('ETW_BRIDGE_STOP_FAILED', 'EtwBridge_Stop failed: ' + st, { status: st });
            return false;
        }
        return true;
    } catch (e) {
        postError('ETW_BRIDGE_STOP_EXCEPTION', (e && e.message) ? e.message : String(e || 'EtwBridge_Stop'), { stack: e && e.stack ? String(e.stack) : '' });
        return false;
    }
}

/**
 * - 函数: `cleanupResources`
 * - Function: `cleanupResources`
 * - 作用: 在 ETW 会话停止或启动回滚后清理 worker 运行态，关闭 bridge 轮询器并重置 `isSessionRunning`、`isStopping` 等状态位，确保下一次启动能从干净状态开始。
 * - Purpose: Cleans up worker runtime state after ETW shutdown or startup rollback by stopping the bridge poller and resetting flags such as `isSessionRunning` and `isStopping`, so the next startup begins from a clean state.
 * - 调用方: `stopSession` 在正常停止后调用，`startSessionOnce` 在启动失败回滚时调用。
 * - Callers: Called by `stopSession` after a normal stop and by `startSessionOnce` during rollback when startup fails.
 * - 被调方: `stopBridgePoller`。
 * - Callees: `stopBridgePoller`.
 * - 变量说明: 无显式入参；全局状态 `isSessionRunning` 表示当前会话是否处于运行态，`isStopping` 表示是否正在执行停止流程，二者都会在本函数中复位。
 * - Variables: No explicit parameters; the global state `isSessionRunning` marks whether a session is active and `isStopping` marks whether a stop is in progress, and both are reset here.
 * - 接入方式: 仅应在会话生命周期收尾阶段调用；如果以后新增更多 ETW 运行态标记，应优先在本函数统一复位，避免停止路径出现遗漏。
 * - Integration: Call it only during session-lifecycle teardown; if more ETW runtime flags are introduced later, reset them here so shutdown paths do not drift apart.
 * - 错误处理: 依赖 `stopBridgePoller` 自身的守卫语义，本函数不额外抛错；即使部分资源已经提前释放，也应保持幂等并安全重复调用。
 * - Error Handling: It relies on the guard semantics inside `stopBridgePoller` and does not throw; even if some resources were already released earlier, the function is expected to remain idempotent and safe to call repeatedly.
 * - 关键词: 生命周期清理 | lifecycle cleanup | 状态复位 | state reset | 轮询器关闭 | poller shutdown | 幂等收尾 | idempotent teardown | ETW运行态 | ETW runtime
 */
function cleanupResources() {
    stopBridgePoller();
    isSessionRunning = false;
    isStopping = false;
}

/**
 * - 函数: `stopSession`
 * - Function: `stopSession`
 * - 作用: 作为 ETW worker 的对外停止入口，负责用 `stopPromise` 实现停止过程幂等化，串联底层停链、桥接消息排空和运行态清理，并将最终结果以 Promise 形式返回给控制消息流。
 * - Purpose: Acts as the external shutdown entry for the ETW worker by using `stopPromise` to make shutdown idempotent, chaining low-level stop, bridge-message draining, and runtime cleanup before returning the final result as a Promise to the control flow.
 * - 调用方: `parentPort.on('message')` 中的 `stop`/`pause` 指令分支，以及 `startSessionOnce` 失败后的回滚流程。
 * - Callers: Called by the `stop`/`pause` branches inside `parentPort.on('message')` and by rollback paths after `startSessionOnce` failures.
 * - 被调方: `stopSessionInternal`、`drainBridgeMessages`、`cleanupResources`。
 * - Callees: `stopSessionInternal`, `drainBridgeMessages`, `cleanupResources`.
 * - 变量说明: `timeoutMs` 为停止超时；全局 `stopPromise` 缓存当前停止流程 Promise；`ok` 表示底层停链结果；`isStopping` 会在停止开始时被置为 `true`。
 * - Variables: `timeoutMs` is the shutdown timeout, the global `stopPromise` caches the in-flight shutdown promise, `ok` is the low-level stop result, and `isStopping` is set to `true` when shutdown begins.
 * - 接入方式: 所有对外“停止或暂停 ETW 会话”的场景都应走本函数，而不是直接调用 `stopSessionInternal`，这样才能复用幂等控制和排空剩余 bridge 消息的语义。
 * - Integration: All external scenarios that stop or pause ETW sessions should go through this function instead of calling `stopSessionInternal` directly so they inherit idempotency and residual bridge-message draining.
 * - 错误处理: 通过 Promise 封装停止过程，避免重复停止触发并发竞争；`drainBridgeMessages` 异常会被局部吞掉，底层停止结果则转换为布尔值返回给上层消息分支。
 * - Error Handling: The shutdown sequence is wrapped in a Promise to avoid concurrent stop races; `drainBridgeMessages` failures are swallowed locally, and the low-level stop result is normalized to a boolean for upper control-message branches.
 * - 关键词: 停止入口 | shutdown entry | 幂等停止 | idempotent stop | Promise收敛 | promise convergence | 消息排空 | message draining | 会话收尾 | session teardown
 */
async function stopSession(timeoutMs) {
    if (stopPromise) return stopPromise;
    stopPromise = (async () => {
        isStopping = true;
        const ok = stopSessionInternal(timeoutMs);
        try { drainBridgeMessages(); } catch {}
        cleanupResources();
        return !!ok;
    })();
    return stopPromise;
}

/**
 * - 函数: `startWithRetry`
 * - Function: `startWithRetry`
 * - 作用: 作为 ETW worker 的启动总入口，负责缓存最近一次配置、解析最终 ETW 配置、预热设备路径映射、校验管理员权限，并在启动失败时按重试策略反复调用 `startSessionOnce` 建立监听会话。
 * - Purpose: Serves as the ETW worker bootstrap entry by caching the latest config, resolving the effective ETW settings, priming device-path mapping, checking elevation, and retrying `startSessionOnce` until the retry policy is exhausted.
 * - 调用方: `parentPort.on('message')` 中收到 `start` 或 `resume` 指令后的 worker 控制入口。
 * - Callers: The worker control entry inside `parentPort.on('message')` when a `start` or `resume` command is received.
 * - 被调方: `resolveEtwCfg`、`postMessage`、`primeDriveDeviceMapOnce`、`getElevationState`、`postError`、`startSessionOnce`、`sleepSync`。
 * - Callees: `resolveEtwCfg`, `postMessage`, `primeDriveDeviceMapOnce`, `getElevationState`, `postError`, `startSessionOnce`, `sleepSync`.
 * - 变量说明: `payloadCfg` 为主进程下发的启动配置；`lastPayloadCfg` 缓存最近一次可复用配置；`etwCfg` 为归一化后的生效配置；`attempt` 记录当前重试次数；`retries`/`delayMs` 控制重试上限与退避间隔。
 * - Variables: `payloadCfg` is the startup config sent from the main process; `lastPayloadCfg` caches the latest reusable config; `etwCfg` is the normalized effective config; `attempt` tracks retry count; `retries` and `delayMs` control retry limits and backoff.
 * - 接入方式: 仅供本 worker 内部通过消息循环触发；若新增启动指令，优先复用本函数而不是直接调用 `startSessionOnce`，这样可保留权限校验、默认配置合并与失败重试语义。
 * - Integration: Trigger it from the worker message loop only; if you add a new startup command, route it through this function instead of calling `startSessionOnce` directly so permission checks, config normalization, and retry semantics stay intact.
 * - 错误处理: 在 ETW 被禁用时发送状态消息直接返回；权限不足时发送 `ETW_PERMISSION`；单次建链异常时发送 `ETW_START_FAILED` 并在超过重试次数后停止，不把异常继续抛回消息循环。
 * - Error Handling: Emits a status and returns when ETW is disabled; reports `ETW_PERMISSION` when elevation is missing; on single-start failure it posts `ETW_START_FAILED` and stops after the retry budget is exhausted instead of bubbling the exception to the message loop.
 * - 关键词: ETW工作线程 | ETW worker | 启动重试 | startup retry | 提权校验 | elevation check | 配置归一化 | config normalization | 会话启动 | session bootstrap
 */
async function startWithRetry(payloadCfg) {
    lastPayloadCfg = payloadCfg || lastPayloadCfg;
    etwCfg = resolveEtwCfg(payloadCfg);
    if (!etwCfg.enabled) {
        postMessage({ type: 'status', message: 'ETW disabled by config' });
        return;
    }

    primeDriveDeviceMapOnce();

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

/**
 * - 函数: `guidToBuffer`
 * - Function: `guidToBuffer`
 * - 作用: 将 GUID 结构（`{ Data1, Data2, Data3, Data4 }`）编码为 16 字节小端序 Buffer，便于后续在 ETW/FFI 场景中拼装二进制结构体或向 native 接口传参。
 * - Purpose: Encodes a GUID struct (`{ Data1, Data2, Data3, Data4 }`) into a 16-byte little-endian Buffer, useful for assembling binary structs or passing parameters in ETW/FFI/native interop scenarios.
 * - 调用方: 暂无（当前文件内未发现调用点，保留供 ETW 结构体/FFI 拼装使用）。
 * - Callers: None currently (no call sites found in this file; kept for ETW struct/FFI assembly use).
 * - 被调方: `Buffer.alloc`、`Buffer#writeUInt32LE`、`Buffer#writeUInt16LE`、`Buffer.from`、`Buffer#copy`。
 * - Callees: `Buffer.alloc`, `Buffer#writeUInt32LE`, `Buffer#writeUInt16LE`, `Buffer.from`, `Buffer#copy`.
 * - 变量说明: `g` 为 GUID 结构体对象（Data1/2/3 为数值，Data4 为长度 8 的字节数组或 Buffer）；`b` 为输出的 16 字节 Buffer。
 * - Variables: `g` is the GUID struct object (Data1/2/3 are numbers, Data4 is an 8-byte array or Buffer); `b` is the output 16-byte Buffer.
 * - 接入方式: 在需要将 koffi/native 返回的 GUID 结构转换为二进制表示时调用；调用方应保证 `g` 字段齐全且类型正确，避免在写入过程中触发运行时异常。
 * - Integration: Call it when converting a GUID struct returned from koffi/native into binary form; callers should ensure `g` fields are present and correctly typed to avoid runtime errors while writing.
 * - 错误处理: 本函数不做字段校验；若 `g` 缺字段或类型不匹配，底层 Buffer 写入可能抛错并向上传播，建议在调用点做输入校验或用 try/catch 包裹。
 * - Error Handling: This function does not validate fields; missing/invalid `g` fields may cause Buffer writes to throw and propagate upward, so validate inputs or wrap calls with try/catch at the call site.
 * - 关键词: GUID编码 | GUID encode | guidToBuffer | little-endian | Buffer | ETW结构体 | ETW struct | FFI | native interop | koffi | 二进制拼装 | binary assembly | Data1/Data2/Data3/Data4 | 16字节 | 16 bytes
 */
function guidToBuffer(g) {
    const b = Buffer.alloc(16);
    b.writeUInt32LE(g.Data1, 0);
    b.writeUInt16LE(g.Data2, 4);
    b.writeUInt16LE(g.Data3, 6);
    Buffer.from(g.Data4).copy(b, 8);
    return b;
}

/**
 * - 函数: `startSessionOnce`
 * - Function: `startSessionOnce`
 * - 作用: 执行一次 ETW 会话建链，负责加载桥接 DLL、初始化桥接句柄、下发规则与上下文容量、计算各 provider 关键字并最终调用 `EtwBridge_Start` 开始消费内核事件，是 ETW 监听真正落地的单次启动动作。
 * - Purpose: Performs one ETW session bootstrap by loading the bridge DLL, initializing the bridge handle, pushing matching rules and context capacity, calculating provider keywords, and finally calling `EtwBridge_Start` to begin consuming kernel events.
 * - 调用方: `startWithRetry`。
 * - Callers: `startWithRetry`.
 * - 被调方: `ensureEtwBridgeLoaded`、`ensureEtwBridgeHandle`、`EtwBridge_SetContextCapacity`、`EtwBridge_SetTrackedPids`、`EtwBridge_SetRulesJson`、`postMessage`、`getProviderKeywords`、`EtwBridge_Start`、`startBridgePoller`、`drainBridgeMessages`、`stopSessionInternal`、`cleanupResources`。
 * - Callees: `ensureEtwBridgeLoaded`, `ensureEtwBridgeHandle`, `EtwBridge_SetContextCapacity`, `EtwBridge_SetTrackedPids`, `EtwBridge_SetRulesJson`, `postMessage`, `getProviderKeywords`, `EtwBridge_Start`, `startBridgePoller`, `drainBridgeMessages`, `stopSessionInternal`, `cleanupResources`.
 * - 变量说明: 无显式入参；`h` 为桥接句柄；`mcfg` 为规则匹配配置；`rulesFile`/`rulesPath` 指向规则文件；`ctxCap` 控制每个 PID 保留的上下文数量；`kw1`~`kw4` 为进程、文件、注册表、网络 provider 关键字；`st` 为 `EtwBridge_Start` 返回状态。
 * - Variables: No explicit parameters; `h` is the bridge handle; `mcfg` stores matching config; `rulesFile`/`rulesPath` point to the rules file; `ctxCap` controls per-PID context capacity; `kw1` through `kw4` store provider keywords for process, file, registry, and network events; `st` is the `EtwBridge_Start` status code.
 * - 接入方式: 仅在 worker 内部作为低层启动原语使用；上层应通过 `startWithRetry` 间接调用，除非你明确希望绕过权限校验与重试策略进行一次性实验启动。
 * - Integration: Use it as a low-level startup primitive inside the worker only; higher-level flows should normally call it indirectly through `startWithRetry` unless you intentionally want a one-shot experimental start without retry orchestration.
 * - 错误处理: 对规则加载、桥接配置等非关键步骤采用局部兜底；对桥接启动阶段的不可恢复异常执行 `stopSessionInternal` 和 `cleanupResources` 后重新抛出，交由 `startWithRetry` 统一决策是否重试。
 * - Error Handling: Uses local fallback handling for non-critical steps such as rule loading and bridge configuration; for unrecoverable startup failures it runs `stopSessionInternal` and `cleanupResources`, then rethrows so `startWithRetry` can decide whether to retry.
 * - 关键词: ETW会话 | ETW session | 桥接启动 | bridge start | 规则加载 | rule loading | 关键字过滤 | keyword filtering | 内核事件 | kernel events
 */
async function startSessionOnce() {
    if (isSessionRunning) return;
    isStopping = false;
    stopPromise = null;

    try {
        if (!ensureEtwBridgeLoaded()) return;
        const h = ensureEtwBridgeHandle();
        if (!h) return;
        try {
            const mcfg = (etwCfg && etwCfg.matching && typeof etwCfg.matching === 'object') ? etwCfg.matching : null;
            const rulesFile = mcfg && typeof mcfg.rulesFile === 'string' && mcfg.rulesFile ? mcfg.rulesFile : '';
            const rulesPath = rulesFile ? (path.isAbsolute(rulesFile) ? rulesFile : path.resolve(__dirname, '../../..', rulesFile)) : '';
        const ctxCap = mcfg && Number.isFinite(mcfg.contextPerPid) ? Math.max(1, Math.min(100, Math.floor(mcfg.contextPerPid))) : 100;
            const includeChildren = mcfg && mcfg.includeChildren === true ? 1 : 0;
            if (EtwBridge_SetContextCapacity) {
                try { EtwBridge_SetContextCapacity(h, ctxCap >>> 0); } catch {}
            }
            if (EtwBridge_SetTrackedPids) {
                try { EtwBridge_SetTrackedPids(h, null, 0, includeChildren); } catch {}
            }
            if (EtwBridge_SetRulesJson && rulesPath && fs.existsSync(rulesPath)) {
                try {
                    const raw = fs.readFileSync(rulesPath, 'utf-8');
                    if (raw && typeof raw === 'string') {
                        const rc = EtwBridge_SetRulesJson(h, raw);
                        postMessage({ type: 'status', message: `ETW matching rules loaded: ${rc}` });
                    }
                } catch {}
            } else if (rulesPath) {
                try { postMessage({ type: 'status', message: `ETW matching rules not found: ${rulesPath}` }); } catch {}
            }
        } catch {}
        const kw1 = getProviderKeywords(etwCfg, 'Process');
        const kw2 = getProviderKeywords(etwCfg, 'File');
        const kw3 = getProviderKeywords(etwCfg, 'Registry');
        const kw4 = getProviderKeywords(etwCfg, 'Network');

        const netCfg = (etwCfg && etwCfg.network && typeof etwCfg.network === 'object') ? etwCfg.network : (DEFAULT_ETW_CFG.network || {});
        const netEnabled = !(netCfg && netCfg.enabled === false);
        const filterPrivateIps = !(netCfg && netCfg.filterPrivateIps === false);
        const skipLoopback = !(netCfg && netCfg.skipLoopback === false);

        const maxBytes = (etwCfg && Number.isFinite(etwCfg.userDataMaxBytes)) ? etwCfg.userDataMaxBytes : DEFAULT_ETW_CFG.userDataMaxBytes;
        const cappedMaxBytes = Math.max(1024, Math.min(50 * 1024 * 1024, maxBytes));

        const st = EtwBridge_Start(
            h,
            kw1.any, kw1.all,
            kw2.any, kw2.all,
            kw3.any, kw3.all,
            kw4.any, kw4.all,
            netEnabled ? 1 : 0,
            filterPrivateIps ? 1 : 0,
            skipLoopback ? 1 : 0,
            cappedMaxBytes >>> 0
        );
        if (st !== 0) {
            if (st === 5 || st === -1073741790 || st === 3221225506) {
                const codeHex = (st >>> 0).toString(16).toUpperCase();
                postError('ETW_PERMISSION', `权限不足：需要管理员权限才能启动 ETW 监听 (错误代码: 0x${codeHex})`, { suggestion: '请以管理员身份运行程序', status: st });
                return;
            }
            postError('ETW_BRIDGE_START_FAILED', 'EtwBridge_Start failed: ' + st, { status: st });
            return;
        }

        isSessionRunning = true;
        startBridgePoller();
        drainBridgeMessages();
    } catch (e) {
        try { isStopping = true; } catch {}
        try { stopSessionInternal((etwCfg && etwCfg.stopTimeoutMs) ? etwCfg.stopTimeoutMs : DEFAULT_ETW_CFG.stopTimeoutMs); } catch {}
        try { cleanupResources(); } catch {}
        throw e;
    }
}

/**
 * - 入口: `parentPort.on('message')`
 * - Entry: `parentPort.on('message')`
 * - 作用: 作为 ETW worker 的主控消息入口，负责分发 `start`、`stop`、`pause`、`resume`、`config`、`trusted_seed_snapshot`、`trusted_add` 等指令到对应控制流程。
 * - Purpose: Serves as the control-message entry for the ETW worker, dispatching commands such as `start`, `stop`, `pause`, `resume`, `config`, `trusted_seed_snapshot`, and `trusted_add` to their corresponding control paths.
 * - 调用方: 主进程通过 `Worker.postMessage(...)` 下发的 ETW 生命周期控制与可信进程同步消息。
 * - Callers: ETW lifecycle-control and trusted-process synchronization messages sent by the main process through `Worker.postMessage(...)`.
 * - 被调方: `startWithRetry`、`stopSession`、`resolveEtwCfg`、`trustedPidFilter.seedFromSnapshot`、`trustedPidFilter.addUserTrustedPath`、`trustedPidFilter.addTrustedPid`、`postMessage`、`postError`。
 * - Callees: `startWithRetry`, `stopSession`, `resolveEtwCfg`, `trustedPidFilter.seedFromSnapshot`, `trustedPidFilter.addUserTrustedPath`, `trustedPidFilter.addTrustedPid`, `postMessage`, `postError`.
 * - 变量说明: `msg` 为主进程下发的控制消息；`cfg` 为 `start/config` 指令携带的配置；`timeoutMs` 为停止会话超时；`reqId` 为 `pause/resume` 的响应关联标识；`list`/`paths`/`pids` 为可信种子同步载荷。
 * - Variables: `msg` is the inbound control message from the main process, `cfg` carries config for `start`/`config`, `timeoutMs` is the stop timeout, `reqId` correlates `pause`/`resume` responses, and `list`/`paths`/`pids` hold trusted-seed synchronization payloads.
 * - 接入方式: 若主进程新增 ETW 控制指令，应优先在此入口扩展分发分支，并尽量复用现有 `startWithRetry`、`stopSession` 和 `postMessage` 语义，而不是在其他位置旁路修改 worker 状态。
 * - Integration: When the main process introduces new ETW control commands, extend dispatching here first and reuse existing `startWithRetry`, `stopSession`, and `postMessage` semantics instead of mutating worker state through side paths.
 * - 错误处理: 单条消息处理异常会统一转成 `ETW_MESSAGE_HANDLER_ERROR` 上报，避免某个控制指令异常导致整个 worker 消息循环退出；`pause/resume` 还会通过 `ok: false` 给主进程显式反馈失败。
 * - Error Handling: Failures while handling an individual message are reported as `ETW_MESSAGE_HANDLER_ERROR` so one bad command does not terminate the worker message loop; `pause` and `resume` also send explicit `ok: false` replies on failure.
 * - 关键词: 消息入口 | message entry | 生命周期控制 | lifecycle control | 暂停恢复 | pause resume | 配置热更 | config refresh | 可信同步 | trusted sync
 */
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
                    try {
                        if (EtwBridge_Destroy && etwBridgeHandle) EtwBridge_Destroy(etwBridgeHandle);
                    } catch {}
                    etwBridgeHandle = null;
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
            if (msg && typeof msg === 'object' && msg.type === 'trusted_seed_snapshot') {
                const list = Array.isArray(msg.list) ? msg.list : [];
                try { trustedPidFilter.seedFromSnapshot(list); } catch {}
                return;
            }
            if (msg && typeof msg === 'object' && msg.type === 'trusted_add') {
                const paths = Array.isArray(msg.paths) ? msg.paths : [];
                for (const p of paths) {
                    try { trustedPidFilter.addUserTrustedPath(p); } catch {}
                }
                const pids = Array.isArray(msg.pids) ? msg.pids : [];
                for (const pid of pids) {
                    const p = asPid(pid);
                    if (p != null) {
                        try { trustedPidFilter.addTrustedPid(p); } catch {}
                        extraTrustedPids.add(p);
                    }
                }
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
        parseKeyword64,
        mergeProviders,
        getProviderKeywords,
        filetimeToIso,
        extractUtf16Strings,
        parseRegistryUserData,
        parseNetworkUserDataHeuristic,
        pickBestPathCandidate,
        resolveEtwCfg,
        mapRegistryOp,
        mapNetworkOp,
        mapFileOp,
        readUInt32LESafe,
        tryDecodeEventRecord,
        normalizeEventRecordPtr,
        shouldSkipByFilters
    }
};
