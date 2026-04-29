const fs = require('fs');
const path = require('path');
const koffi = require('koffi');

const libKernel32 = koffi.load('kernel32.dll');
const libPsapi = koffi.load('psapi.dll');
let libNtdll = null;
try {
    libNtdll = koffi.load('ntdll.dll');
} catch (e) {
    console.warn('Failed to load ntdll.dll', e);
}
let libWintrust = null;
try {
    libWintrust = koffi.load('wintrust.dll');
} catch (e) {
    console.warn('Failed to load wintrust.dll', e);
}
let libAdvapi32 = null;
try {
    libAdvapi32 = koffi.load('advapi32.dll');
} catch (e) {
    console.warn('Failed to load advapi32.dll', e);
}

let trustBridgeLib = null;
let TrustBridge_SetCacheConfig = null;
let TrustBridge_VerifyFile = null;
let TrustBridge_GetSignerInfoJson = null;
let TrustBridge_ComputeFileSha256Hex = null;
let TrustBridge_ScanCacheLookupByFile = null;
let TrustBridge_ScanCacheLookupByFile2 = null;
let TrustBridge_ScanCacheStore = null;
let TrustBridge_Free = null;

/**
 * - 函数: `resolveTrustBridgeDllPath`
 * - Function: `resolveTrustBridgeDllPath`
 * - 作用: 按打包资源目录和开发态目录顺序查找 `trust_bridge.dll`，为 TrustBridge 懒加载提供唯一的 DLL 定位入口。
 * - Purpose: Resolves `trust_bridge.dll` from packaged resources and development directories in order, acting as the single DLL locator for TrustBridge lazy loading.
 * - 调用方: `tryLoadTrustBridge`。
 * - Callers: `tryLoadTrustBridge`.
 * - 被调方: `path.join`、`fs.existsSync`、数组 `push`。
 * - Callees: `path.join`, `fs.existsSync`, and array `push`.
 * - 变量说明: 无显式入参；`candidates` 保存候选 DLL 路径；`p` 为逐个检测的候选项。
 * - Variables: There are no explicit parameters; `candidates` stores possible DLL paths, and `p` is the candidate being checked.
 * - 接入方式: 仅应由 TrustBridge 初始化链路调用；如果以后扩展更多打包位置，也应继续集中在本函数追加候选路径。
 * - Integration: It should stay internal to the TrustBridge bootstrap flow; if more packaging locations are added later, extend the candidate list here.
 * - 错误处理: 路径拼接和文件存在性检查都包在局部 `try` 中，任一候选失败只会被跳过，最终未命中时返回 `null`。
 * - Error Handling: Path composition and existence checks are wrapped in local `try` blocks, so any failing candidate is skipped and the function returns `null` when nothing resolves.
 * - 关键词: TrustBridge路径解析 | TrustBridge path resolution | DLL候选查找 | DLL candidate lookup | 打包资源目录 | packaged resources | 开发态回退 | development fallback | 原生库定位 | native library location
 */
function resolveTrustBridgeDllPath() {
    const candidates = [];
    try {
        if (process && typeof process.resourcesPath === 'string' && process.resourcesPath) {
            candidates.push(path.join(process.resourcesPath, 'native', 'win32-x64', 'trust_bridge.dll'));
        }
    } catch {}
    try {
        candidates.push(path.join(__dirname, '../../native/bin/win32-x64/trust_bridge.dll'));
    } catch {}
    for (const p of candidates) {
        try {
            if (p && fs.existsSync(p)) return p;
        } catch {}
    }
    return null;
}

/**
 * - 函数: `tryLoadTrustBridge`
 * - Function: `tryLoadTrustBridge`
 * - 作用: 懒加载 `trust_bridge.dll` 并绑定签名验证、签名信息查询、文件哈希和扫描缓存相关导出，是本模块所有 TrustBridge 能力的统一初始化入口。
 * - Purpose: Lazily loads `trust_bridge.dll` and binds exports for trust verification, signer-info lookup, file hashing, and scan-cache operations, serving as the shared initialization entry for all TrustBridge-backed features in this module.
 * - 调用方: `verifyTrust`、`getSignerInfo`、`computeFileSha256Hex`、`scanCacheLookupByFile`、`scanCacheStore` 等需要 TrustBridge 原生能力的封装函数。
 * - Callers: Used by wrapper functions that depend on TrustBridge native capabilities, including `verifyTrust`, `getSignerInfo`, `computeFileSha256Hex`, `scanCacheLookupByFile`, and `scanCacheStore`.
 * - 被调方: `resolveTrustBridgeDllPath`、`koffi.load`、`trustBridgeLib.func`、`TrustBridge_SetCacheConfig`、`console.warn`。
 * - Callees: `resolveTrustBridgeDllPath`, `koffi.load`, `trustBridgeLib.func`, `TrustBridge_SetCacheConfig`, and `console.warn`.
 * - 变量说明: 无显式入参；模块级变量 `trustBridgeLib` 保存 DLL 句柄；`TrustBridge_*` 系列变量保存各导出函数指针；`dllPath` 为解析出的原生库路径。
 * - Variables: There are no explicit parameters; the module-level `trustBridgeLib` stores the DLL handle, `TrustBridge_*` variables keep native function pointers, and `dllPath` is the resolved library path.
 * - 接入方式: 仅应由本模块内对外封装函数间接调用；新增 TrustBridge 能力时先扩展本函数绑定，再在外层新增语义化包装，不要在其他文件重复加载 DLL。
 * - Integration: It should only be invoked indirectly through wrappers in this module; when new TrustBridge capabilities are added, extend the bindings here first and then expose a semantic wrapper instead of reloading the DLL elsewhere.
 * - 错误处理: 找不到 DLL 或绑定任一关键导出失败时返回 `false`，并清空已写入的函数指针；异常只记录告警，不向上抛出，方便上层能力自行回退到禁用状态。
 * - Error Handling: It returns `false` when the DLL cannot be found or a critical export binding fails, resetting any partially initialized function pointers; exceptions are logged as warnings instead of being rethrown so upper layers can degrade gracefully.
 * - 关键词: TrustBridge装载 | TrustBridge loading | 原生导出绑定 | native export binding | DLL懒加载 | DLL lazy load | 签名验证桥 | trust bridge | 缓存接口初始化 | cache API bootstrap
 */
function tryLoadTrustBridge() {
    if (trustBridgeLib) return true;
    const dllPath = resolveTrustBridgeDllPath();
    if (!dllPath) return false;
    try {
        trustBridgeLib = koffi.load(dllPath);
        TrustBridge_SetCacheConfig = trustBridgeLib.func('__cdecl', 'TrustBridge_SetCacheConfig', 'int', ['uint32_t', 'uint32_t']);
        TrustBridge_VerifyFile = trustBridgeLib.func('__cdecl', 'TrustBridge_VerifyFile', 'int', ['string16', koffi.out('uint32_t *')]);
        TrustBridge_GetSignerInfoJson = trustBridgeLib.func('__cdecl', 'TrustBridge_GetSignerInfoJson', 'int', ['string16', koffi.out(koffi.pointer('void *', 2))]);
        try { TrustBridge_ComputeFileSha256Hex = trustBridgeLib.func('__cdecl', 'TrustBridge_ComputeFileSha256Hex', 'int', ['string16', koffi.out(koffi.pointer('void *', 2))]); } catch { TrustBridge_ComputeFileSha256Hex = null; }
        try { TrustBridge_ScanCacheLookupByFile = trustBridgeLib.func('__cdecl', 'TrustBridge_ScanCacheLookupByFile', 'int', ['string16', koffi.out('int *'), koffi.out(koffi.pointer('void *', 2))]); } catch { TrustBridge_ScanCacheLookupByFile = null; }
        try { TrustBridge_ScanCacheLookupByFile2 = trustBridgeLib.func('__cdecl', 'TrustBridge_ScanCacheLookupByFile2', 'int', ['string16', koffi.out('int *'), 'void *', 'int']); } catch { TrustBridge_ScanCacheLookupByFile2 = null; }
        try { TrustBridge_ScanCacheStore = trustBridgeLib.func('__cdecl', 'TrustBridge_ScanCacheStore', 'int', ['string', 'int']); } catch { TrustBridge_ScanCacheStore = null; }
        TrustBridge_Free = trustBridgeLib.func('__cdecl', 'TrustBridge_Free', 'void', ['void *']);
        try { TrustBridge_SetCacheConfig(4096, 600000); } catch {}
        return true;
    } catch (e) {
        trustBridgeLib = null;
        TrustBridge_SetCacheConfig = null;
        TrustBridge_VerifyFile = null;
        TrustBridge_GetSignerInfoJson = null;
        TrustBridge_ComputeFileSha256Hex = null;
        TrustBridge_ScanCacheLookupByFile = null;
        TrustBridge_ScanCacheLookupByFile2 = null;
        TrustBridge_ScanCacheStore = null;
        TrustBridge_Free = null;
        console.warn('Failed to load trust_bridge.dll', e);
        return false;
    }
}

const HANDLE = koffi.pointer('HANDLE', koffi.opaque());
const HMODULE = koffi.pointer('HMODULE', koffi.opaque());
const LPWSTR = koffi.pointer('LPWSTR', 'uint16_t');
const DWORD = 'uint32_t';
const BOOL = 'int';
const LONG = 'long';

const GUID = koffi.struct('GUID', {
    Data1: 'uint32_t',
    Data2: 'uint16_t',
    Data3: 'uint16_t',
    Data4: koffi.array('uint8_t', 8)
});

const WINTRUST_FILE_INFO = koffi.struct('WINTRUST_FILE_INFO', {
    cbStruct: 'uint32_t',
    pcwszFilePath: 'string16',
    hFile: 'HANDLE',
    pgKnownSubject: koffi.pointer(GUID)
});

const WINTRUST_DATA = koffi.struct('WINTRUST_DATA', {
    cbStruct: 'uint32_t',
    pPolicyCallbackData: 'void *',
    pSIPClientData: 'void *',
    dwUIChoice: 'uint32_t',
    fdwRevocationChecks: 'uint32_t',
    dwUnionChoice: 'uint32_t',
    pFile: koffi.pointer(WINTRUST_FILE_INFO),
    dwStateAction: 'uint32_t',
    hWVTStateData: 'HANDLE',
    pwszURLReference: 'string16',
    dwProvFlags: 'uint32_t',
    dwUIContext: 'uint32_t',
    pSignatureSettings: 'void *'
});

const PROCESS_QUERY_INFORMATION = 0x0400;
const PROCESS_VM_READ = 0x0010;
const PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
const SYNCHRONIZE = 0x00100000;
const PROCESS_SUSPEND_RESUME = 0x0800;
const PROCESS_TERMINATE = 0x0001;
const MAX_PATH = 260;
const READ_CONTROL = 0x00020000;
const WRITE_DAC = 0x00040000;
const FILE_SHARE_READ = 0x00000001;
const FILE_SHARE_WRITE = 0x00000002;
const OPEN_EXISTING = 3;
const FILE_ATTRIBUTE_NORMAL = 0x00000080;

const WTD_UI_NONE = 2;
const WTD_REVOKE_NONE = 0x00000000;
const WTD_CHOICE_FILE = 1;
const WTD_STATEACTION_VERIFY = 0x00000001;
const WTD_STATEACTION_CLOSE = 0x00000002;
const WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00000010;
const TRUST_E_NOSIGNATURE = 0x800B0100;
const TRUST_E_EXPLICIT_DISTRUST = 0x800B0111;
const TRUST_E_SUBJECT_NOT_TRUSTED = 0x800B0004;
const CRYPT_E_SECURITY_SETTINGS = 0x80092026;
const ERROR_SUCCESS = 0;
const SE_KERNEL_OBJECT = 6;
const SE_FILE_OBJECT = 1;
const DACL_SECURITY_INFORMATION = 0x00000004;
const SDDL_EVERYONE_FULL = 'D:(A;;GA;;;WD)(A;;GA;;;SY)(A;;GA;;;BA)';

const OpenProcess = libKernel32.func('__stdcall', 'OpenProcess', HANDLE, [DWORD, BOOL, DWORD]);
const CloseHandle = libKernel32.func('__stdcall', 'CloseHandle', BOOL, [HANDLE]);
const TerminateProcess = libKernel32.func('__stdcall', 'TerminateProcess', BOOL, [HANDLE, DWORD]);
const QueryDosDeviceW = libKernel32.func('__stdcall', 'QueryDosDeviceW', DWORD, ['string16', koffi.out(LPWSTR), DWORD]);
const lstrlenA = libKernel32.func('__stdcall', 'lstrlenA', 'int', ['void *']);
const LocalFree = libKernel32.func('__stdcall', 'LocalFree', 'void *', ['void *']);
const GetLastError = libKernel32.func('__stdcall', 'GetLastError', DWORD, []);
const CreateFileW = libKernel32.func('__stdcall', 'CreateFileW', HANDLE, ['string16', DWORD, DWORD, 'void *', DWORD, DWORD, HANDLE]);
const EnumProcesses = libPsapi.func('__stdcall', 'EnumProcesses', BOOL, [koffi.out('uint32_t *'), DWORD, koffi.out('uint32_t *')]);
const EnumProcessModules = libPsapi.func('__stdcall', 'EnumProcessModules', BOOL, [HANDLE, koffi.out('void *'), DWORD, koffi.out('uint32_t *')]);
const GetModuleFileNameExW = libPsapi.func('__stdcall', 'GetModuleFileNameExW', DWORD, [HANDLE, HMODULE, koffi.out(LPWSTR), DWORD]);
const QueryFullProcessImageNameW = libKernel32.func('__stdcall', 'QueryFullProcessImageNameW', BOOL, [HANDLE, DWORD, koffi.out(LPWSTR), koffi.inout('uint32_t *')]);

let NtSuspendProcess = null;
let NtResumeProcess = null;
if (libNtdll) {
    try {
        NtSuspendProcess = libNtdll.func('__stdcall', 'NtSuspendProcess', LONG, [HANDLE]);
        NtResumeProcess = libNtdll.func('__stdcall', 'NtResumeProcess', LONG, [HANDLE]);
    } catch (e) {
        console.warn('Failed to bind NtSuspendProcess/NtResumeProcess', e);
        NtSuspendProcess = null;
        NtResumeProcess = null;
    }
}

let WinVerifyTrust = null;
if (libWintrust) {
    try {
        WinVerifyTrust = libWintrust.func('__stdcall', 'WinVerifyTrust', LONG, ['void *', koffi.pointer(GUID), koffi.pointer(WINTRUST_DATA)]);
    } catch (e) {
        console.warn('Failed to bind WinVerifyTrust', e);
    }
}
let ConvertStringSecurityDescriptorToSecurityDescriptorW = null;
let GetSecurityDescriptorDacl = null;
let SetNamedSecurityInfoW = null;
let SetSecurityInfo = null;
if (libAdvapi32) {
    try {
        ConvertStringSecurityDescriptorToSecurityDescriptorW = libAdvapi32.func('__stdcall', 'ConvertStringSecurityDescriptorToSecurityDescriptorW', BOOL, ['string16', DWORD, koffi.out(koffi.pointer('void *', 2)), koffi.out('uint32_t *')]);
        GetSecurityDescriptorDacl = libAdvapi32.func('__stdcall', 'GetSecurityDescriptorDacl', BOOL, ['void *', koffi.out('int *'), koffi.out(koffi.pointer('void *', 2)), koffi.out('int *')]);
        SetNamedSecurityInfoW = libAdvapi32.func('__stdcall', 'SetNamedSecurityInfoW', DWORD, ['string16', DWORD, DWORD, 'void *', 'void *', 'void *', 'void *']);
        SetSecurityInfo = libAdvapi32.func('__stdcall', 'SetSecurityInfo', DWORD, [HANDLE, DWORD, DWORD, 'void *', 'void *', 'void *', 'void *']);
    } catch (e) {
        console.warn('Failed to bind advapi32 security functions', e);
        ConvertStringSecurityDescriptorToSecurityDescriptorW = null;
        GetSecurityDescriptorDacl = null;
        SetNamedSecurityInfoW = null;
        SetSecurityInfo = null;
    }
}

const ACTION_GENERIC_VERIFY_V2 = {
    Data1: 0x00AAC56B,
    Data2: 0xCD44,
    Data3: 0x11D0,
    Data4: [0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE]
};

const trustedCache = new Map();

/**
 * - 函数: `verifyTrust`
 * - Function: `verifyTrust`
 * - 作用: 判断指定文件是否被系统信任签名，优先走 `trust_bridge.dll` 的快速验证路径，缺失时再回退到 `WinVerifyTrust`，为主进程扫描、ETW 风险过滤和拦截快照提供统一签名判定。
 * - Purpose: Determines whether a file carries a trusted signature, preferring the fast `trust_bridge.dll` verification path and falling back to `WinVerifyTrust` when needed, so main-process scans, ETW risk filtering, and interception snapshots share one trust decision source.
 * - 调用方: `main.js` 的启动注入扫描与 IPC `scanner:verifyTrust`、`scanner_client.js` 的签名判断包装、`interception_snapshot_worker.js`、`etw_risk_worker.js` 以及本模块内部的进程路径枚举链路都会调用。
 * - Callers: Used by the startup injection scan and `scanner:verifyTrust` IPC in `main.js`, the signing wrapper in `scanner_client.js`, `interception_snapshot_worker.js`, `etw_risk_worker.js`, and the internal process-path enumeration flow in this module.
 * - 被调方: `tryLoadTrustBridge`、`TrustBridge_VerifyFile`、`WinVerifyTrust`、`trustedCache.has/get/set`、`koffi.sizeof`。
 * - Callees: `tryLoadTrustBridge`, `TrustBridge_VerifyFile`, `WinVerifyTrust`, `trustedCache.has/get/set`, and `koffi.sizeof`.
 * - 变量说明: `filePath` 为待验证文件路径；`trustedCache` 缓存 WinVerifyTrust 结果；`fileInfo`/`winTrustData` 为 WinVerifyTrust 调用所需原生结构；`status` 为系统验证状态码。
 * - Variables: `filePath` is the target file path, `trustedCache` caches `WinVerifyTrust` results, `fileInfo` and `winTrustData` are native structures for the WinVerifyTrust call, and `status` is the returned verification status code.
 * - 接入方式: 所有需要“已签名/未签名”判定的主进程或 worker 逻辑都应通过本函数接入；不要在业务侧直接拼 `WinVerifyTrust` 或重复维护另一套签名缓存。
 * - Integration: Any main-process or worker logic that needs a signed/unsigned decision should route through this function; do not assemble `WinVerifyTrust` calls directly in business code or maintain another signature cache elsewhere.
 * - 错误处理: TrustBridge 调用失败时直接回退 `false`；系统 API 路径会在验证完成后主动发送 CLOSE 状态释放句柄，异常场景仅打印错误并返回 `false`，避免签名验证错误阻断扫描主流程。
 * - Error Handling: TrustBridge failures immediately fall back to `false`; on the system-API path the function explicitly sends the CLOSE action to release state handles, and exception cases only log and return `false` so signature errors do not block the wider scanning flow.
 * - 关键词: 签名验证 | signature verification | TrustBridge优先 | TrustBridge first | WinVerifyTrust回退 | WinVerifyTrust fallback | 文件信任判定 | file trust decision | 风险过滤前置 | risk filter guard
 */
function verifyTrust(filePath) {
    if (tryLoadTrustBridge() && TrustBridge_VerifyFile) {
        try {
            const st = Buffer.alloc(4);
            const ok = TrustBridge_VerifyFile(filePath, st);
            return ok === 1;
        } catch {
            return false;
        }
    }

    if (!WinVerifyTrust) return false;
    
    if (trustedCache.has(filePath)) return trustedCache.get(filePath);

    const fileInfo = {
        cbStruct: 0,
        pcwszFilePath: filePath,
        hFile: null,
        pgKnownSubject: null
    };
    fileInfo.cbStruct = koffi.sizeof(WINTRUST_FILE_INFO);

    const winTrustData = {
        cbStruct: 0,
        pPolicyCallbackData: null,
        pSIPClientData: null,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        pFile: fileInfo,
        dwStateAction: WTD_STATEACTION_VERIFY,
        hWVTStateData: null,
        pwszURLReference: null,
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
        dwUIContext: 0,
        pSignatureSettings: null
    };
    winTrustData.cbStruct = koffi.sizeof(WINTRUST_DATA);

    try {
        const status = WinVerifyTrust(null, ACTION_GENERIC_VERIFY_V2, winTrustData);
        
        winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(null, ACTION_GENERIC_VERIFY_V2, winTrustData);
        
        const isTrusted = (status === ERROR_SUCCESS);
        trustedCache.set(filePath, isTrusted);
        return isTrusted;
    } catch (e) {
        console.error('WinVerifyTrust failed', e);
        return false;
    }
}

/**
 * - 函数: `getProcessImagePathByPid`
 * - Function: `getProcessImagePathByPid`
 * - 作用: 通过 `QueryFullProcessImageNameW` 读取指定 PID 的主映像路径，为进程快照和模块枚举失败回退提供统一入口。
 * - Purpose: Reads the main image path for a PID through `QueryFullProcessImageNameW`, providing the shared fallback used by process snapshots and module enumeration.
 * - 调用方: `getProcessImageSnapshot`、`getProcessModules`。
 * - Callers: `getProcessImageSnapshot` and `getProcessModules`.
 * - 被调方: `OpenProcess`、`QueryFullProcessImageNameW`、`CloseHandle`、`Buffer.alloc`。
 * - Callees: `OpenProcess`, `QueryFullProcessImageNameW`, `CloseHandle`, and `Buffer.alloc`.
 * - 变量说明: `pid` 为目标进程 ID；`hProcess` 为进程句柄；`pathBuffer` 保存 UTF-16 路径；`sizeBuf` 记录返回字符数；`p` 为清洗后的路径。
 * - Variables: `pid` is the target process ID, `hProcess` is the process handle, `pathBuffer` stores the UTF-16 path, `sizeBuf` stores the returned character count, and `p` is the sanitized path string.
 * - 接入方式: 任何需要从 PID 读取主进程路径的逻辑都应优先复用本函数，不要重复拼同样的 Win32 缓冲区与前缀清洗逻辑。
 * - Integration: Any flow that needs the main image path from a PID should reuse this helper instead of rebuilding the same Win32 buffer handling and prefix cleanup.
 * - 错误处理: PID 非法、打开进程失败、API 调用失败或路径清洗后为空时统一返回 `null`；`finally` 中始终尝试关闭句柄。
 * - Error Handling: Invalid PIDs, failed handle opens, failed API calls, or empty sanitized paths all collapse to `null`, and the handle is always closed in `finally`.
 * - 关键词: 进程映像路径 | process image path | PID路径查询 | PID path lookup | QueryFullProcessImageNameW | 句柄安全释放 | handle cleanup | 路径前缀清洗 | path prefix cleanup
 */
function getProcessImagePathByPid(pid) {
    if (!Number.isFinite(pid) || pid <= 0) return null;
    let hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid >>> 0);
    if (!hProcess) return null;
    try {
        const pathBuffer = Buffer.alloc(4096);
        const sizeBuf = Buffer.alloc(4);
        sizeBuf.writeUInt32LE(2048, 0);
        if (!QueryFullProcessImageNameW(hProcess, 0, pathBuffer, sizeBuf)) return null;
        const len = sizeBuf.readUInt32LE(0);
        if (!len) return null;
        let p = pathBuffer.toString('utf16le', 0, len * 2);
        p = (p || '').replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\uFFFD]/g, '').trim();
        if (!p) return null;
        if (p.startsWith('\\??\\')) p = p.substring(4);
        return p || null;
    } catch {
        return null;
    } finally {
        try { CloseHandle(hProcess); } catch {}
    }
}

/**
 * - 函数: `getProcessImageSnapshot`
 * - Function: `getProcessImageSnapshot`
 * - 作用: 枚举当前系统 PID 列表并收集每个进程的主映像路径，返回轻量级 `{ pid, imagePath }` 快照。
 * - Purpose: Enumerates current system PIDs and collects each process's main image path, returning a lightweight `{ pid, imagePath }` snapshot.
 * - 调用方: 供主进程或 worker 在需要快速拿到全量 PID 与主程序路径映射时调用。
 * - Callers: Used by main-process or worker flows that need a fast PID-to-main-image snapshot.
 * - 被调方: `EnumProcesses`、`getProcessImagePathByPid`、`Buffer.alloc`、`Math.max/min/floor`。
 * - Callees: `EnumProcesses`, `getProcessImagePathByPid`, `Buffer.alloc`, and `Math.max/min/floor`.
 * - 变量说明: `maxPids` 为调用方建议的枚举上限；`maxProcesses` 为收紧后的实际上限；`pidsBuffer` 保存返回的 PID 数组；`bytesReturned` 记录有效字节数；`out` 为最终结果。
 * - Variables: `maxPids` is the caller-suggested cap, `maxProcesses` is the clamped actual limit, `pidsBuffer` stores returned PIDs, `bytesReturned` stores the byte count, and `out` is the final result array.
 * - 接入方式: 适合需要“先拿一份进程路径快照再做后续过滤”的逻辑；若未来要附带更多字段，可在本函数内集中扩展返回结构。
 * - Integration: Use it for flows that first need a process-path snapshot before later filtering; if more fields are needed later, extend the returned structure here.
 * - 错误处理: `EnumProcesses` 失败时返回空数组；单个 PID 路径解析失败只跳过该项，不影响整体快照构建。
 * - Error Handling: It returns an empty array when `EnumProcesses` fails, and a single PID path failure only skips that entry without aborting the whole snapshot.
 * - 关键词: 进程快照枚举 | process snapshot enumeration | PID映像映射 | PID image mapping | 轻量结果集 | lightweight result set | 全量进程扫描 | full process scan | 快照回退入口 | snapshot fallback entry
 */
function getProcessImageSnapshot(maxPids) {
    const maxProcesses = Number.isFinite(maxPids) ? Math.max(256, Math.min(65536, Math.floor(maxPids))) : 8192;
    const pidsBuffer = Buffer.alloc(maxProcesses * 4);
    const bytesReturned = Buffer.alloc(4);

    const ret = EnumProcesses(pidsBuffer, pidsBuffer.length, bytesReturned);
    if (!ret) return [];

    const bytesUsed = bytesReturned.readUInt32LE(0);
    const numProcesses = Math.floor(bytesUsed / 4);
    const out = [];
    for (let i = 0; i < numProcesses; i++) {
        const pid = pidsBuffer.readUInt32LE(i * 4);
        if (!pid) continue;
        const imagePath = getProcessImagePathByPid(pid);
        if (imagePath) out.push({ pid, imagePath });
    }
    return out;
}

/**
 * - 函数: `getProcessModules`
 * - Function: `getProcessModules`
 * - 作用: 枚举指定进程已加载模块路径，并在模块枚举失败或结果为空时回退到主映像路径，供风险分析与拦截快照复用。
 * - Purpose: Enumerates loaded module paths for the target process and falls back to the main image path when module enumeration fails or yields nothing, supporting risk analysis and interception snapshots.
 * - 调用方: 供主进程或 worker 在需要按 PID 分析加载模块时调用。
 * - Callers: Used by main-process or worker flows that analyze loaded modules by PID.
 * - 被调方: `OpenProcess`、`EnumProcessModules`、`GetModuleFileNameExW`、`getProcessImagePathByPid`、`CloseHandle`、`Set`。
 * - Callees: `OpenProcess`, `EnumProcessModules`, `GetModuleFileNameExW`, `getProcessImagePathByPid`, `CloseHandle`, and `Set`.
 * - 变量说明: `pid` 为目标进程 ID；`maxBufferBytes` 为模块句柄缓冲区上限；`hProcess` 为进程句柄；`modulesBuffer` 与 `cbNeeded` 承载原生输出；`seen` 用于路径去重；`out` 为最终模块路径列表。
 * - Variables: `pid` is the target process ID, `maxBufferBytes` is the module-handle buffer cap, `hProcess` is the process handle, `modulesBuffer` and `cbNeeded` carry native output, `seen` deduplicates paths, and `out` is the final module-path list.
 * - 接入方式: 任何需要完整模块路径列表的逻辑都应走本函数；不要在调用方重复处理位数差异、路径清洗和去重。
 * - Integration: Any flow that needs the full module-path list should reuse this helper rather than duplicating pointer-size handling, path cleanup, and deduplication elsewhere.
 * - 错误处理: PID 非法、进程打开失败或内部异常时返回空数组；模块枚举失败时优先回退主映像路径，尽量保证调用方仍有最小结果可用。
 * - Error Handling: Invalid PIDs, failed process opens, or internal exceptions return an empty array, while module-enumeration failures fall back to the main image path whenever possible.
 * - 关键词: 进程模块枚举 | process module enumeration | 模块路径去重 | module path deduplication | 主映像回退 | main image fallback | 位数兼容处理 | pointer-size compatibility | 风险分析输入 | risk-analysis input
 */
function getProcessModules(pid, maxBufferBytes = 65536) {
    if (!Number.isFinite(pid) || pid <= 0) return [];
    const maxBytes = Number.isFinite(maxBufferBytes) ? Math.max(4096, Math.min(1024 * 1024, Math.floor(maxBufferBytes))) : 65536;
    let hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid >>> 0);
    if (!hProcess) hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid >>> 0);
    if (!hProcess) return [];
    try {
        const ptrSize = process.arch === 'x64' ? 8 : 4;
        const modulesBuffer = Buffer.alloc(maxBytes);
        const cbNeeded = Buffer.alloc(4);

        const ok = EnumProcessModules(hProcess, modulesBuffer, modulesBuffer.length, cbNeeded);
        if (!ok) {
            const img = getProcessImagePathByPid(pid);
            return img ? [img] : [];
        }

        const bytesNeeded = cbNeeded.readUInt32LE(0);
        const count = Math.floor(Math.min(bytesNeeded, modulesBuffer.length) / ptrSize);
        const out = [];
        const seen = new Set();
        for (let i = 0; i < count; i++) {
            let hMod;
            if (ptrSize === 8) hMod = modulesBuffer.readBigUInt64LE(i * 8);
            else hMod = modulesBuffer.readUInt32LE(i * 4);
            if (!hMod) continue;

            const pathBuffer = Buffer.alloc(4096);
            const len = GetModuleFileNameExW(hProcess, hMod, pathBuffer, 2048);
            if (!len) continue;
            let p = pathBuffer.toString('utf16le', 0, len * 2);
            p = (p || '').replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\uFFFD]/g, '').trim();
            if (p.startsWith('\\??\\')) p = p.substring(4);
            if (!p) continue;
            const key = p.toLowerCase();
            if (seen.has(key)) continue;
            seen.add(key);
            out.push(p);
        }
        if (!out.length) {
            const img = getProcessImagePathByPid(pid);
            return img ? [img] : [];
        }
        return out;
    } catch {
        return [];
    } finally {
        try { CloseHandle(hProcess); } catch {}
    }
}

let driveDeviceMapCache = null;

/**
 * - 函数: `listExistingDriveNames`
 * - Function: `listExistingDriveNames`
 * - 作用: 枚举当前机器上实际存在的盘符列表，为 NT 设备路径到 DOS 路径映射构建提供输入。
 * - Purpose: Enumerates the drive letters that actually exist on the current machine, providing the input for NT-device to DOS-path mapping.
 * - 调用方: `getDriveDeviceMap`。
 * - Callers: `getDriveDeviceMap`.
 * - 被调方: `fs.existsSync`、数组 `push`。
 * - Callees: `fs.existsSync` and array `push`.
 * - 变量说明: 无显式入参；`letters` 为候选盘符表；`driveName` 为当前盘符；`root` 为盘符根目录；`out` 为实际存在的盘符列表。
 * - Variables: There are no explicit parameters; `letters` is the candidate drive alphabet, `driveName` is the current drive letter, `root` is the drive root path, and `out` is the resulting list of existing drives.
 * - 接入方式: 仅建议作为设备映射构建的底层辅助函数使用，不要在业务层重复做 A-Z 探测。
 * - Integration: Keep it as a low-level helper for device-map construction; business code should not reimplement A-Z probing.
 * - 错误处理: 单个盘符检测异常会被静默跳过，保证枚举流程继续执行。
 * - Error Handling: Exceptions while probing a single drive are silently skipped so the enumeration can continue.
 * - 关键词: 盘符枚举 | drive letter enumeration | 存在盘检测 | existing drive detection | 设备映射前置 | device-map prerequisite | A到Z探测 | A-to-Z probing | DOS盘列表 | DOS drive list
 */
function listExistingDriveNames() {
    const out = [];
    const letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    for (let i = 0; i < letters.length; i++) {
        const driveName = letters[i] + ':';
        const root = driveName + '\\';
        try {
            if (fs.existsSync(root)) out.push(driveName);
        } catch {}
    }
    return out;
}

/**
 * - 函数: `queryDosDevice`
 * - Function: `queryDosDevice`
 * - 作用: 调用 `QueryDosDeviceW` 读取某个盘符或 DOS 设备名对应的 NT 目标路径列表，是设备路径映射构建的底层查询封装。
 * - Purpose: Calls `QueryDosDeviceW` to read the NT target-path list for a drive letter or DOS device name, forming the low-level query wrapper behind device-path mapping.
 * - 调用方: `getDriveDeviceMap`。
 * - Callers: `getDriveDeviceMap`.
 * - 被调方: `QueryDosDeviceW`、`Buffer.alloc`、字符串 `split`、数组 `filter`。
 * - Callees: `QueryDosDeviceW`, `Buffer.alloc`, string `split`, and array `filter`.
 * - 变量说明: `deviceName` 为待查询的 DOS 设备名；`maxChars` 为输出缓冲区上限；`buf` 为 UTF-16 原生缓冲区；`n` 为返回字符数；`raw` 为原始解码结果。
 * - Variables: `deviceName` is the DOS device name to query, `maxChars` is the output-buffer cap, `buf` is the UTF-16 native buffer, `n` is the returned character count, and `raw` is the decoded raw string.
 * - 接入方式: 仅建议在设备映射构建链路中复用；不要让上层直接处理 `QueryDosDeviceW` 的多字符串返回格式。
 * - Integration: Reuse it only in the device-map construction path; upper layers should not parse the multi-string `QueryDosDeviceW` format directly.
 * - 错误处理: Win32 调用异常或返回长度为 0 时统一返回空数组，交由上层决定是否跳过该盘符。
 * - Error Handling: Win32 call failures or zero-length results collapse to an empty array so callers can simply skip that drive.
 * - 关键词: QueryDosDevice封装 | QueryDosDevice wrapper | NT目标路径 | NT target paths | 设备名查询 | device-name query | 多字符串解码 | multi-string decoding | 盘符映射基础 | drive-map foundation
 */
function queryDosDevice(deviceName) {
    const maxChars = 32768;
    const buf = Buffer.alloc(maxChars * 2);
    let n = 0;
    try {
        n = QueryDosDeviceW(deviceName, buf, maxChars) >>> 0;
    } catch {
        n = 0;
    }
    if (!n) return [];
    const raw = buf.toString('utf16le', 0, n * 2);
    return raw.split('\u0000').filter(Boolean);
}

/**
 * - 函数: `getDriveDeviceMap`
 * - Function: `getDriveDeviceMap`
 * - 作用: 构建并缓存 `\\Device\\HarddiskVolume*` 到盘符的映射表，供 ETW 设备路径还原为 DOS 路径时复用，避免每次事件解析都重复遍历盘符和查询设备名。
 * - Purpose: Builds and caches the mapping from `\\Device\\HarddiskVolume*` paths to drive letters so ETW device paths can be converted back to DOS paths without re-enumerating drives on every event.
 * - 调用方: `primeDriveDeviceMap` 负责启动期预热，`devicePathToDosPath` 在实际路径转换时调用；`etw_worker.js` 也会通过 `winapi.getDriveDeviceMap()` 间接使用这份缓存。
 * - Callers: Warmed up by `primeDriveDeviceMap` and used by `devicePathToDosPath` during actual path conversion; `etw_worker.js` also consumes this cache indirectly through `winapi.getDriveDeviceMap()`.
 * - 被调方: `listExistingDriveNames`、`queryDosDevice`、`Map`、字符串 `trim`、`startsWith`、`toLowerCase`。
 * - Callees: `listExistingDriveNames`, `queryDosDevice`, `Map`, string `trim`, `startsWith`, and `toLowerCase`.
 * - 变量说明: 无显式入参；模块级 `driveDeviceMapCache` 保存构建后的映射；`drives` 为存在的盘符列表；`targets` 为某个盘符对应的 NT 设备路径集合；`map` 为最终缓存对象。
 * - Variables: There are no explicit parameters; the module-level `driveDeviceMapCache` stores the built mapping, `drives` is the list of existing drive letters, `targets` holds NT device targets for one drive, and `map` is the final cache object.
 * - 接入方式: 所有设备路径转盘符逻辑都应通过本函数或 `devicePathToDosPath` 复用缓存；如果新增 ETW provider 也产出 `\\Device\\` 路径，优先复用这里而不是重新查询 `QueryDosDeviceW`。
 * - Integration: Any device-path-to-drive-letter logic should reuse this function or `devicePathToDosPath`; if new ETW providers also emit `\\Device\\` paths, prefer this cache instead of issuing fresh `QueryDosDeviceW` calls.
 * - 错误处理: 主要依赖下游函数的安全回退，查询失败的盘符会被跳过；即使结果为空也会返回可复用的 `Map` 实例，避免上游路径转换链路因为异常中断。
 * - Error Handling: It relies on safe fallbacks in downstream helpers, skipping drives that fail to resolve; even an empty result is returned as a reusable `Map` instance so path-conversion flows do not abort unexpectedly.
 * - 关键词: 设备路径映射 | device path map | 盘符缓存 | drive-letter cache | ETW路径还原 | ETW path restore | QueryDosDevice复用 | QueryDosDevice reuse | NT路径转换 | NT path conversion
 */
function getDriveDeviceMap() {
    if (driveDeviceMapCache) return driveDeviceMapCache;
    const map = new Map();
    const drives = listExistingDriveNames();
    for (const driveName of drives) {
        const targets = queryDosDevice(driveName);
        for (const t of targets) {
            const s = typeof t === 'string' ? t.trim() : '';
            if (!s) continue;
            if (!s.startsWith('\\Device\\')) continue;
            map.set(s.toLowerCase(), driveName);
        }
    }
    driveDeviceMapCache = map;
    return map;
}

/**
 * - 函数: `getSignerInfo`
 * - Function: `getSignerInfo`
 * - 作用: 从 TrustBridge 读取文件签名者信息 JSON，并解码为可直接传给主进程拦截弹窗或渲染层展示的对象结构。
 * - Purpose: Fetches signer metadata JSON from TrustBridge and decodes it into an object that can be passed directly to interception UI flows or renderer-side display logic.
 * - 调用方: `main.js` 中拦截面板相关 IPC 包装会调用本函数，再由 `renderer/interception.js` 展示签名者信息。
 * - Callers: Called by the interception-related IPC wrapper in `main.js`, with the result later rendered in `renderer/interception.js`.
 * - 被调方: `tryLoadTrustBridge`、`TrustBridge_GetSignerInfoJson`、`lstrlenA`、`koffi.decode`、`TrustBridge_Free`、`JSON.parse`。
 * - Callees: `tryLoadTrustBridge`, `TrustBridge_GetSignerInfoJson`, `lstrlenA`, `koffi.decode`, `TrustBridge_Free`, and `JSON.parse`.
 * - 变量说明: `filePath` 为目标文件路径；`out` 为原生输出指针槽位；`ptr` 为 TrustBridge 返回的 C 字符串指针；`len` 为字符串长度；`json` 为待解析的 JSON 文本。
 * - Variables: `filePath` is the target file path, `out` is the native output slot, `ptr` is the C-string pointer returned by TrustBridge, `len` is the string length, and `json` is the JSON text to parse.
 * - 接入方式: 适合作为“签名详情查询”统一入口；如果后续 UI 需要更多签名字段，优先扩展 TrustBridge 输出与本函数解析，不要在多个 IPC 处理器里复制 native 指针释放逻辑。
 * - Integration: Use it as the shared entry for signer-detail lookups; if UI flows need more signer fields later, extend the TrustBridge payload and this parser instead of duplicating native-pointer cleanup logic across IPC handlers.
 * - 错误处理: 缺少 TrustBridge 能力、原生返回非零、指针为空、长度非法或 JSON 解析失败时统一返回 `null`；无论成功失败都尽量释放原生指针，避免内存泄漏。
 * - Error Handling: Missing TrustBridge support, non-zero native return codes, null pointers, invalid lengths, or JSON parse failures all collapse to `null`; the function still tries to free native pointers whenever possible to avoid leaks.
 * - 关键词: 签名者详情 | signer details | JSON解码 | JSON decode | 原生指针释放 | native pointer free | 拦截弹窗信息 | interception dialog data | TrustBridge查询 | TrustBridge query
 */
function getSignerInfo(filePath) {
    if (!(tryLoadTrustBridge() && TrustBridge_GetSignerInfoJson && TrustBridge_Free)) return null;
    try {
        const out = [null];
        const rc = TrustBridge_GetSignerInfoJson(filePath, out);
        if (rc !== 0) return null;
        const ptr = out[0];
        if (!ptr) return null;
        const len = lstrlenA(ptr) | 0;
        if (!len || len < 0) {
            try { TrustBridge_Free(ptr); } catch {}
            return null;
        }
        const bytes = koffi.decode(ptr, koffi.array('uint8_t', len));
        const json = Buffer.from(bytes).toString('utf8');
        try { TrustBridge_Free(ptr); } catch {}
        try { return JSON.parse(json); } catch { return null; }
    } catch {
        return null;
    }
}

/**
 * - 函数: `computeFileSha256Hex`
 * - Function: `computeFileSha256Hex`
 * - 作用: 通过 TrustBridge 原生接口计算文件 SHA-256 十六进制摘要，为缓存存储和文件信誉判断提供统一哈希入口。
 * - Purpose: Computes the file SHA-256 hex digest through the TrustBridge native API, providing the shared hashing entry for cache storage and file reputation flows.
 * - 调用方: 供 ETW 风险分析和 TrustBridge 缓存写入链路在需要文件哈希时调用。
 * - Callers: Used by ETW risk-analysis and TrustBridge cache-store flows whenever a file hash is needed.
 * - 被调方: `tryLoadTrustBridge`、`TrustBridge_ComputeFileSha256Hex`、`TrustBridge_Free`、`koffi.decode`、`Buffer.from`。
 * - Callees: `tryLoadTrustBridge`, `TrustBridge_ComputeFileSha256Hex`, `TrustBridge_Free`, `koffi.decode`, and `Buffer.from`.
 * - 变量说明: `filePath` 为目标文件路径；`out` 接收原生输出指针；`ptr` 为返回字符串地址；`len` 为 ANSI 字符串长度；`hex` 为最终十六进制哈希。
 * - Variables: `filePath` is the target file path, `out` receives the native output pointer, `ptr` is the returned string address, `len` is the ANSI string length, and `hex` is the final hexadecimal hash.
 * - 接入方式: 需要 TrustBridge 版本一致的文件哈希时应复用本函数，不要在调用方混用 Node `crypto` 与原生结果。
 * - Integration: Reuse this helper whenever the hash must stay consistent with TrustBridge; callers should not mix Node `crypto` output with native results arbitrarily.
 * - 错误处理: TrustBridge 未加载、原生返回码异常、指针为空或长度异常时统一返回 `null`；拿到指针后会尽量释放原生内存。
 * - Error Handling: Missing TrustBridge bindings, nonzero native return codes, null pointers, or invalid lengths all return `null`, and native memory is freed whenever a pointer is obtained.
 * - 关键词: 文件SHA256 | file SHA256 | TrustBridge哈希 | TrustBridge hashing | 原生摘要计算 | native digest compute | 哈希缓存输入 | hash cache input | 指针释放 | pointer cleanup
 */
function computeFileSha256Hex(filePath) {
    if (!(tryLoadTrustBridge() && TrustBridge_ComputeFileSha256Hex && TrustBridge_Free)) return null;
    try {
        const out = [null];
        const rc = TrustBridge_ComputeFileSha256Hex(filePath, out);
        if (rc !== 0) return null;
        const ptr = out[0];
        if (!ptr) return null;
        const len = lstrlenA(ptr) | 0;
        if (!len || len < 0 || len > 256) {
            try { TrustBridge_Free(ptr); } catch {}
            return null;
        }
        const bytes = koffi.decode(ptr, koffi.array('uint8_t', len));
        const hex = Buffer.from(bytes).toString('utf8');
        try { TrustBridge_Free(ptr); } catch {}
        return hex || null;
    } catch {
        return null;
    }
}

/**
 * - 函数: `scanCacheLookupByFile`
 * - Function: `scanCacheLookupByFile`
 * - 作用: 通过 TrustBridge 查询指定文件是否已有扫描缓存命中，并把原生返回值规整成 `{ hit, verdict, hash }` 结构，供 ETW 风险 worker 在真正扫描前做快速短路判断。
 * - Purpose: Queries TrustBridge for a scan-cache hit for the given file and normalizes the native result into a `{ hit, verdict, hash }` object so the ETW risk worker can short-circuit before performing a full scan.
 * - 调用方: `etw_risk_worker.js` 中基于文件路径做哈希缓存复用的链路会调用本函数；未来任何需要“先查缓存再决定是否扫描”的 worker 也应复用它。
 * - Callers: Used by the file-path hash-cache reuse flow in `etw_risk_worker.js`; any future worker that needs a cache-first scanning decision should reuse it as well.
 * - 被调方: `tryLoadTrustBridge`、`TrustBridge_ScanCacheLookupByFile2`、`TrustBridge_ScanCacheLookupByFile`、`TrustBridge_Free`、`Buffer.alloc`、`writeInt32LE`、`readInt32LE`、`fill`。
 * - Callees: `tryLoadTrustBridge`, `TrustBridge_ScanCacheLookupByFile2`, `TrustBridge_ScanCacheLookupByFile`, `TrustBridge_Free`, `Buffer.alloc`, `writeInt32LE`, `readInt32LE`, and `fill`.
 * - 变量说明: `filePath` 为要查询缓存的文件路径；`verdictBuf` 存放原生返回判定值；`hexBuf` 或 `outHex` 用于接收缓存中的哈希；`rc` 表示原生命中状态；`verdict`/`hash` 为规整后的返回字段。
 * - Variables: `filePath` is the file path being looked up, `verdictBuf` holds the native verdict value, `hexBuf` or `outHex` receives the cached hash, `rc` is the native hit status, and `verdict` and `hash` are the normalized output fields.
 * - 接入方式: 适合作为扫描缓存查询统一入口；业务侧不要直接分支调用 `LookupByFile2` 或旧版接口，保持版本兼容逻辑集中在本函数中。
 * - Integration: Use it as the shared entry for scan-cache lookups; business code should not branch on `LookupByFile2` versus the legacy API directly, keeping version-compatibility logic centralized here.
 * - 错误处理: 缺少缓存接口、原生返回异常或解析失败时统一返回 `null`；命中与未命中分别显式返回结构化对象，避免上层把“查询失败”和“没有缓存”混为一谈。
 * - Error Handling: Missing cache APIs, native failures, or parse problems all collapse to `null`; cache hits and misses return explicit structured objects so upper layers can distinguish query failure from a normal cache miss.
 * - 关键词: 扫描缓存查询 | scan cache lookup | TrustBridge缓存 | TrustBridge cache | verdict归一化 | verdict normalization | ETW短路扫描 | ETW scan short-circuit | 哈希复用 | hash reuse
 */
function scanCacheLookupByFile(filePath) {
    if (!(tryLoadTrustBridge() && (TrustBridge_ScanCacheLookupByFile2 || TrustBridge_ScanCacheLookupByFile) && TrustBridge_Free)) return null;
    try {
        if (TrustBridge_ScanCacheLookupByFile2) {
            const verdictBuf = Buffer.alloc(4);
            verdictBuf.writeInt32LE(0, 0);
            const hexBuf = Buffer.alloc(128);
            hexBuf.fill(0);
            const rc = TrustBridge_ScanCacheLookupByFile2(filePath, verdictBuf, hexBuf, hexBuf.length);
            const verdict = verdictBuf.readInt32LE(0);
            let hash = null;
            const nul = hexBuf.indexOf(0);
            const end = nul >= 0 ? nul : hexBuf.length;
            if (end > 0) hash = hexBuf.toString('utf8', 0, end) || null;
            if (rc === 1) return { hit: true, verdict, hash };
            if (rc === 0) return { hit: false, verdict: 0, hash };
            return null;
        } else {
            const verdictBuf = Buffer.alloc(4);
            verdictBuf.writeInt32LE(0, 0);
            const outHex = [null];
            const rc = TrustBridge_ScanCacheLookupByFile(filePath, verdictBuf, outHex);
            const verdict = verdictBuf.readInt32LE(0);
            let hash = null;
            const ptr = outHex[0];
            if (ptr) {
                try { TrustBridge_Free(ptr); } catch {}
            }
            if (rc === 1) return { hit: true, verdict, hash };
            if (rc === 0) return { hit: false, verdict: 0, hash };
            return null;
        }
    } catch {
        return null;
    }
}

/**
 * - 函数: `scanCacheStore`
 * - Function: `scanCacheStore`
 * - 作用: 把文件哈希与判定结果写入 TrustBridge 扫描缓存，供后续 ETW 快速命中判断复用。
 * - Purpose: Stores a file hash and verdict into the TrustBridge scan cache so later ETW checks can reuse the result quickly.
 * - 调用方: 风险分析链路在拿到最终哈希与判定后会调用本函数写回原生缓存。
 * - Callers: Risk-analysis flows call this helper after obtaining the final hash and verdict to persist them into the native cache.
 * - 被调方: `tryLoadTrustBridge`、`TrustBridge_ScanCacheStore`、`String`、字符串 `trim`、`Number.isFinite`。
 * - Callees: `tryLoadTrustBridge`, `TrustBridge_ScanCacheStore`, `String`, string `trim`, and `Number.isFinite`.
 * - 变量说明: `hashHex` 为待写入的哈希；`verdict` 为缓存判定值；`h` 为清洗后的哈希字符串；`v` 为标准化后的整数判定。
 * - Variables: `hashHex` is the hash to store, `verdict` is the cached verdict value, `h` is the sanitized hash string, and `v` is the normalized integer verdict.
 * - 接入方式: 所有需要写入原生扫描缓存的场景都应经过本函数，保证参数清洗与返回约定一致。
 * - Integration: Any flow that writes into the native scan cache should go through this helper so parameter sanitation and return semantics stay consistent.
 * - 错误处理: 哈希为空、判定非法、TrustBridge 不可用或原生调用抛错时统一返回 `false`。
 * - Error Handling: Empty hashes, invalid verdicts, unavailable TrustBridge bindings, and native exceptions all collapse to `false`.
 * - 关键词: 扫描缓存写入 | scan cache store | verdict持久化 | verdict persistence | 哈希回写 | hash write-back | TrustBridge缓存更新 | TrustBridge cache update | 原生布尔结果 | native boolean result
 */
function scanCacheStore(hashHex, verdict) {
    if (!(tryLoadTrustBridge() && TrustBridge_ScanCacheStore)) return false;
    const h = typeof hashHex === 'string' ? hashHex.trim() : '';
    const v = Number.isFinite(verdict) ? verdict : parseInt(String(verdict), 10);
    if (!h) return false;
    if (!Number.isFinite(v)) return false;
    try {
        return TrustBridge_ScanCacheStore(h, v | 0) === 0;
    } catch {
        return false;
    }
}

/**
 * - 函数: `primeDriveDeviceMap`
 * - Function: `primeDriveDeviceMap`
 * - 作用: 预热 NT 设备路径到盘符的缓存映射，减少首次路径转换时的阻塞感知。
 * - Purpose: Warms up the cached NT-device to drive-letter mapping so the first path-conversion request avoids extra latency.
 * - 调用方: 主进程启动后可主动调用本函数预建映射；`etw_worker.js` 相关链路也可在进入高频转换前先预热。
 * - Callers: The main process may call it after startup to build the map early, and `etw_worker.js`-related flows can use it before high-frequency path conversions.
 * - 被调方: `getDriveDeviceMap`。
 * - Callees: `getDriveDeviceMap`.
 * - 变量说明: 无显式入参；返回值仅表示预热是否顺利完成。
 * - Variables: There are no explicit parameters; the return value only indicates whether warm-up completed successfully.
 * - 接入方式: 适合放在初始化阶段调用，不负责返回映射内容本身。
 * - Integration: It is intended for initialization-time warm-up and does not expose the map content itself.
 * - 错误处理: 预热过程中若底层映射构建抛错则返回 `false`，避免启动流程被异常中断。
 * - Error Handling: If map construction throws during warm-up, the function returns `false` so startup is not interrupted.
 * - 关键词: 设备映射预热 | device-map warm-up | 盘符缓存初始化 | drive cache init | 路径转换加速 | path conversion acceleration | 启动期准备 | startup preparation | 惰性缓存装载 | lazy cache preload
 */
function primeDriveDeviceMap() {
    try {
        getDriveDeviceMap();
        return true;
    } catch {
        return false;
    }
}

/**
 * - 函数: `devicePathToDosPath`
 * - Function: `devicePathToDosPath`
 * - 作用: 把 `\Device\HarddiskVolume...` 等 NT 设备路径尽量转换为 `C:\...` 风格 DOS 路径，便于 UI 展示、缓存命中和签名校验复用。
 * - Purpose: Converts NT device paths such as `\Device\HarddiskVolume...` into DOS-style paths like `C:\...` whenever possible for easier UI display, cache hits, and trust verification.
 * - 调用方: `etw_worker.js`、主进程拦截链路及其他需要把内核路径转换成用户可读路径的逻辑。
 * - Callers: Used by `etw_worker.js`, main-process interception flows, and any logic that needs to turn kernel paths into user-readable paths.
 * - 被调方: `getDriveDeviceMap`、字符串 `trim`、`startsWith`、`substring`、`toLowerCase`、`indexOf`、`slice`。
 * - Callees: `getDriveDeviceMap`, string `trim`, `startsWith`, `substring`, `toLowerCase`, `indexOf`, and `slice`.
 * - 变量说明: `p` 为原始路径；`s` 为清洗后的路径；`lower` 为小写匹配副本；`map` 为设备前缀到盘符映射；`devKey` 为待匹配的设备前缀。
 * - Variables: `p` is the raw path, `s` is the sanitized path, `lower` is the lowercase comparison copy, `map` is the device-prefix to drive-letter mapping, and `devKey` is the prefix being matched.
 * - 接入方式: 任何 ETW 或 Win32 返回 NT 设备路径的场景都应优先走本函数，不要在调用方各自实现前缀替换。
 * - Integration: Any ETW or Win32 flow that receives NT device paths should route through this helper instead of implementing ad-hoc prefix replacement in each caller.
 * - 错误处理: 非字符串或空白输入返回空字符串；无法映射时保留原始清洗后的路径，避免信息丢失。
 * - Error Handling: Non-string or blank input returns an empty string, and unmapped device paths fall back to the sanitized original so information is not lost.
 * - 关键词: NT路径转盘符 | NT path to drive letter | 设备前缀映射 | device-prefix mapping | 用户可读路径 | user-readable path | ETW路径归一化 | ETW path normalization | DOS路径回填 | DOS path conversion
 */
function devicePathToDosPath(p) {
    if (typeof p !== 'string') return '';
    let s = p.trim();
    if (!s) return '';
    if (s.startsWith('\\??\\')) s = s.substring(4);
    if (/^[a-zA-Z]:[\\/]/.test(s)) return s;
    const lower = s.toLowerCase();
    if (!lower.startsWith('\\device\\')) return s;

    const map = getDriveDeviceMap();
    const prefixStart = 8;
    const prefixEnd = lower.indexOf('\\', prefixStart);
    const devKey = prefixEnd === -1 ? lower : lower.slice(0, prefixEnd);
    const driveName = map.get(devKey);
    if (driveName) {
        const rest = s.substring(devKey.length);
        return rest ? (driveName + rest) : (driveName + '\\');
    }

    for (const [dev, driveName2] of map.entries()) {
        if (lower === dev) return driveName2 + '\\';
        if (lower.startsWith(dev + '\\')) return driveName2 + s.substring(dev.length);
    }
    return s;
}


/**
 * - 函数: `getProcessPaths`
 * - Function: `getProcessPaths`
 * - 作用: 全量枚举进程及其模块路径，并过滤系统 DLL 与已验证可信的可执行文件，返回需要进一步检查的文件路径集合。
 * - Purpose: Enumerates all processes and module paths, filters out system DLLs and trust-verified executables, and returns the path set that still requires further inspection.
 * - 调用方: `main.js` 中的进程扫描与启动期可疑文件收集逻辑会调用本函数。
 * - Callers: Used by the process-scanning and suspicious-file collection flows in `main.js`.
 * - 被调方: `EnumProcesses`、`OpenProcess`、`EnumProcessModules`、`GetModuleFileNameExW`、`QueryFullProcessImageNameW`、`verifyTrust`、`CloseHandle`、`Set`。
 * - Callees: `EnumProcesses`, `OpenProcess`, `EnumProcessModules`, `GetModuleFileNameExW`, `QueryFullProcessImageNameW`, `verifyTrust`, `CloseHandle`, and `Set`.
 * - 变量说明: 无显式入参；`paths` 为去重路径集合；`systemRoot` 用于识别系统 DLL；`pidsBuffer`/`bytesReturned` 存储 PID 枚举结果；`hProcess` 为当前进程句柄；`modulesBuffer` 与 `cbNeeded` 为模块枚举缓冲区。
 * - Variables: There are no explicit parameters; `paths` is the deduplicated path set, `systemRoot` identifies system DLLs, `pidsBuffer` and `bytesReturned` store PID enumeration results, `hProcess` is the current process handle, and `modulesBuffer` plus `cbNeeded` back module enumeration.
 * - 接入方式: 适合作为“先拿候选可疑路径，再做后续信誉或扫描”的统一入口；若后续要增加白名单或更多过滤规则，应优先在本函数内收口。
 * - Integration: Use it as the shared entry for collecting suspicious candidate paths before later reputation or scan steps; add future whitelist or filter rules here centrally.
 * - 错误处理: `EnumProcesses` 失败时返回空数组；单个进程模块读取失败只影响该 PID；内部异常不会中断整体扫描，句柄会在 `finally` 中关闭。
 * - Error Handling: It returns an empty array when `EnumProcesses` fails, a single PID failure affects only that process, and internal exceptions never abort the full scan because handles are still closed in `finally`.
 * - 关键词: 进程路径收集 | process path collection | 模块路径枚举 | module path enumeration | 可疑文件筛选 | suspicious file filtering | 可信签名排除 | trusted-signature exclusion | 启动扫描输入 | startup scan input
 */
function getProcessPaths() {
    const paths = new Set();
    const systemRoot = (process.env.SystemRoot || 'C:\\Windows').toLowerCase();
    
    const maxProcesses = 4096;
    const pidsBuffer = Buffer.alloc(maxProcesses * 4);
    const bytesReturned = Buffer.alloc(4);
    
    const ret = EnumProcesses(pidsBuffer, pidsBuffer.length, bytesReturned);
    if (!ret) {
        console.error('EnumProcesses failed');
        return [];
    }
    
    const bytesUsed = bytesReturned.readUInt32LE(0);
    const numProcesses = Math.floor(bytesUsed / 4);
    
    for (let i = 0; i < numProcesses; i++) {
        const pid = pidsBuffer.readUInt32LE(i * 4);
        if (pid === 0) continue;
        
        let hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
        if (!hProcess) {
             hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        }

        if (hProcess) {
            try {
                const modulesBuffer = Buffer.alloc(1024 * 8);
                const cbNeeded = Buffer.alloc(4);
                
                if (EnumProcessModules(hProcess, modulesBuffer, modulesBuffer.length, cbNeeded)) {
                    const bytesNeeded = cbNeeded.readUInt32LE(0);
                    const numModules = Math.floor(Math.min(bytesNeeded, modulesBuffer.length) / (process.arch === 'x64' ? 8 : 4));
                    const ptrSize = process.arch === 'x64' ? 8 : 4;

                    for (let j = 0; j < numModules; j++) {
                         let hMod;
                         if (process.arch === 'x64') {
                             hMod = modulesBuffer.readBigUInt64LE(j * 8);
                         } else {
                             hMod = modulesBuffer.readUInt32LE(j * 4);
                         }
                         
                         if (!hMod) continue;

                         const pathBuffer = Buffer.alloc(4096);
                        const len = GetModuleFileNameExW(hProcess, hMod, pathBuffer, 2048);
                         if (len > 0) {
                             let path = pathBuffer.toString('utf16le', 0, len * 2);
                             path = (path || '').replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\uFFFD]/g, '').trim();
                             if (path.startsWith('\\??\\')) path = path.substring(4);
                             
                             const lowerPath = path.toLowerCase();
                             const isSystemDll = lowerPath.startsWith(systemRoot) && lowerPath.endsWith('.dll');
                             
                             if (!isSystemDll) {
                                 if (lowerPath.endsWith('.exe') || lowerPath.endsWith('.dll')) {
                                     if (!verifyTrust(path)) {
                                          paths.add(path);
                                     }
                                 } else {
                                     paths.add(path);
                                 }
                             }
                         }
                    }
                } else {
                    const pathBuffer = Buffer.alloc(4096);
                    const sizeBuf = Buffer.alloc(4);
                    sizeBuf.writeUInt32LE(2048, 0);
                    if (QueryFullProcessImageNameW(hProcess, 0, pathBuffer, sizeBuf)) {
                        const len = sizeBuf.readUInt32LE(0);
                        let path = pathBuffer.toString('utf16le', 0, len * 2);
                        path = (path || '').replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\uFFFD]/g, '').trim();
                        if (path.startsWith('\\??\\')) path = path.substring(4);
                        
                        const lowerPath = path.toLowerCase();
                        const isSystemDll = lowerPath.startsWith(systemRoot) && lowerPath.endsWith('.dll');
                        
                        if (!isSystemDll) {
                            if (lowerPath.endsWith('.exe') || lowerPath.endsWith('.dll')) {
                                if (!verifyTrust(path)) {
                                     paths.add(path);
                                }
                            } else {
                                paths.add(path);
                            }
                        }
                    }
                }
            } catch (e) {
            } finally {
                CloseHandle(hProcess);
            }
        }
    }
    
    return Array.from(paths);
}

/**
 * - 函数: `suspendProcessByPid`
 * - Function: `suspendProcessByPid`
 * - 作用: 通过 `NtSuspendProcess` 暂停指定进程，供拦截策略在用户确认前冻结可疑进程。
 * - Purpose: Suspends the target process via `NtSuspendProcess` so interception flows can freeze a suspicious process until the user decides what to do.
 * - 调用方: `main.js` 中的拦截确认与队列入列逻辑会调用本函数。
 * - Callers: Used by the interception confirmation and queueing flows in `main.js`.
 * - 被调方: `OpenProcess`、`NtSuspendProcess`、`CloseHandle`、`Number.isFinite`。
 * - Callees: `OpenProcess`, `NtSuspendProcess`, `CloseHandle`, and `Number.isFinite`.
 * - 变量说明: `pid` 为目标进程 ID；`hProcess` 为带暂停权限打开的句柄；`st` 为原生 NTSTATUS 返回值。
 * - Variables: `pid` is the target process ID, `hProcess` is the handle opened with suspend rights, and `st` is the native NTSTATUS result.
 * - 接入方式: 仅建议用于 Windows 拦截链路；若未来需要线程级挂起，应另建接口，不要复用本函数伪装更细粒度行为。
 * - Integration: Use it only in Windows interception flows; if thread-level suspension is needed later, add a dedicated API instead of stretching this helper.
 * - 错误处理: 未导出 `NtSuspendProcess`、PID 非法、打开进程失败或原生调用异常时均返回 `false`，且始终尝试关闭句柄。
 * - Error Handling: Missing `NtSuspendProcess`, invalid PIDs, failed process opens, or native exceptions all return `false`, and the handle is always closed.
 * - 关键词: 进程挂起 | process suspend | NtSuspendProcess封装 | NtSuspendProcess wrapper | 拦截冻结 | interception freeze | PID控制 | PID control | 句柄释放 | handle release
 */
function suspendProcessByPid(pid) {
    if (!NtSuspendProcess) return false;
    if (!Number.isFinite(pid) || pid <= 0) return false;
    const hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, 0, pid >>> 0);
    if (!hProcess) return false;
    try {
        const st = NtSuspendProcess(hProcess);
        return st === 0;
    } catch {
        return false;
    } finally {
        try { CloseHandle(hProcess); } catch {}
    }
}

/**
 * - 函数: `resumeProcessByPid`
 * - Function: `resumeProcessByPid`
 * - 作用: 通过 `NtResumeProcess` 恢复之前被拦截暂停的进程，是用户选择放行后的核心恢复动作。
 * - Purpose: Resumes a previously suspended process via `NtResumeProcess`, forming the core recovery action after the user chooses to allow execution.
 * - 调用方: `main.js` 中的单个放行、批量恢复和拦截窗口收尾逻辑会调用本函数。
 * - Callers: Used by the single-allow, batch-resume, and interception-window cleanup flows in `main.js`.
 * - 被调方: `OpenProcess`、`NtResumeProcess`、`CloseHandle`、`Number.isFinite`。
 * - Callees: `OpenProcess`, `NtResumeProcess`, `CloseHandle`, and `Number.isFinite`.
 * - 变量说明: `pid` 为目标进程 ID；`hProcess` 为恢复时使用的进程句柄；`st` 为原生 NTSTATUS 返回值。
 * - Variables: `pid` is the target process ID, `hProcess` is the process handle used for resume, and `st` is the native NTSTATUS result.
 * - 接入方式: 所有“恢复被暂停进程”的逻辑都应统一通过本函数，避免多处散落原生调用。
 * - Integration: All flows that resume suspended processes should call this helper so native resume logic stays centralized.
 * - 错误处理: 未提供 `NtResumeProcess`、PID 非法、句柄打开失败或原生调用异常时返回 `false`，并在 `finally` 中关闭句柄。
 * - Error Handling: Missing `NtResumeProcess`, invalid PIDs, failed handle opens, or native exceptions return `false`, and the handle is closed in `finally`.
 * - 关键词: 进程恢复 | process resume | NtResumeProcess封装 | NtResumeProcess wrapper | 放行动作 | allow action | 批量恢复支持 | batch resume support | 挂起解除 | suspension release
 */
function resumeProcessByPid(pid) {
    if (!NtResumeProcess) return false;
    if (!Number.isFinite(pid) || pid <= 0) return false;
    const hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, 0, pid >>> 0);
    if (!hProcess) return false;
    try {
        const st = NtResumeProcess(hProcess);
        return st === 0;
    } catch {
        return false;
    } finally {
        try { CloseHandle(hProcess); } catch {}
    }
}

/**
 * - 函数: `terminateProcessByPid`
 * - Function: `terminateProcessByPid`
 * - 作用: 通过 `TerminateProcess` 直接结束目标 PID，是拦截中“阻止运行”或强制清理流程的底层动作。
 * - Purpose: Terminates the target PID through `TerminateProcess`, acting as the low-level operation behind "block execution" and forced cleanup flows.
 * - 调用方: `main.js` 中用户选择阻止进程、异常收尾或需要强制结束目标进程的逻辑会调用本函数。
 * - Callers: Used by `main.js` when the user blocks a process, during exceptional cleanup, or whenever a target process must be force-terminated.
 * - 被调方: `OpenProcess`、`TerminateProcess`、`CloseHandle`、`Number.isFinite`。
 * - Callees: `OpenProcess`, `TerminateProcess`, `CloseHandle`, and `Number.isFinite`.
 * - 变量说明: `pid` 为目标进程 ID；`exitCode` 为终止退出码；`hProcess` 为带终止权限的句柄；`code` 为归一化后的无符号退出码。
 * - Variables: `pid` is the target process ID, `exitCode` is the requested termination code, `hProcess` is the terminate-capable handle, and `code` is the normalized unsigned exit code.
 * - 接入方式: 需要按 PID 强制终止进程时应优先复用本函数，不要在业务层直接拼 shell 命令。
 * - Integration: Reuse this helper whenever a process must be force-terminated by PID instead of composing shell commands in business logic.
 * - 错误处理: PID 非法、进程打开失败或原生终止调用异常时返回 `false`；句柄始终在 `finally` 中释放。
 * - Error Handling: Invalid PIDs, failed process opens, or native termination exceptions return `false`, and the handle is always released in `finally`.
 * - 关键词: PID强制终止 | PID force termination | TerminateProcess封装 | TerminateProcess wrapper | 阻止执行 | block execution | 退出码归一化 | exit-code normalization | 终止权限句柄 | termination handle
 */
function terminateProcessByPid(pid, exitCode = 1) {
    if (!Number.isFinite(pid) || pid <= 0) return false;
    const hProcess = OpenProcess(PROCESS_TERMINATE, 0, pid >>> 0);
    if (!hProcess) return false;
    try {
        const code = Number.isFinite(exitCode) ? (exitCode >>> 0) : 1;
        return !!TerminateProcess(hProcess, code);
    } catch {
        return false;
    } finally {
        try { CloseHandle(hProcess); } catch {}
    }
}

/**
 * - 函数: `setPipeSecurity`
 * - Function: `setPipeSecurity`
 * - 作用: 为命名管道设置“Everyone Full Access” DACL，解决扫描引擎与 Electron 主进程在不同权限上下文下的 IPC 访问问题。
 * - Purpose: Applies an `Everyone Full Access` DACL to a named pipe so the scanner engine and Electron main process can communicate even across different privilege contexts.
 * - 调用方: `main.js` 在创建或探测扫描引擎命名管道后会调用本函数修正访问权限。
 * - Callers: `main.js` calls this helper after creating or probing the scanner engine named pipe to fix access permissions.
 * - 被调方: `ConvertStringSecurityDescriptorToSecurityDescriptorW`、`GetSecurityDescriptorDacl`、`CreateFileW`、`SetSecurityInfo`、`SetNamedSecurityInfoW`、`GetLastError`、`CloseHandle`。
 * - Callees: `ConvertStringSecurityDescriptorToSecurityDescriptorW`, `GetSecurityDescriptorDacl`, `CreateFileW`, `SetSecurityInfo`, `SetNamedSecurityInfoW`, `GetLastError`, and `CloseHandle`.
 * - 变量说明: `pipeName` 为原始管道名；`name` 为清洗后的名称；`suffix` 为去掉前缀后的管道后缀；`candidates` 保存不同对象类型的命名候选；`sd` 为安全描述符；`dacl` 为提取出的访问控制列表。
 * - Variables: `pipeName` is the raw pipe name, `name` is the sanitized name, `suffix` is the pipe tail without prefix, `candidates` stores alternative object-name forms, `sd` is the security descriptor, and `dacl` is the extracted access-control list.
 * - 接入方式: 命名管道权限修复应统一通过本函数完成，避免调用方分别处理文件对象和内核对象两套路径。
 * - Integration: All named-pipe permission repair should go through this helper so callers do not duplicate file-object and kernel-object handling branches.
 * - 错误处理: 关键安全 API 缺失时直接返回 `false`；若句柄方式设置失败，会继续尝试命名对象方式并返回包含 `ok`、`code`、`name`、`type` 的结果对象。
 * - Error Handling: It returns `false` immediately when required security APIs are missing; if handle-based updates fail, it continues with named-object updates and returns a structured `{ ok, code, name, type }` result.
 * - 关键词: 命名管道权限 | named pipe security | DACL设置 | DACL assignment | Everyone全访问 | Everyone full access | IPC权限修复 | IPC permission repair | 安全描述符转换 | security descriptor conversion
 */
function setPipeSecurity(pipeName) {
    if (!pipeName || !ConvertStringSecurityDescriptorToSecurityDescriptorW || !GetSecurityDescriptorDacl || !SetNamedSecurityInfoW || !SetSecurityInfo) return false;
    let name = String(pipeName || '').trim();
    let suffix = name;
    if (suffix.startsWith('\\\\.\\pipe\\')) {
        suffix = suffix.slice('\\\\.\\pipe\\'.length);
    }
    const candidates = [
        { name, type: SE_FILE_OBJECT },
        { name: '\\\\?\\pipe\\' + suffix, type: SE_FILE_OBJECT },
        { name: '\\\\Device\\\\NamedPipe\\\\' + suffix, type: SE_KERNEL_OBJECT },
        { name: 'PIPE\\' + suffix, type: SE_KERNEL_OBJECT }
    ];
    let sd = null;
    try {
        const outSd = [null];
        const sizeBuf = Buffer.alloc(4);
        const ok = ConvertStringSecurityDescriptorToSecurityDescriptorW(SDDL_EVERYONE_FULL, 1, outSd, sizeBuf);
        if (!ok) return false;
        sd = outSd[0];
        if (!sd) return false;
        const daclPresent = Buffer.alloc(4);
        const daclDefaulted = Buffer.alloc(4);
        const outDacl = [null];
        const okDacl = GetSecurityDescriptorDacl(sd, daclPresent, outDacl, daclDefaulted);
        if (!okDacl) return false;
        if (daclPresent.readInt32LE(0) === 0) return false;
        const dacl = outDacl[0];
        const desiredAccess = READ_CONTROL | WRITE_DAC;
        const shareMode = FILE_SHARE_READ | FILE_SHARE_WRITE;
        const hPipe = CreateFileW(name, desiredAccess, shareMode, null, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, null);
        if (hPipe) {
            const rcHandle = SetSecurityInfo(hPipe, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, null, null, dacl, null);
            try { CloseHandle(hPipe); } catch {}
            if (rcHandle === 0) return { ok: true, code: 0, name, type: 'handle' };
        }
        let lastCode = 0;
        let lastName = '';
        let lastType = '';
        for (const candidate of candidates) {
            const rc = SetNamedSecurityInfoW(candidate.name, candidate.type, DACL_SECURITY_INFORMATION, null, null, dacl, null);
            if (rc === 0) return { ok: true, code: 0, name: candidate.name, type: candidate.type === SE_FILE_OBJECT ? 'file' : 'kernel' };
            lastCode = rc;
            lastName = candidate.name;
            lastType = candidate.type === SE_FILE_OBJECT ? 'file' : 'kernel';
        }
        return { ok: false, code: Number.isFinite(lastCode) ? lastCode : 0, name: lastName, type: lastType };
    } catch {
        const err = GetLastError ? GetLastError() : 0;
        return { ok: false, code: Number.isFinite(err) ? err : -1, name: name, type: 'error' };
    } finally {
        if (sd) {
            try { LocalFree(sd); } catch {}
        }
    }
}

module.exports = {
    verifyTrust,
    getSignerInfo,
    computeFileSha256Hex,
    scanCacheLookupByFile,
    scanCacheStore,
    getProcessPaths,
    getProcessImagePathByPid,
    getProcessImageSnapshot,
    getProcessModules,
    getDriveDeviceMap,
    primeDriveDeviceMap,
    devicePathToDosPath,
    suspendProcessByPid,
    resumeProcessByPid,
    terminateProcessByPid,
    setPipeSecurity,
    PROCESS_SUSPEND_RESUME,
    PROCESS_TERMINATE
};
