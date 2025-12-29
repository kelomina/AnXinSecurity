const fs = require('fs');
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

const OpenProcess = libKernel32.func('__stdcall', 'OpenProcess', HANDLE, [DWORD, BOOL, DWORD]);
const CloseHandle = libKernel32.func('__stdcall', 'CloseHandle', BOOL, [HANDLE]);
const TerminateProcess = libKernel32.func('__stdcall', 'TerminateProcess', BOOL, [HANDLE, DWORD]);
const QueryDosDeviceW = libKernel32.func('__stdcall', 'QueryDosDeviceW', DWORD, ['string16', koffi.out(LPWSTR), DWORD]);
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

const ACTION_GENERIC_VERIFY_V2 = {
    Data1: 0x00AAC56B,
    Data2: 0xCD44,
    Data3: 0x11D0,
    Data4: [0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE]
};

const trustedCache = new Map();

function verifyTrust(filePath) {
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

function devicePathToDosPath(p) {
    if (typeof p !== 'string') return '';
    let s = p.trim();
    if (!s) return '';
    if (s.startsWith('\\??\\')) s = s.substring(4);
    if (/^[a-zA-Z]:[\\/]/.test(s)) return s;
    const lower = s.toLowerCase();
    if (!lower.startsWith('\\device\\')) return s;

    const map = getDriveDeviceMap();
    for (const [dev, driveName] of map.entries()) {
        if (lower === dev) return driveName + '\\';
        if (lower.startsWith(dev + '\\')) return driveName + s.substring(dev.length);
    }
    return s;
}


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

module.exports = {
    verifyTrust,
    getProcessPaths,
    getProcessImagePathByPid,
    getProcessImageSnapshot,
    getProcessModules,
    getDriveDeviceMap,
    devicePathToDosPath,
    suspendProcessByPid,
    resumeProcessByPid,
    terminateProcessByPid,
    PROCESS_SUSPEND_RESUME,
    PROCESS_TERMINATE
};
