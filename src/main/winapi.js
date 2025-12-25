const koffi = require('koffi');

// Load libraries
const libKernel32 = koffi.load('kernel32.dll');
const libPsapi = koffi.load('psapi.dll');
let libWintrust = null;
try {
    libWintrust = koffi.load('wintrust.dll');
} catch (e) {
    console.warn('Failed to load wintrust.dll', e);
}

// Define types
const HANDLE = koffi.pointer('HANDLE', koffi.opaque());
const HMODULE = koffi.pointer('HMODULE', koffi.opaque());
const LPWSTR = koffi.pointer('LPWSTR', 'uint16_t'); // Pointer to uint16 buffer
const DWORD = 'uint32_t';
const BOOL = 'int';
const LONG = 'long';

// GUID
const GUID = koffi.struct('GUID', {
    Data1: 'uint32_t',
    Data2: 'uint16_t',
    Data3: 'uint16_t',
    Data4: koffi.array('uint8_t', 8)
});

// WinVerifyTrust types
const WINTRUST_FILE_INFO = koffi.struct('WINTRUST_FILE_INFO', {
    cbStruct: 'uint32_t',
    pcwszFilePath: 'string16', // LPCWSTR
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
    pFile: koffi.pointer(WINTRUST_FILE_INFO), // Union (we use file info)
    dwStateAction: 'uint32_t',
    hWVTStateData: 'HANDLE',
    pwszURLReference: 'string16',
    dwProvFlags: 'uint32_t',
    dwUIContext: 'uint32_t',
    pSignatureSettings: 'void *'
});

// Constants
const PROCESS_QUERY_INFORMATION = 0x0400;
const PROCESS_VM_READ = 0x0010;
const PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
const SYNCHRONIZE = 0x00100000;
const MAX_PATH = 260; 

// WinVerifyTrust Constants
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

// Function definitions
// func(convention, name, ret, params)
const OpenProcess = libKernel32.func('__stdcall', 'OpenProcess', HANDLE, [DWORD, BOOL, DWORD]);
const CloseHandle = libKernel32.func('__stdcall', 'CloseHandle', BOOL, [HANDLE]);
const EnumProcesses = libPsapi.func('__stdcall', 'EnumProcesses', BOOL, [koffi.out('uint32_t *'), DWORD, koffi.out('uint32_t *')]);
const EnumProcessModules = libPsapi.func('__stdcall', 'EnumProcessModules', BOOL, [HANDLE, koffi.out('void *'), DWORD, koffi.out('uint32_t *')]);
const GetModuleFileNameExW = libPsapi.func('__stdcall', 'GetModuleFileNameExW', DWORD, [HANDLE, HMODULE, koffi.out(LPWSTR), DWORD]);
const QueryFullProcessImageNameW = libKernel32.func('__stdcall', 'QueryFullProcessImageNameW', BOOL, [HANDLE, DWORD, koffi.out(LPWSTR), koffi.inout('uint32_t *')]);

let WinVerifyTrust = null;
if (libWintrust) {
    try {
        WinVerifyTrust = libWintrust.func('__stdcall', 'WinVerifyTrust', LONG, ['void *', koffi.pointer(GUID), koffi.pointer(WINTRUST_DATA)]);
    } catch (e) {
        console.warn('Failed to bind WinVerifyTrust', e);
    }
}

// WINTRUST_ACTION_GENERIC_VERIFY_V2
// {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
const ACTION_GENERIC_VERIFY_V2 = {
    Data1: 0x00AAC56B,
    Data2: 0xCD44,
    Data3: 0x11D0,
    Data4: [0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE]
};

const trustedCache = new Map();

function verifyTrust(filePath) {
    if (!WinVerifyTrust) return false;
    
    // Check cache
    if (trustedCache.has(filePath)) return trustedCache.get(filePath);

    const fileInfo = {
        cbStruct: 0, // Set later
        pcwszFilePath: filePath,
        hFile: null,
        pgKnownSubject: null
    };
    // Need to set size manually as Koffi might not do it automatically for us inside the struct logic unless we encode it
    // Koffi structs usually calculate size. But WinAPI expects the field to be set.
    // sizeof(WINTRUST_FILE_INFO) = 4 + 8 + 8 + 8 = 28 on x64? Or 4 + 4 + 4 + 4 = 16 on x86.
    // We can rely on koffi.sizeof(WINTRUST_FILE_INFO).
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
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL, // Do not hit network
        dwUIContext: 0,
        pSignatureSettings: null
    };
    winTrustData.cbStruct = koffi.sizeof(WINTRUST_DATA);

    try {
        // We need to pass the struct as a pointer. Koffi handles object -> struct conversion.
        // But for nested pointers (pFile), we might need to be careful.
        // Koffi says: "If you pass a JS object where a pointer is expected, Koffi allocates memory..."
        
        // However, we need to make sure the nested pointer `pFile` is valid.
        // We can explicitly encode it or let koffi handle it.
        // Let's try passing the object directly.
        
        const status = WinVerifyTrust(null, ACTION_GENERIC_VERIFY_V2, winTrustData);
        
        // Close state
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


function getProcessPaths() {
    const paths = new Set();
    const systemRoot = (process.env.SystemRoot || 'C:\\Windows').toLowerCase();
    
    // 1. EnumProcesses
    const maxProcesses = 4096;
    const pidsBuffer = Buffer.alloc(maxProcesses * 4);
    const bytesReturned = Buffer.alloc(4); // DWORD
    
    const ret = EnumProcesses(pidsBuffer, pidsBuffer.length, bytesReturned);
    if (!ret) {
        console.error('EnumProcesses failed');
        return [];
    }
    
    const bytesUsed = bytesReturned.readUInt32LE(0);
    const numProcesses = Math.floor(bytesUsed / 4);
    
    // 2. Loop through PIDs
    for (let i = 0; i < numProcesses; i++) {
        const pid = pidsBuffer.readUInt32LE(i * 4);
        if (pid === 0) continue; // System Idle Process
        
        // Use PROCESS_QUERY_INFORMATION | PROCESS_VM_READ to be able to read modules
        let hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
        if (!hProcess) {
             // Fallback to limited info (might miss some modules but can get main exe)
             hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        }

        if (hProcess) {
            try {
                // Get all modules
                const modulesBuffer = Buffer.alloc(1024 * 8); // Array of HMODULEs (8 bytes on x64, 4 on x86, assume max size)
                const cbNeeded = Buffer.alloc(4);
                
                // If EnumProcessModules fails (e.g. access denied or 32/64 bit mismatch), we just try to get main image name
                if (EnumProcessModules(hProcess, modulesBuffer, modulesBuffer.length, cbNeeded)) {
                    const bytesNeeded = cbNeeded.readUInt32LE(0);
                    const numModules = Math.floor(Math.min(bytesNeeded, modulesBuffer.length) / (process.arch === 'x64' ? 8 : 4));
                    const ptrSize = process.arch === 'x64' ? 8 : 4;

                    for (let j = 0; j < numModules; j++) {
                         // Read HMODULE (pointer) - actually we just pass it to GetModuleFileNameExW
                         // But we need the value if we were to construct it? 
                         // Koffi handles opaque pointers but here we have a buffer of pointers.
                         // We can pass the address inside the buffer? No, we need the HMODULE value.
                         // But wait, EnumProcessModules fills an array of HMODULEs.
                         // GetModuleFileNameExW takes an HMODULE.
                         // We can read the pointer value from buffer.
                         
                         // Simplification: Just read main module first?
                         // User wants ALL loaded dlls.
                         
                         // We need to pass HMODULE value to GetModuleFileNameExW.
                         // Since HMODULE is opaque pointer, in JS it's a BigInt (64-bit) or Number (32-bit) address.
                         let hMod;
                         if (process.arch === 'x64') {
                             hMod = modulesBuffer.readBigUInt64LE(j * 8);
                         } else {
                             hMod = modulesBuffer.readUInt32LE(j * 4);
                         }
                         
                         // Skip null handles
                         if (!hMod) continue;

                         const pathBuffer = Buffer.alloc(4096);
                         const len = GetModuleFileNameExW(hProcess, hMod, pathBuffer, 2048);
                         if (len > 0) {
                             let path = pathBuffer.toString('utf16le', 0, len * 2);
                             if (path.startsWith('\\??\\')) path = path.substring(4);
                             
                             const lowerPath = path.toLowerCase();
                             const isSystemDll = lowerPath.startsWith(systemRoot) && lowerPath.endsWith('.dll');
                             
                             if (!isSystemDll) {
                                 // Check digital signature if it's an executable or dll
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
                    // EnumProcessModules failed, try QueryFullProcessImageNameW for main exe at least
                    const pathBuffer = Buffer.alloc(4096);
                    const sizeBuf = Buffer.alloc(4);
                    sizeBuf.writeUInt32LE(2048, 0);
                    if (QueryFullProcessImageNameW(hProcess, 0, pathBuffer, sizeBuf)) {
                        const len = sizeBuf.readUInt32LE(0);
                        let path = pathBuffer.toString('utf16le', 0, len * 2);
                        if (path.startsWith('\\??\\')) path = path.substring(4);
                        
                        const lowerPath = path.toLowerCase();
                        const isSystemDll = lowerPath.startsWith(systemRoot) && lowerPath.endsWith('.dll');
                        
                        if (!isSystemDll) {
                            // Check digital signature if it's an executable or dll
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
                // Ignore errors
            } finally {
                CloseHandle(hProcess);
            }
        }
    }
    
    return Array.from(paths);
}

module.exports = {
    getProcessPaths
};
