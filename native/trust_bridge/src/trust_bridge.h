#pragma once

#include <cstdint>

#if defined(_WIN32)
  #if defined(TRUST_BRIDGE_BUILD)
    #define TRUST_BRIDGE_API __declspec(dllexport)
  #else
    #define TRUST_BRIDGE_API __declspec(dllimport)
  #endif
#else
  #define TRUST_BRIDGE_API
#endif

extern "C" {

TRUST_BRIDGE_API int TrustBridge_SetCacheConfig(std::uint32_t maxEntries, std::uint32_t ttlMs);

TRUST_BRIDGE_API int TrustBridge_VerifyFile(const wchar_t* filePath, unsigned long* outStatus);

TRUST_BRIDGE_API int TrustBridge_GetSignerInfoJson(const wchar_t* filePath, char** outUtf8Json);

TRUST_BRIDGE_API int TrustBridge_ComputeFileSha256Hex(const wchar_t* filePath, char** outUtf8Hex);

TRUST_BRIDGE_API int TrustBridge_ScanCacheLookupByFile(const wchar_t* filePath, int* outVerdict, char** outUtf8Hex);

TRUST_BRIDGE_API int TrustBridge_ScanCacheLookupByFile2(const wchar_t* filePath, int* outVerdict, char* outUtf8HexBuf, int outCap);

TRUST_BRIDGE_API int TrustBridge_ScanCacheStore(const char* utf8HashHex, int verdict);

TRUST_BRIDGE_API void TrustBridge_Free(void* p);

}
