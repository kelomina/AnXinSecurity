#pragma once

#include <cstdint>

#if defined(_WIN32)
  #if defined(ETW_BRIDGE_BUILD)
    #define ETW_BRIDGE_API __declspec(dllexport)
  #else
    #define ETW_BRIDGE_API __declspec(dllimport)
  #endif
#else
  #define ETW_BRIDGE_API
#endif

extern "C" {

ETW_BRIDGE_API void* EtwBridge_Create(const wchar_t* sessionName);

ETW_BRIDGE_API int EtwBridge_Start(
    void* handle,
    std::uint64_t processAnyKeyword, std::uint64_t processAllKeyword,
    std::uint64_t fileAnyKeyword, std::uint64_t fileAllKeyword,
    std::uint64_t registryAnyKeyword, std::uint64_t registryAllKeyword,
    std::uint64_t networkAnyKeyword, std::uint64_t networkAllKeyword,
    int networkEnabled,
    int filterPrivateIps,
    int skipLoopback,
    std::uint32_t userDataMaxBytes);

ETW_BRIDGE_API int EtwBridge_Stop(void* handle, std::uint32_t timeoutMs);

ETW_BRIDGE_API int EtwBridge_PollJson(void* handle, char** outUtf8Json);

ETW_BRIDGE_API void EtwBridge_Free(void* p);

ETW_BRIDGE_API void EtwBridge_Destroy(void* handle);

}

