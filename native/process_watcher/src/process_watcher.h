#pragma once

#include <windows.h>

extern "C" __declspec(dllexport) int ProcessWatcher_Start(const wchar_t* injectorX64, const wchar_t* injectorX86, const wchar_t* dllX64, const wchar_t* dllX86, int intervalMs);
extern "C" __declspec(dllexport) void ProcessWatcher_Stop();
extern "C" __declspec(dllexport) int ProcessWatcher_SetSignedList(const wchar_t* data, int length);
extern "C" __declspec(dllexport) int ProcessWatcher_PollNewPid();
