#pragma once

#include <windows.h>

// Exported entry called via CreateRemoteThread after LoadLibraryW of the
// embedded hook image. Returns 0 on success.
extern "C" DWORD WINAPI spice_exe_init(LPVOID param);
