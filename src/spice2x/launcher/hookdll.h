#pragma once

#include <windows.h>

// CreateRemoteThread calls this directly. MinGW codegen assumes a 16-byte
// aligned stack; the Windows thread starter only guarantees 4. Without the
// realign attribute the prologue faults with 0xC0000005 before any C++ runs.
// Release builds use -fvisibility=hidden, so a .def alias of _spice_exe_init@4
// is not an exportable symbol. dllexport marks this entry and keeps it alive
// across --gc-sections. --kill-at strips the stdcall @4 from the export name.
#if defined(__GNUC__)
#define SPICE_THREAD_ENTRY \
    __attribute__((force_align_arg_pointer, visibility("default"), used, dllexport))
#else
#define SPICE_THREAD_ENTRY
#endif

// Exported entry called via CreateRemoteThread after LoadLibraryW of the
// embedded hook image. Returns 0 on success.
extern "C" SPICE_THREAD_ENTRY DWORD WINAPI spice_exe_init(LPVOID param);
