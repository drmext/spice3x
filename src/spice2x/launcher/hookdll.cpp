#include "hookdll.h"

#include <string>
#include <vector>

#include <shellapi.h>
#include <windows.h>

#include "launcher/launcher.h"
#include "util/logging.h"
#include "util/utils.h"

BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) {
    // Do not call DisableThreadLibraryCalls. The init thread is created by
    // CreateRemoteThread, and MinGW's CRT sets up that thread from
    // DLL_THREAD_ATTACH. Skipping it leaves TLS/errno unmapped and the first
    // CRT call access-violates.
    return TRUE;
}

extern "C" SPICE_THREAD_ENTRY DWORD WINAPI spice_exe_init(LPVOID) {
    const char *cmdline = getenv("SPICE_CMDLINE");
    if (!cmdline || !*cmdline) {
        // Fall back to the process command line (bm2dx.exe args) — still
        // enough for spice to parse its own options if the host set none.
        cmdline = GetCommandLineA();
    }

    int wargc = 0;
    LPWSTR *wargv = CommandLineToArgvW(s2ws(cmdline).c_str(), &wargc);
    if (!wargv || wargc < 1) {
        if (wargv) {
            LocalFree(wargv);
        }
        return 1;
    }

    // Convert to UTF-8 argv for main_implementation
    std::vector<std::string> args_storage;
    args_storage.reserve(static_cast<size_t>(wargc));
    for (int i = 0; i < wargc; i++) {
        args_storage.push_back(ws2s(wargv[i]));
    }
    LocalFree(wargv);

    std::vector<char *> argv;
    argv.reserve(args_storage.size());
    for (auto &s : args_storage) {
        argv.push_back(s.data());
    }

    // Ensure the injected flag is visible even if CreateProcess inheritance
    // dropped the variable for any reason.
    SetEnvironmentVariableA("SPICE_INJECTED", "1");

    // bm2dx.exe is a GUI image and CreateProcess did not inherit std handles,
    // so logger WriteFile(STD_OUTPUT_HANDLE) would go nowhere. Attach to the
    // spice.exe console before logger::start() so inject + game logs share it.
    if (!AttachConsole(ATTACH_PARENT_PROCESS)) {
        const DWORD err = GetLastError();
        if (err != ERROR_ACCESS_DENIED) {
            // ERROR_ACCESS_DENIED: already attached; anything else: no console
        }
    }
    HANDLE conout = CreateFileA(
            "CONOUT$",
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            0,
            nullptr);
    if (conout != INVALID_HANDLE_VALUE) {
        SetStdHandle(STD_OUTPUT_HANDLE, conout);
        SetStdHandle(STD_ERROR_HANDLE, conout);
    }

    const int rc = main_implementation(static_cast<int>(argv.size()), argv.data());
    return static_cast<DWORD>(rc < 0 ? 1 : rc);
}
