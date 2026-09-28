#include "hookdll.h"

#include <string>
#include <vector>

#include <shellapi.h>
#include <windows.h>

#include "launcher/launcher.h"
#include "util/logging.h"
#include "util/utils.h"

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
    }
    return TRUE;
}

extern "C" DWORD WINAPI spice_exe_init(LPVOID) {
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

    const int rc = main_implementation(static_cast<int>(argv.size()), argv.data());
    return static_cast<DWORD>(rc < 0 ? 1 : rc);
}
