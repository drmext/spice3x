#pragma once

#include <windows.h>

namespace hooks::lang {
    void early_init();
    void init();

    // Patch MultiByteToWideChar on a specific module. Needed when the null-module
    // PEB walk in init() skips the injected game exe.
    void init_module(HMODULE module);

    bool is_native_shiftjis();
}
