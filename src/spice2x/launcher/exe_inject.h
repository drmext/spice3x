#pragma once

#include <filesystem>
#include <optional>
#include <string>

namespace launcher {

    struct ExeGameTarget {
        std::string model;
        std::string dest;
        std::string spec;
        std::string rev;
        std::string ext;
        std::filesystem::path sidcode_dir;
        std::filesystem::path work_dir;
        std::filesystem::path exe_path;
    };

    // Look for IIDX 14-17 sidcode.txt next to spice.exe (or its parent when
    // spice was started from inside the date folder). Accepts GLD/HDD/I00/JDJ.
    std::optional<ExeGameTarget> try_detect_jdj();

    // CREATE_SUSPENDED + LoadLibraryW of the embedded hook + spice_exe_init,
    // then wait for the game process. Returns the game exit code.
    int exe_inject(const ExeGameTarget &target);

    // Terminate the injected game process early (CTRL+C / console close).
    // No-op when not injecting.
    void terminate_injected_child();
}
