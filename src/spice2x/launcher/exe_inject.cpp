#include "exe_inject.h"

#include <fstream>
#include <string>
#include <vector>

#include <windows.h>

#if defined(SPICE64)

namespace launcher {

    std::optional<ExeGameTarget> try_detect_jdj() {
        return std::nullopt;
    }

    int exe_inject(const ExeGameTarget &) {
        return 1;
    }
}

#else

#include "build/resource.h"
#include "launcher/launcher.h"
#include "util/fileutils.h"
#include "util/logging.h"
#include "util/resutils.h"
#include "util/utils.h"

namespace launcher {

    static std::optional<ExeGameTarget> parse_sidcode_file(
            const std::filesystem::path &sidcode_path) {
        if (!fileutils::file_exists(sidcode_path)) {
            return std::nullopt;
        }

        auto text = fileutils::text_read(sidcode_path);
        // trim whitespace / CR
        while (!text.empty() && (text.back() == '\n' || text.back() == '\r'
                || text.back() == ' ' || text.back() == '\t')) {
            text.pop_back();
        }
        if (text.empty()) {
            return std::nullopt;
        }

        // model:dest:spec:rev:ext
        std::vector<std::string> fields;
        size_t start = 0;
        while (start <= text.size()) {
            auto pos = text.find(':', start);
            if (pos == std::string::npos) {
                fields.push_back(text.substr(start));
                break;
            }
            fields.push_back(text.substr(start, pos - start));
            start = pos + 1;
        }
        if (fields.size() != 5) {
            log_warning("exe-inject", "sidcode.txt has {} fields, expected 5: {}",
                    fields.size(), text);
            return std::nullopt;
        }

        ExeGameTarget target;
        target.model = fields[0];
        target.dest = fields[1];
        target.spec = fields[2];
        target.rev = fields[3];
        target.ext = fields[4];
        target.sidcode_dir = sidcode_path.parent_path();
        target.work_dir = target.sidcode_dir / target.ext;
        target.exe_path = target.work_dir / "bm2dx.exe";
        return target;
    }

    std::optional<ExeGameTarget> try_detect_jdj() {
        // Prefer sidcode next to spice.exe; also try parent when spice lives
        // inside the date folder (e.g. JDJ\2010071200\spice.exe).
        const std::filesystem::path candidates[] = {
            MODULE_PATH / "sidcode.txt",
            MODULE_PATH.parent_path() / "sidcode.txt",
        };

        for (const auto &path : candidates) {
            auto target = parse_sidcode_file(path);
            if (!target) {
                continue;
            }
            if (_stricmp(target->model.c_str(), "JDJ") != 0) {
                log_misc("exe-inject", "sidcode model {} is not JDJ, ignoring",
                        target->model);
                continue;
            }
            if (!fileutils::file_exists(target->exe_path)) {
                log_warning("exe-inject",
                        "JDJ sidcode points at missing exe: {}",
                        target->exe_path.string());
                continue;
            }
            log_info("exe-inject", "detected IIDX 17 Sirius (JDJ) at {}",
                    target->exe_path.string());
            return target;
        }
        return std::nullopt;
    }

    // Find export RVA of `name` in a PE image in memory (no LoadLibrary).
    static DWORD find_export_rva(const uint8_t *data, size_t size, const char *name) {
        if (size < sizeof(IMAGE_DOS_HEADER)) {
            return 0;
        }
        auto dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(data);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            return 0;
        }
        if (static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS32) > size) {
            return 0;
        }
        auto nt = reinterpret_cast<const IMAGE_NT_HEADERS32 *>(data + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) {
            return 0;
        }
        if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            return 0;
        }

        const auto &dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (dir.VirtualAddress == 0 || dir.Size == 0) {
            return 0;
        }

        auto rva_to_off = [&](DWORD rva) -> size_t {
            auto sec = IMAGE_FIRST_SECTION(const_cast<IMAGE_NT_HEADERS32 *>(nt));
            for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
                if (rva >= sec->VirtualAddress
                        && rva < sec->VirtualAddress + sec->SizeOfRawData) {
                    return sec->PointerToRawData + (rva - sec->VirtualAddress);
                }
            }
            return static_cast<size_t>(-1);
        };

        const size_t exp_off = rva_to_off(dir.VirtualAddress);
        if (exp_off == static_cast<size_t>(-1) || exp_off + sizeof(IMAGE_EXPORT_DIRECTORY) > size) {
            return 0;
        }
        auto exp = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY *>(data + exp_off);

        const size_t names_off = rva_to_off(exp->AddressOfNames);
        const size_t ords_off = rva_to_off(exp->AddressOfNameOrdinals);
        const size_t funcs_off = rva_to_off(exp->AddressOfFunctions);
        if (names_off == static_cast<size_t>(-1)
                || ords_off == static_cast<size_t>(-1)
                || funcs_off == static_cast<size_t>(-1)) {
            return 0;
        }

        auto names = reinterpret_cast<const DWORD *>(data + names_off);
        auto ords = reinterpret_cast<const WORD *>(data + ords_off);
        auto funcs = reinterpret_cast<const DWORD *>(data + funcs_off);

        for (DWORD i = 0; i < exp->NumberOfNames; i++) {
            const size_t name_off = rva_to_off(names[i]);
            if (name_off == static_cast<size_t>(-1) || name_off >= size) {
                continue;
            }
            if (strcmp(reinterpret_cast<const char *>(data + name_off), name) == 0) {
                const DWORD rva = funcs[ords[i]];
                // A .def name that does not match the stdcall symbol is exported
                // as a bogus high RVA (observed 0xD0000000). Reject anything
                // that does not land in a real section.
                if (rva_to_off(rva) == static_cast<size_t>(-1)) {
                    log_warning("exe-inject",
                            "export {} has invalid RVA {:#x}",
                            name, rva);
                    return 0;
                }
                return rva;
            }
        }
        return 0;
    }

    static bool write_temp_hook(const uint8_t *data, size_t size, std::filesystem::path &out_path) {
        wchar_t temp_dir[MAX_PATH];
        if (!GetTempPathW(MAX_PATH, temp_dir)) {
            log_warning("exe-inject", "GetTempPathW failed: {}", GetLastError());
            return false;
        }
        wchar_t temp_file[MAX_PATH];
        if (!GetTempFileNameW(temp_dir, L"sph", 0, temp_file)) {
            log_warning("exe-inject", "GetTempFileNameW failed: {}", GetLastError());
            return false;
        }

        // GetTempFileName creates a 0-byte file; replace it with the DLL and
        // give it a .dll extension so LoadLibrary is happy.
        out_path = temp_file;
        out_path.replace_extension(L".dll");
        DeleteFileW(temp_file);

        std::ofstream out(out_path, std::ios::binary);
        if (!out) {
            log_warning("exe-inject", "failed to open temp hook path {}", out_path.string());
            return false;
        }
        out.write(reinterpret_cast<const char *>(data), static_cast<std::streamsize>(size));
        if (!out) {
            log_warning("exe-inject", "failed to write temp hook image");
            return false;
        }
        return true;
    }

    static bool remote_load_library(HANDLE process, const std::filesystem::path &dll_path,
            HMODULE *remote_module) {
        const auto path_w = dll_path.wstring();
        const size_t bytes = (path_w.size() + 1) * sizeof(wchar_t);

        void *remote = VirtualAllocEx(process, nullptr, bytes, MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE);
        if (!remote) {
            log_warning("exe-inject", "VirtualAllocEx failed: {}", GetLastError());
            return false;
        }

        if (!WriteProcessMemory(process, remote, path_w.c_str(), bytes, nullptr)) {
            log_warning("exe-inject", "WriteProcessMemory failed: {}", GetLastError());
            VirtualFreeEx(process, remote, 0, MEM_RELEASE);
            return false;
        }

        // Both host and target are 32-bit; LoadLibraryW in this process is a
        // valid address in the game.
        auto load_library_w = reinterpret_cast<LPTHREAD_START_ROUTINE>(
                GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW"));
        if (!load_library_w) {
            VirtualFreeEx(process, remote, 0, MEM_RELEASE);
            return false;
        }

        HANDLE thread = CreateRemoteThread(process, nullptr, 0, load_library_w, remote, 0, nullptr);
        if (!thread) {
            log_warning("exe-inject", "CreateRemoteThread(LoadLibraryW) failed: {}", GetLastError());
            VirtualFreeEx(process, remote, 0, MEM_RELEASE);
            return false;
        }

        WaitForSingleObject(thread, INFINITE);
        DWORD exit_code = 0;
        GetExitCodeThread(thread, &exit_code);
        CloseHandle(thread);
        VirtualFreeEx(process, remote, 0, MEM_RELEASE);

        if (exit_code == 0) {
            log_warning("exe-inject", "remote LoadLibraryW returned NULL");
            return false;
        }
        *remote_module = reinterpret_cast<HMODULE>(static_cast<uintptr_t>(exit_code));
        return true;
    }

    static bool remote_call_export(HANDLE process, HMODULE remote_module, DWORD export_rva) {
        auto start = reinterpret_cast<LPTHREAD_START_ROUTINE>(
                reinterpret_cast<uint8_t *>(remote_module) + export_rva);
        HANDLE thread = CreateRemoteThread(process, nullptr, 0, start, nullptr, 0, nullptr);
        if (!thread) {
            log_warning("exe-inject", "CreateRemoteThread(spice_exe_init) failed: {}", GetLastError());
            return false;
        }
        WaitForSingleObject(thread, INFINITE);
        DWORD exit_code = 0;
        GetExitCodeThread(thread, &exit_code);
        CloseHandle(thread);
        if (exit_code != 0) {
            log_warning("exe-inject", "spice_exe_init returned {}", exit_code);
            return false;
        }
        return true;
    }

    int exe_inject(const ExeGameTarget &target) {
        log_info("exe-inject", "injecting into {}", target.exe_path.string());

        DWORD res_size = 0;
        const char *res_data = resutil::load_file(IDR_SPICEHOOK, &res_size);
        if (!res_data || res_size == 0) {
            log_fatal("exe-inject", "embedded spicehook image (IDR_SPICEHOOK) missing");
        }

        const auto *bytes = reinterpret_cast<const uint8_t *>(res_data);
        const DWORD init_rva = find_export_rva(bytes, res_size, "spice_exe_init");
        if (init_rva == 0) {
            log_fatal("exe-inject", "spice_exe_init export not found in embedded hook");
        }

        std::filesystem::path temp_dll;
        if (!write_temp_hook(bytes, res_size, temp_dll)) {
            log_fatal("exe-inject", "failed to extract embedded hook to temp file");
        }
        log_info("exe-inject", "extracted hook to {}", temp_dll.string());

        // Build a command line that is just the game exe (no spice args).
        std::wstring cmd = L"\"" + target.exe_path.wstring() + L"\"";
        std::wstring work_dir = target.work_dir.wstring();

        // Pass spice's original command line and inject flag to the child.
        std::string spice_cmdline;
        if (LAUNCHER_ARGC > 0 && LAUNCHER_ARGV) {
            for (int i = 0; i < LAUNCHER_ARGC; i++) {
                if (i) {
                    spice_cmdline.push_back(' ');
                }
                const bool need_quotes = strchr(LAUNCHER_ARGV[i], ' ') != nullptr;
                if (need_quotes) {
                    spice_cmdline.push_back('"');
                }
                spice_cmdline += LAUNCHER_ARGV[i];
                if (need_quotes) {
                    spice_cmdline.push_back('"');
                }
            }
        } else {
            spice_cmdline = GetCommandLineA();
        }
        SetEnvironmentVariableA("SPICE_INJECTED", "1");
        SetEnvironmentVariableA("SPICE_CMDLINE", spice_cmdline.c_str());

        STARTUPINFOW si {};
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi {};

        BOOL ok = CreateProcessW(
                target.exe_path.c_str(),
                cmd.data(),
                nullptr,
                nullptr,
                FALSE,
                CREATE_SUSPENDED,
                nullptr,
                work_dir.c_str(),
                &si,
                &pi);

        // Clear from this process so a later re-entry cannot confuse us.
        SetEnvironmentVariableA("SPICE_INJECTED", nullptr);
        SetEnvironmentVariableA("SPICE_CMDLINE", nullptr);

        if (!ok) {
            DeleteFileW(temp_dll.c_str());
            log_fatal("exe-inject", "CreateProcessW failed: {}", GetLastError());
        }

        log_info("exe-inject", "created suspended process pid={}", pi.dwProcessId);

        HMODULE remote_module = nullptr;
        if (!remote_load_library(pi.hProcess, temp_dll, &remote_module)) {
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            DeleteFileW(temp_dll.c_str());
            log_fatal("exe-inject", "failed to LoadLibraryW hook into game");
        }
        log_info("exe-inject", "hook loaded at {:#x}",
                reinterpret_cast<uintptr_t>(remote_module));

        if (!remote_call_export(pi.hProcess, remote_module, init_rva)) {
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            // temp DLL stays locked by the game until Terminate finishes
            log_fatal("exe-inject", "failed to run spice_exe_init in game");
        }
        log_info("exe-inject", "spice_exe_init completed, resuming game");

        if (ResumeThread(pi.hThread) == static_cast<DWORD>(-1)) {
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            log_fatal("exe-inject", "ResumeThread failed: {}", GetLastError());
        }

        WaitForSingleObject(pi.hProcess, INFINITE);
        DWORD exit_code = 1;
        GetExitCodeProcess(pi.hProcess, &exit_code);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);

        // Game has unlocked the temp file.
        DeleteFileW(temp_dll.c_str());

        log_info("exe-inject", "game exited with code {}", exit_code);
        return static_cast<int>(exit_code);
    }
}

#endif // !SPICE64
