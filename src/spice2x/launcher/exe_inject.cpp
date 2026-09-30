#include "exe_inject.h"

#include <cstring>
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

    void terminate_injected_child() {}
}

#else

#include "build/resource.h"
#include "launcher/launcher.h"
#include "util/fileutils.h"
#include "util/logging.h"
#include "util/resutils.h"
#include "util/utils.h"

namespace launcher {

    // Kept open for terminate_injected_child / job kill-on-close while waiting.
    static HANDLE g_injected_child = nullptr;
    static HANDLE g_injected_job = nullptr;

    void terminate_injected_child() {
        if (g_injected_child != nullptr && g_injected_child != INVALID_HANDLE_VALUE) {
            TerminateProcess(g_injected_child, 1);
        }
    }

    static void clear_injected_handles() {
        // Drop the child pointer before the process handle is closed so a
        // concurrent CTRL+C cannot TerminateProcess a closed handle.
        g_injected_child = nullptr;
        if (g_injected_job != nullptr) {
            CloseHandle(g_injected_job);
            g_injected_job = nullptr;
        }
    }

    static bool assign_kill_on_close_job(HANDLE process) {
        HANDLE job = CreateJobObjectW(nullptr, nullptr);
        if (!job) {
            log_warning("exe-inject", "CreateJobObject failed: {}", GetLastError());
            return false;
        }

        JOBOBJECT_EXTENDED_LIMIT_INFORMATION info {};
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &info, sizeof(info))) {
            log_warning("exe-inject", "SetInformationJobObject failed: {}", GetLastError());
            CloseHandle(job);
            return false;
        }

        if (!AssignProcessToJobObject(job, process)) {
            log_warning("exe-inject", "AssignProcessToJobObject failed: {}", GetLastError());
            CloseHandle(job);
            return false;
        }

        g_injected_job = job;
        return true;
    }

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

        // 5-field: model:dest:spec:rev:ext (14-17 date folder)
        // 4-field: model:dest:spec:rev (9-13 JA* folder; ext = folder with bm2dx.exe)
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
        if (fields.size() != 4 && fields.size() != 5) {
            log_warning("exe-inject", "sidcode.txt has {} fields, expected 4 or 5: {}",
                    fields.size(), text);
            return std::nullopt;
        }

        ExeGameTarget target;
        target.model = fields[0];
        target.dest = fields[1];
        target.spec = fields[2];
        target.rev = fields[3];
        target.sidcode_dir = sidcode_path.parent_path();

        if (fields.size() == 5) {
            target.ext = fields[4];
            target.work_dir = target.sidcode_dir / target.ext;
            target.exe_path = target.work_dir / "bm2dx.exe";
            return target;
        }

        // 9-13: find the unique child folder that contains bm2dx.exe
        std::error_code ec;
        std::optional<std::filesystem::path> found;
        for (const auto &entry : std::filesystem::directory_iterator(target.sidcode_dir, ec)) {
            if (ec || !entry.is_directory()) {
                continue;
            }
            auto exe = entry.path() / "bm2dx.exe";
            if (fileutils::file_exists(exe)) {
                if (found) {
                    log_warning("exe-inject",
                            "multiple bm2dx.exe under {}; pick one folder",
                            target.sidcode_dir.string());
                    return std::nullopt;
                }
                found = entry.path();
            }
        }
        if (!found) {
            log_warning("exe-inject", "no bm2dx.exe under {}", target.sidcode_dir.string());
            return std::nullopt;
        }
        target.work_dir = *found;
        target.ext = found->filename().string();
        target.exe_path = target.work_dir / "bm2dx.exe";
        return target;
    }

    static const char *inject_style_name(const std::string &model) {
        if (_stricmp(model.c_str(), "C02") == 0) {
            return "IIDX 9th Style";
        }
        if (_stricmp(model.c_str(), "D01") == 0) {
            return "IIDX 10th Style";
        }
        if (_stricmp(model.c_str(), "E11") == 0) {
            return "IIDX 11 RED";
        }
        if (_stricmp(model.c_str(), "ECO") == 0) {
            return "IIDX 12 Happy Sky";
        }
        if (_stricmp(model.c_str(), "FDD") == 0) {
            return "IIDX 13 DistorteD";
        }
        if (_stricmp(model.c_str(), "GLD") == 0) {
            return "IIDX 14 GOLD";
        }
        if (_stricmp(model.c_str(), "HDD") == 0) {
            return "IIDX 15 DJ TROOPERS";
        }
        if (_stricmp(model.c_str(), "I00") == 0) {
            return "IIDX 16 EMPRESS";
        }
        if (_stricmp(model.c_str(), "JDJ") == 0) {
            return "IIDX 17 Sirius";
        }
        return nullptr;
    }

    static bool is_inject_model(const std::string &model) {
        return inject_style_name(model) != nullptr;
    }

    std::optional<ExeGameTarget> try_detect_jdj() {
        // Prefer sidcode next to spice.exe; also try parent when spice lives
        // inside the date/JA* folder (e.g. JDJ\2010071200\spice.exe).
        std::vector<std::filesystem::path> candidates;
        std::error_code cwd_error;
        auto cwd = std::filesystem::current_path(cwd_error);
        if (!cwd_error) {
            candidates.push_back(cwd / "sidcode.txt");
            candidates.push_back(cwd.parent_path() / "sidcode.txt");
        }
        candidates.push_back(MODULE_PATH / "sidcode.txt");
        candidates.push_back(MODULE_PATH.parent_path() / "sidcode.txt");

        for (const auto &path : candidates) {
            auto target = parse_sidcode_file(path);
            if (!target) {
                continue;
            }
            if (!is_inject_model(target->model)) {
                log_misc("exe-inject", "sidcode model {} is not IIDX 9-17, ignoring",
                        target->model);
                continue;
            }
            if (!fileutils::file_exists(target->exe_path)) {
                log_warning("exe-inject",
                        "{} sidcode points at missing exe: {}",
                        inject_style_name(target->model),
                        target->exe_path.string());
                continue;
            }
            log_info("exe-inject", "detected {} ({}) at {}",
                    inject_style_name(target->model),
                    target->model,
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

    // avs.dll (IIDX 10-13) creates e:\avs00000.bin / f:\avs00000.bin from DllMain,
    // which runs inside the loader before spice_exe_init. Patch ntdll!NtCreateFile
    // while the process is still suspended so that open is redirected.
    static bool install_early_drive_hook(HANDLE process, const std::filesystem::path &work_dir) {
        std::error_code ec;
        std::filesystem::create_directories(work_dir / "d", ec);
        std::filesystem::create_directories(work_dir / "e", ec);
        std::filesystem::create_directories(work_dir / "f", ec);

        HMODULE local_ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!local_ntdll) {
            log_warning("exe-inject", "ntdll not loaded; drive redirect not installed");
            return false;
        }
        auto *nt = reinterpret_cast<uint8_t *>(GetProcAddress(local_ntdll, "NtCreateFile"));
        if (!nt) {
            log_warning("exe-inject", "NtCreateFile not found; drive redirect not installed");
            return false;
        }

        uint8_t stub[16] {};
        SIZE_T read = 0;
        if (!ReadProcessMemory(process, nt, stub, sizeof(stub), &read) || read != sizeof(stub)) {
            log_warning("exe-inject", "failed to read remote NtCreateFile");
            return false;
        }
        // mov eax, imm32; mov edx, imm32; call edx; ret 0x2C
        if (stub[0] != 0xB8 || stub[5] != 0xBA || stub[10] != 0xFF || stub[11] != 0xD2
                || stub[12] != 0xC2 || stub[13] != 0x2C || stub[14] != 0x00) {
            log_warning("exe-inject", "unexpected NtCreateFile stub; drive redirect not installed");
            return false;
        }
        const uint32_t syscall_num = *reinterpret_cast<uint32_t *>(stub + 1);
        const uint32_t wow64_gate = *reinterpret_cast<uint32_t *>(stub + 6);

        std::wstring prefix = L"\\??\\";
        prefix += std::filesystem::absolute(work_dir).wstring();
        for (wchar_t &ch : prefix) {
            if (ch == L'/') {
                ch = L'\\';
            }
        }
        if (prefix.empty() || prefix.back() != L'\\') {
            prefix.push_back(L'\\');
        }
        if (prefix.size() + 8 >= 512) {
            log_warning("exe-inject", "game path too long for drive redirect");
            return false;
        }

        constexpr uint32_t kCaveSize = 0x2000;
        constexpr uint32_t kNewPath = 0x800;
        constexpr uint32_t kPrefix = 0x1000;
        constexpr uint32_t kLock = 0x1400;
        constexpr uint32_t kHeld = 0x1401;
        constexpr uint32_t kSavedUstr = 0x1404;
        constexpr uint32_t kSavedLen = 0x1408;
        constexpr uint32_t kSavedMax = 0x140A;
        constexpr uint32_t kSavedBuf = 0x140C;

        void *cave = VirtualAllocEx(process, nullptr, kCaveSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!cave) {
            log_warning("exe-inject", "VirtualAllocEx for drive hook failed: {}", GetLastError());
            return false;
        }
        const auto cave_addr = reinterpret_cast<uintptr_t>(cave);
        const uint32_t newpath = static_cast<uint32_t>(cave_addr + kNewPath);
        const uint32_t prefix_addr = static_cast<uint32_t>(cave_addr + kPrefix);
        const uint32_t lock_addr = static_cast<uint32_t>(cave_addr + kLock);
        const uint32_t held_addr = static_cast<uint32_t>(cave_addr + kHeld);
        const uint32_t saved_ustr = static_cast<uint32_t>(cave_addr + kSavedUstr);
        const uint32_t saved_len = static_cast<uint32_t>(cave_addr + kSavedLen);
        const uint32_t saved_max = static_cast<uint32_t>(cave_addr + kSavedMax);
        const uint32_t saved_buf = static_cast<uint32_t>(cave_addr + kSavedBuf);
        const uint32_t prefix_wchars = static_cast<uint32_t>(prefix.size());
        const uint32_t rest_limit = 1024 - prefix_wchars - 2;

        std::vector<uint8_t> code;
        code.reserve(256);
        auto u8 = [&](uint8_t v) { code.push_back(v); };
        auto u16 = [&](uint16_t v) {
            code.push_back(static_cast<uint8_t>(v));
            code.push_back(static_cast<uint8_t>(v >> 8));
        };
        auto u32 = [&](uint32_t v) {
            code.push_back(static_cast<uint8_t>(v));
            code.push_back(static_cast<uint8_t>(v >> 8));
            code.push_back(static_cast<uint8_t>(v >> 16));
            code.push_back(static_cast<uint8_t>(v >> 24));
        };
        std::vector<std::pair<size_t, const char *>> fixups;
        // Near conditional/unconditional jumps so the pass path can sit past 127 bytes.
        auto j32 = [&](uint8_t short_op, const char *label) {
            if (short_op == 0xEB) {
                u8(0xE9);
            } else {
                u8(0x0F);
                u8(static_cast<uint8_t>(short_op + 0x10));
            }
            u32(0);
            fixups.emplace_back(code.size() - 4, label);
        };
        std::vector<std::pair<const char *, size_t>> labels;
        auto lab = [&](const char *name) { labels.emplace_back(name, code.size()); };

        // pushad. ObjectAttributes is at [esp+44].
        u8(0x60);
        u8(0x8B); u8(0x44); u8(0x24); u8(44);
        u8(0x85); u8(0xC0);
        j32(0x74, "pass");
        u8(0x83); u8(0x78); u8(0x04); u8(0x00);
        j32(0x75, "pass");
        u8(0x8B); u8(0x70); u8(0x08);
        u8(0x85); u8(0xF6);
        j32(0x74, "pass");
        u8(0x0F); u8(0xB7); u8(0x0E);
        u8(0x83); u8(0xF9); u8(14);
        j32(0x72, "pass");
        u8(0x8B); u8(0x56); u8(0x04);
        u8(0x85); u8(0xD2);
        j32(0x74, "pass");
        u8(0x81); u8(0x3A); u32(0x005C005C);
        j32(0x75, "pass");
        u8(0x81); u8(0x7A); u8(0x04); u32(0x003F003F);
        j32(0x75, "pass");
        u8(0x66); u8(0x81); u8(0x7A); u8(0x08); u16(0x005C);
        j32(0x75, "pass");
        u8(0x0F); u8(0xB7); u8(0x5A); u8(10);
        u8(0x66); u8(0x83); u8(0xFB); u8(static_cast<uint8_t>('A'));
        j32(0x72, "lower_done");
        u8(0x66); u8(0x83); u8(0xFB); u8(static_cast<uint8_t>('Z'));
        j32(0x77, "lower_done");
        u8(0x66); u8(0x83); u8(0xC3); u8(32);
        lab("lower_done");
        u8(0x66); u8(0x83); u8(0xFB); u8(static_cast<uint8_t>('d'));
        j32(0x72, "pass");
        u8(0x66); u8(0x83); u8(0xFB); u8(static_cast<uint8_t>('f'));
        j32(0x77, "pass");
        u8(0x66); u8(0x81); u8(0x7A); u8(12); u16(static_cast<uint16_t>(':'));
        j32(0x75, "pass");
        // ebp = UNICODE_STRING (saved across the copy)
        u8(0x89); u8(0xF5);
        u8(0xBF); u32(lock_addr);
        lab("spin");
        u8(0x31); u8(0xC0);
        u8(0x40);
        u8(0x86); u8(0x07);
        u8(0x84); u8(0xC0);
        j32(0x75, "spin");
        u8(0x0F); u8(0xB7); u8(0x4D); u8(0x00);
        u8(0x83); u8(0xE9); u8(14);
        u8(0xD1); u8(0xE9);
        u8(0x81); u8(0xF9); u32(rest_limit);
        j32(0x73, "unlock_pass");
        // ecx is the remaining wchar count; keep it across the prefix copy.
        u8(0x51);
        // save caller's UNICODE_STRING fields
        u8(0x66); u8(0x8B); u8(0x45); u8(0x00);
        u8(0x66); u8(0xA3); u32(saved_len);
        u8(0x66); u8(0x8B); u8(0x45); u8(0x02);
        u8(0x66); u8(0xA3); u32(saved_max);
        u8(0x8B); u8(0x45); u8(0x04);
        u8(0xA3); u32(saved_buf);
        u8(0x89); u8(0x2D); u32(saved_ustr);
        u8(0xFC);
        u8(0xBF); u32(newpath);
        u8(0xBE); u32(prefix_addr);
        u8(0xB9); u32(prefix_wchars);
        u8(0xF3); u8(0x66); u8(0xA5);
        u8(0x66); u8(0x89); u8(0xD8);
        u8(0x66); u8(0xAB);
        u8(0x59);
        u8(0x8B); u8(0x75); u8(0x04);
        u8(0x83); u8(0xC6); u8(14);
        u8(0xF3); u8(0x66); u8(0xA5);
        u8(0x31); u8(0xC0);
        u8(0x66); u8(0xAB);
        u8(0x89); u8(0xF8);
        u8(0x2D); u32(newpath + 2);
        u8(0x66); u8(0x89); u8(0x45); u8(0x00);
        u8(0x83); u8(0xC0); u8(2);
        u8(0x66); u8(0x89); u8(0x45); u8(0x02);
        u8(0xC7); u8(0x45); u8(0x04); u32(newpath);
        u8(0xC6); u8(0x05); u32(held_addr); u8(1);
        j32(0xEB, "go");
        lab("unlock_pass");
        u8(0xC6); u8(0x05); u32(lock_addr); u8(0);
        lab("pass");
        u8(0xC6); u8(0x05); u32(held_addr); u8(0);
        lab("go");
        u8(0x61);
        u8(0xB8); u32(syscall_num);
        u8(0xBA); u32(wow64_gate);
        u8(0xFF); u8(0xD2);
        u8(0x50);
        u8(0x80); u8(0x3D); u32(held_addr); u8(0);
        j32(0x74, "norestore");
        u8(0x8B); u8(0x0D); u32(saved_ustr);
        u8(0x66); u8(0xA1); u32(saved_len);
        u8(0x66); u8(0x89); u8(0x01);
        u8(0x66); u8(0xA1); u32(saved_max);
        u8(0x66); u8(0x89); u8(0x41); u8(0x02);
        u8(0xA1); u32(saved_buf);
        u8(0x89); u8(0x41); u8(0x04);
        u8(0xC6); u8(0x05); u32(lock_addr); u8(0);
        u8(0xC6); u8(0x05); u32(held_addr); u8(0);
        lab("norestore");
        u8(0x58);
        u8(0xC2); u8(0x2C); u8(0x00);

        for (const auto &fix : fixups) {
            size_t target = static_cast<size_t>(-1);
            for (const auto &label : labels) {
                if (strcmp(label.first, fix.second) == 0) {
                    target = label.second;
                    break;
                }
            }
            if (target == static_cast<size_t>(-1)) {
                log_warning("exe-inject", "drive hook missing label {}", fix.second);
                VirtualFreeEx(process, cave, 0, MEM_RELEASE);
                return false;
            }
            const int32_t rel = static_cast<int32_t>(target) - static_cast<int32_t>(fix.first + 4);
            memcpy(code.data() + fix.first, &rel, sizeof(rel));
        }

        std::vector<uint8_t> image(kCaveSize, 0);
        if (code.size() >= kNewPath) {
            log_warning("exe-inject", "drive hook code overflow");
            VirtualFreeEx(process, cave, 0, MEM_RELEASE);
            return false;
        }
        memcpy(image.data(), code.data(), code.size());
        memcpy(image.data() + kPrefix, prefix.data(), prefix.size() * sizeof(wchar_t));

        SIZE_T written = 0;
        if (!WriteProcessMemory(process, cave, image.data(), image.size(), &written) || written != image.size()) {
            log_warning("exe-inject", "failed to write drive hook");
            VirtualFreeEx(process, cave, 0, MEM_RELEASE);
            return false;
        }

        DWORD old_protect = 0;
        if (!VirtualProtectEx(process, nt, 5, PAGE_EXECUTE_READWRITE, &old_protect)) {
            log_warning("exe-inject", "VirtualProtectEx NtCreateFile failed: {}", GetLastError());
            VirtualFreeEx(process, cave, 0, MEM_RELEASE);
            return false;
        }
        uint8_t jmp[5] = {0xE9, 0, 0, 0, 0};
        const auto nt_addr = reinterpret_cast<uintptr_t>(nt);
        const int32_t rel = static_cast<int32_t>(cave_addr - (nt_addr + 5));
        memcpy(jmp + 1, &rel, sizeof(rel));
        if (!WriteProcessMemory(process, nt, jmp, sizeof(jmp), &written) || written != sizeof(jmp)) {
            log_warning("exe-inject", "failed to patch NtCreateFile");
            VirtualProtectEx(process, nt, 5, old_protect, &old_protect);
            VirtualFreeEx(process, cave, 0, MEM_RELEASE);
            return false;
        }
        VirtualProtectEx(process, nt, 5, old_protect, &old_protect);
        FlushInstructionCache(process, nt, 5);
        log_info("exe-inject", "NtCreateFile drive redirect installed for {}", work_dir.string());
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

        g_injected_child = pi.hProcess;
        if (!assign_kill_on_close_job(pi.hProcess)) {
            log_warning("exe-inject",
                    "job kill-on-close unavailable; CTRL+C will use TerminateProcess fallback");
        }

        log_info("exe-inject", "created suspended process pid={}", pi.dwProcessId);

        // Before LoadLibrary: the loader runs avs.dll DllMain, which creates
        // e:\avs00000.bin / f:\avs00000.bin. Redirect that open first.
        install_early_drive_hook(pi.hProcess, target.work_dir);

        HMODULE remote_module = nullptr;
        if (!remote_load_library(pi.hProcess, temp_dll, &remote_module)) {
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hThread);
            clear_injected_handles();
            CloseHandle(pi.hProcess);
            DeleteFileW(temp_dll.c_str());
            log_fatal("exe-inject", "failed to LoadLibraryW hook into game");
        }
        log_info("exe-inject", "hook loaded at {:#x}",
                reinterpret_cast<uintptr_t>(remote_module));

        if (!remote_call_export(pi.hProcess, remote_module, init_rva)) {
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hThread);
            clear_injected_handles();
            CloseHandle(pi.hProcess);
            // temp DLL stays locked by the game until Terminate finishes
            log_fatal("exe-inject", "failed to run spice_exe_init in game");
        }
        log_info("exe-inject", "spice_exe_init completed, resuming game");

        if (ResumeThread(pi.hThread) == static_cast<DWORD>(-1)) {
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hThread);
            clear_injected_handles();
            CloseHandle(pi.hProcess);
            log_fatal("exe-inject", "ResumeThread failed: {}", GetLastError());
        }

        WaitForSingleObject(pi.hProcess, INFINITE);
        DWORD exit_code = 1;
        GetExitCodeProcess(pi.hProcess, &exit_code);
        CloseHandle(pi.hThread);
        clear_injected_handles();
        CloseHandle(pi.hProcess);

        // Game has unlocked the temp file.
        DeleteFileW(temp_dll.c_str());

        log_info("exe-inject", "game exited with code {}", exit_code);
        return static_cast<int>(exit_code);
    }
}

#endif // !SPICE64
