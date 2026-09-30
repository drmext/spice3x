// GetLocaleInfoEx
#define _WIN32_WINNT 0x0600

#include "lang.h"

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#include <winternl.h>
#include <ntstatus.h>

#include "avs/game.h"
#include "games/iidx/iidx.h"
#include "games/gitadora/gitadora.h"
#include "games/popn/popn.h"
#include "games/sdvx/sdvx.h"
#include "util/deferlog.h"
#include "util/detour.h"
#include "util/logging.h"
#include "util/utils.h"

// ANSI/OEM Japanese; Japanese (Shift-JIS)
constexpr UINT CODEPAGE_SHIFT_JIS = 932;

static decltype(GetACP) *GetACP_orig = nullptr;
static decltype(GetOEMCP) *GetOEMCP_orig = nullptr;
static decltype(MultiByteToWideChar) *MultiByteToWideChar_orig = nullptr;
static decltype(WideCharToMultiByte) *WideCharToMultiByte_orig = nullptr;
static decltype(GetLocaleInfoEx) *GetLocaleInfoEx_orig = nullptr;
static decltype(IsDBCSLeadByte) *IsDBCSLeadByte_orig = nullptr;
static decltype(IsDBCSLeadByteEx) *IsDBCSLeadByteEx_orig = nullptr;
#ifdef SPICE64
static decltype(GetLocaleInfoA) *GetLocaleInfoA_orig = nullptr;
#endif

#ifdef SPICE64
static decltype(GetSystemDefaultLCID) *GetSystemDefaultLCID_orig = nullptr;
static decltype(GetThreadLocale) *GetThreadLocale_orig = nullptr;
#endif

static NTSTATUS NTAPI RtlMultiByteToUnicodeN_hook(
        PWCH UnicodeString,
        ULONG MaxBytesInUnicodeString,
        PULONG BytesInUnicodeString,
        const CHAR *MultiByteString,
        ULONG BytesInMultiByteString)
{
    // try to convert
    auto wc_num = MultiByteToWideChar(
            CODEPAGE_SHIFT_JIS,
            0,
            MultiByteString,
            static_cast<int>(BytesInMultiByteString),
            UnicodeString,
            static_cast<int>(MaxBytesInUnicodeString)
    );

    // error handling
    if (!wc_num) {
        auto error = GetLastError();

        switch (error) {
            case ERROR_INSUFFICIENT_BUFFER:
                return STATUS_BUFFER_TOO_SMALL;

            case ERROR_INVALID_PARAMETER:
            case ERROR_INVALID_FLAGS:
                return STATUS_INVALID_PARAMETER;

            case ERROR_NO_UNICODE_TRANSLATION:
                return STATUS_UNMAPPABLE_CHARACTER;

            default:
                return STATUS_UNSUCCESSFUL;
        }
    }

    // set byte count
    if (BytesInUnicodeString) {
        *BytesInUnicodeString = 2 * static_cast<UINT>(wc_num);
    }

    // return success
    return STATUS_SUCCESS;
}

static UINT WINAPI GetACP_hook() {
    return CODEPAGE_SHIFT_JIS;
}

static UINT WINAPI GetOEMCP_hook() {
    return CODEPAGE_SHIFT_JIS;
}

#ifdef SPICE64

static LCID WINAPI GetSystemDefaultLCID_hook() {
    // ja-JP per https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lcid/a9eac961-e77d-41a6-90a5-ce1a8b0cdb9c
    // this is passed to LCMapStringA for kana conversions (e.g., for subscreen song search)
    return 0x411;
}

static LCID WINAPI GetThreadLocale_hook() {
    return 0x411;
}

#endif

static int WINAPI MultiByteToWideChar_hook(
        UINT CodePage,
        DWORD dwFlags,
        LPCCH lpMultiByteStr,
        int cbMultiByte,
        LPWSTR lpWideCharStr,
        int cchWideChar)
{
    switch (CodePage) {
        case CP_ACP:
        case CP_THREAD_ACP:

            // this fixes pop'n music's mojibake issue with the system locale not set to Japanese
            SetThreadLocale(MAKELANGID(LANG_JAPANESE, SUBLANG_JAPANESE_JAPAN));

            CodePage = CODEPAGE_SHIFT_JIS;

            break;

        default:
            break;
    }

    return MultiByteToWideChar_orig(
            CodePage,
            dwFlags,
            lpMultiByteStr,
            cbMultiByte,
            lpWideCharStr,
            cchWideChar);
}

static int WINAPI GetLocaleInfoEx_hook (
        LPCWSTR lpLocaleName,
        LCTYPE LCType,
        LPWSTR lpLCData,
        int cchData)
{

#if 0
    if (lpLocaleName == LOCALE_NAME_INVARIANT) {
        log_misc("hooks::lang", "GetLocaleInfoEx_hook hit (LOCALE_NAME_INVARIANT), {}, {}", LCType, cchData);
    } else if (lpLocaleName == LOCALE_NAME_SYSTEM_DEFAULT) {
        log_misc("hooks::lang", "GetLocaleInfoEx_hook hit (LOCALE_NAME_SYSTEM_DEFAULT), {}, {}", LCType, cchData);
    } else if (lpLocaleName == LOCALE_NAME_USER_DEFAULT) {
        log_misc("hooks::lang", "GetLocaleInfoEx_hook hit (LOCALE_NAME_USER_DEFAULT), {}, {}", LCType, cchData);
    } else {
        log_misc("hooks::lang", "GetLocaleInfoEx_hook hit ({}), {}, {}", ws2s(lpLocaleName), LCType, cchData);
    }
#endif

    if (lpLocaleName == LOCALE_NAME_USER_DEFAULT &&
        LCType == LOCALE_SISO639LANGNAME &&
        lpLCData != NULL &&
        cchData >= 3) {
        log_misc("hooks::lang",
                 "GetLocaleInfoEx_hook hit (LOCALE_NAME_USER_DEFAULT / LOCALE_SISO639LANGNAME), return `ja`");
        wcscpy(lpLCData, L"ja");
        return 3;
    }

    if (lpLocaleName == LOCALE_NAME_USER_DEFAULT &&
        LCType == LOCALE_SISO3166CTRYNAME &&
        lpLCData != NULL &&
        cchData >= 3) {
        log_misc("hooks::lang",
                 "GetLocaleInfoEx_hook hit (LOCALE_NAME_USER_DEFAULT / LOCALE_SISO3166CTRYNAME), return `JP`");
        wcscpy(lpLCData, L"JP");
        return 3;
    }

    return GetLocaleInfoEx_orig(lpLocaleName, LCType, lpLCData, cchData);
}

static BOOL WINAPI IsDBCSLeadByte_hook (
    BYTE TestChar
    )
{
    if (IsDBCSLeadByteEx_orig) {
        return IsDBCSLeadByteEx_orig(CODEPAGE_SHIFT_JIS, TestChar);
    }

    return IsDBCSLeadByteEx(CODEPAGE_SHIFT_JIS, TestChar);
}

static BOOL WINAPI IsDBCSLeadByteEx_hook(
    UINT CodePage,
    BYTE TestChar)
{
    switch (CodePage) {
        case CP_ACP:
        case CP_THREAD_ACP:
            CodePage = CODEPAGE_SHIFT_JIS;
            break;

        default:
            break;
    }

    return IsDBCSLeadByteEx_orig(CodePage, TestChar);
}

static
int
WINAPI
WideCharToMultiByte_hook(
    UINT CodePage,
    DWORD dwFlags,
    LPCWCH lpWideCharStr,
    int cchWideChar,
    LPSTR lpMultiByteStr,
    int cbMultiByte,
    LPCCH lpDefaultChar,
    LPBOOL lpUsedDefaultChar
    )
{
    switch (CodePage) {
        case CP_ACP:
        case CP_THREAD_ACP:
            SetThreadLocale(MAKELANGID(LANG_JAPANESE, SUBLANG_JAPANESE_JAPAN));
            CodePage = CODEPAGE_SHIFT_JIS;
            break;

        default:
            break;
    }
    return WideCharToMultiByte_orig(
        CodePage,
        dwFlags,
        lpWideCharStr,
        cchWideChar,
        lpMultiByteStr,
        cbMultiByte,
        lpDefaultChar,
        lpUsedDefaultChar);
}

#ifdef SPICE64
static int WINAPI GetLocaleInfoA_hook(
    LCID Locale,
    LCTYPE LCType,
    LPSTR lpLCData,
    int cchData) {

    if (LCType == LOCALE_SISO639LANGNAME && lpLCData != NULL && cchData >= 3) {
        log_misc("hooks::lang", "GetLocaleInfoA_hook hit ({:#x}, LOCALE_SISO639LANGNAME), return `ja`", Locale);
        strcpy(lpLCData, "ja");
        return 3;
    }

    if (LCType == LOCALE_SISO3166CTRYNAME && lpLCData != NULL && cchData >= 3) {
        log_misc("hooks::lang",
                 "GetLocaleInfoA_hook hit ({:#x}, LOCALE_SISO3166CTRYNAME), return `JP`", Locale);
        strcpy(lpLCData, "JP");
        return 3;
    }

    log_misc("hooks::lang", "GetLocaleInfoA_hook hit, {:#x}, {:#x}", Locale, LCType);
    return GetLocaleInfoA_orig(Locale, LCType, lpLCData, cchData);
}
#endif

void hooks::lang::early_init() {
    log_info("hooks::lang", "early initialization");

    const auto native_code_page = GetACP();
    if (native_code_page == CP_UTF8) {
        log_warning(
            "hooks::lang",
            "Windows is using UTF-8 as the system code page; "
            "some games may render text incorrectly or behave unexpectedly");

        deferredlogs::defer_error_messages({
            "Windows is using UTF-8 as the system code page",
            "    some games may render text incorrectly or behave unexpectedly"});
    }

    // hooking these two functions fixes the jubeat mojibake
    detour::trampoline_try("kernel32.dll", "GetACP", GetACP_hook, &GetACP_orig);
    detour::trampoline_try("kernel32.dll", "GetOEMCP", GetOEMCP_hook, &GetOEMCP_orig);

#ifdef SPICE64 // SDVX5+ specific code
    if (games::sdvx::is_valkyrie_model()) {
        log_info("hooks::lang", "hooking GetSystemDefaultLCID");
        detour::trampoline_try(
            "kernel32.dll",
            "GetSystemDefaultLCID",
            GetSystemDefaultLCID_hook,
            &GetSystemDefaultLCID_orig);
    }
#endif

    if (avs::game::is_model("XIF")) {
        log_info("hooks::lang", "hooking GetLocaleInfoEx");
        detour::trampoline_try(
            "kernel32.dll",
            "GetLocaleInfoEx",
            GetLocaleInfoEx_hook,
            &GetLocaleInfoEx_orig);
    }

#ifdef SPICE64

    if (avs::game::is_model("UJK")) {
        // CCJ build of Unity calls GetThreadLocale,
        // and then GetLocaleInfoA to figure out the locale; eventually this is
        // used to figure out the decimal separator, which is then used in parsing
        // Double values - which fails carding in if it isn't "."
        log_info("hooks::lang", "hooking GetThreadLocale");
        detour::trampoline_try(
            "kernel32.dll",
            "GetThreadLocale",
            GetThreadLocale_hook,
            &GetThreadLocale_orig);

        log_info("hooks::lang", "hooking GetLocaleInfoA");
        detour::trampoline_try(
            "kernel32.dll",
            "GetLocaleInfoA",
            GetLocaleInfoA_hook,
            &GetLocaleInfoA_orig);
    }

#endif

    // for TDJ subscreen search keyboard
    // T44 narrow-string handling
    // NDD text measuring
    // IIDX 9-13 Shift-JIS layout (colon overlap on non-Japanese hosts)
    const bool hook_dbcs =
#ifdef SPICE64
            (avs::game::is_model("LDJ") && games::iidx::TDJ_MODE) ||
            avs::game::is_model({ "T44", "NDD" }) ||
#endif
            avs::game::is_model({ "C02", "D01", "E11", "ECO", "FDD" });
    if (hook_dbcs) {
        log_info("hooks::lang", "hooking IsDBCSLeadByte");
        detour::trampoline_try(
            "kernel32.dll",
            "IsDBCSLeadByte",
            IsDBCSLeadByte_hook,
            &IsDBCSLeadByte_orig);
        detour::trampoline_try(
            "kernel32.dll",
            "IsDBCSLeadByteEx",
            IsDBCSLeadByteEx_hook,
            &IsDBCSLeadByteEx_orig);

        // GDI text extent converts via kernel32/kernelbase ACP paths. IAT-only
        // MB2WC is not enough for IIDX 9-13 (often GetProcAddress / delay-load /
        // gdi32 → kernelbase), which causes colon overlap on status lines.
        if (avs::game::is_model({ "C02", "D01", "E11", "ECO", "FDD" })) {
            // Hook kernelbase first (real body on Win10+); then kernel32 (stub or
            // older OS). Prefer the kernelbase trampoline as orig so a hooked
            // kernel32 stub that jmps into kernelbase cannot re-enter our hook.
            decltype(MultiByteToWideChar) *orig_kb = nullptr;
            decltype(MultiByteToWideChar) *orig_k32 = nullptr;
            const bool kb = detour::trampoline_try(
                "kernelbase.dll",
                "MultiByteToWideChar",
                MultiByteToWideChar_hook,
                &orig_kb);
            const bool k32 = detour::trampoline_try(
                "kernel32.dll",
                "MultiByteToWideChar",
                MultiByteToWideChar_hook,
                &orig_k32);
            if (orig_kb) {
                MultiByteToWideChar_orig = orig_kb;
            } else if (orig_k32) {
                MultiByteToWideChar_orig = orig_k32;
            }
            if ((kb || k32) && MultiByteToWideChar_orig) {
                log_info("hooks::lang",
                        "MultiByteToWideChar trampoline installed for legacy IIDX "
                        "(kernelbase={}, kernel32={})",
                        kb, k32);
            } else {
                log_warning("hooks::lang",
                        "MultiByteToWideChar trampoline failed for legacy IIDX "
                        "(colon overlap likely on non-Japanese hosts)");
            }
        }
    }

#ifdef SPICE64
    if (games::popn::is_pikapika_model() && native_code_page == CP_UTF8) {
        // IsDBCSLeadByteEx already hooked above for some models; ensure it is set.
        if (!IsDBCSLeadByteEx_orig) {
            detour::trampoline_try(
                "kernel32.dll",
                "IsDBCSLeadByteEx",
                IsDBCSLeadByteEx_hook,
                &IsDBCSLeadByteEx_orig);
        }
    }
#endif

#ifdef SPICE64
    // NDD renders through GetTextExtentPoint32A, so its wide strings go back through CP_ACP first
    const auto hook_wide_char_to_multi_byte =
        games::gitadora::is_arena_model() || avs::game::is_model({ "T44", "NDD" });
#else
    // XG2 converts UTF-8 property strings through CP_ACP before rendering.
    const auto hook_wide_char_to_multi_byte = avs::game::is_model({ "K32", "K33" });
#endif

    if (hook_wide_char_to_multi_byte && !WideCharToMultiByte_orig) {
        log_info("hooks::lang", "hooking WideCharToMultiByte");
        detour::trampoline_try(
            "kernel32.dll",
            "WideCharToMultiByte",
            WideCharToMultiByte_hook,
            &WideCharToMultiByte_orig);
    }

}

void hooks::lang::init() {
    log_info("hooks::lang", "initializing");

    detour::iat_try("RtlMultiByteToUnicodeN", RtlMultiByteToUnicodeN_hook, nullptr, "ntdll.dll");

    // Preserve MinHook trampoline orig if early_init already installed it.
    auto *prev = detour::iat_try(
            "MultiByteToWideChar",
            MultiByteToWideChar_hook,
            nullptr,
            "kernel32.dll");
    if (!MultiByteToWideChar_orig && prev) {
        MultiByteToWideChar_orig = prev;
    }

    // Fallback trampoline if early_init did not cover this model.
    if (!MultiByteToWideChar_orig) {
        decltype(MultiByteToWideChar) *orig_kb = nullptr;
        decltype(MultiByteToWideChar) *orig_k32 = nullptr;
        detour::trampoline_try(
                "kernelbase.dll",
                "MultiByteToWideChar",
                MultiByteToWideChar_hook,
                &orig_kb);
        detour::trampoline_try(
                "kernel32.dll",
                "MultiByteToWideChar",
                MultiByteToWideChar_hook,
                &orig_k32);
        MultiByteToWideChar_orig = orig_kb ? orig_kb : orig_k32;
    }
}

void hooks::lang::init_module(HMODULE module) {
    if (!module) {
        return;
    }

    auto *prev = detour::iat_try(
            "MultiByteToWideChar",
            MultiByteToWideChar_hook,
            module,
            "kernel32.dll");
    if (!MultiByteToWideChar_orig && prev) {
        MultiByteToWideChar_orig = prev;
    }
    if (!prev) {
        // Common for delay-loaded / GDI-only modules (e.g. d3d8to9). Harmless
        // when the process-wide trampoline or game EXE IAT is already hooked —
        // only note it for the game image itself.
        if (module == avs::game::DLL_INSTANCE) {
            log_misc("hooks::lang",
                    "MultiByteToWideChar not in game module IAT ({:#x}); "
                    "relying on trampoline",
                    reinterpret_cast<uintptr_t>(module));
        }
    } else {
        log_misc("hooks::lang", "MultiByteToWideChar IAT hooked in module {:#x}",
                reinterpret_cast<uintptr_t>(module));
    }
}

bool hooks::lang::is_native_shiftjis() {
    return GetACP() == CODEPAGE_SHIFT_JIS;
}
