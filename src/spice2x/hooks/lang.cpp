// GetLocaleInfoEx
#define _WIN32_WINNT 0x0600

#include "lang.h"

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#include <intrin.h>
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
static decltype(GetCPInfo) *GetCPInfo_orig = nullptr;
static decltype(MultiByteToWideChar) *MultiByteToWideChar_orig = nullptr;
static decltype(WideCharToMultiByte) *WideCharToMultiByte_orig = nullptr;
static decltype(GetLocaleInfoEx) *GetLocaleInfoEx_orig = nullptr;
static decltype(IsDBCSLeadByte) *IsDBCSLeadByte_orig = nullptr;
static decltype(IsDBCSLeadByteEx) *IsDBCSLeadByteEx_orig = nullptr;
static decltype(CreateFontA) *CreateFontA_orig = nullptr;
static decltype(CreateFontIndirectA) *CreateFontIndirectA_orig = nullptr;
#ifdef SPICE64
static decltype(GetLocaleInfoA) *GetLocaleInfoA_orig = nullptr;
#endif

#ifdef SPICE64
static decltype(GetSystemDefaultLCID) *GetSystemDefaultLCID_orig = nullptr;
static decltype(GetThreadLocale) *GetThreadLocale_orig = nullptr;
#endif

// MinHook needs an orig slot even when the hook does not call through.
static void *RtlMultiByteToUnicodeN_orig = nullptr;

// eam3lib XML (C02) must keep the host ACP; GDI/bm2dx need Shift-JIS.
// ret_addr must be the hook's _ReturnAddress() (the external caller).
static bool module_is_eam3(const void *ret_addr) {
    if (!ret_addr) {
        return false;
    }
    HMODULE caller = nullptr;
    if (!GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
                    | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCSTR>(ret_addr),
            &caller)
            || !caller) {
        return false;
    }
    static HMODULE eam3 = nullptr;
    static HMODULE eam3mod = nullptr;
    if (!eam3) {
        eam3 = GetModuleHandleA("eam3lib.dll");
    }
    if (!eam3mod) {
        eam3mod = GetModuleHandleA("eam3mod.dll");
    }
    return caller == eam3 || caller == eam3mod;
}

static NTSTATUS NTAPI RtlMultiByteToUnicodeN_hook(
        PWCH UnicodeString,
        ULONG MaxBytesInUnicodeString,
        PULONG BytesInUnicodeString,
        const CHAR *MultiByteString,
        ULONG BytesInMultiByteString)
{
    if (module_is_eam3(_ReturnAddress()) && RtlMultiByteToUnicodeN_orig) {
        using fn_t = NTSTATUS (NTAPI *)(PWCH, ULONG, PULONG, const CHAR *, ULONG);
        return reinterpret_cast<fn_t>(RtlMultiByteToUnicodeN_orig)(
                UnicodeString,
                MaxBytesInUnicodeString,
                BytesInUnicodeString,
                MultiByteString,
                BytesInMultiByteString);
    }

    // MaxBytesInUnicodeString is bytes; MultiByteToWideChar wants wchar count.
    const int cch_wide = static_cast<int>(MaxBytesInUnicodeString / sizeof(WCHAR));

    // try to convert
    auto wc_num = MultiByteToWideChar(
            CODEPAGE_SHIFT_JIS,
            0,
            MultiByteString,
            static_cast<int>(BytesInMultiByteString),
            UnicodeString,
            cch_wide
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
    if (module_is_eam3(_ReturnAddress()) && GetACP_orig) {
        return GetACP_orig();
    }
    return CODEPAGE_SHIFT_JIS;
}

static UINT WINAPI GetOEMCP_hook() {
    if (module_is_eam3(_ReturnAddress()) && GetOEMCP_orig) {
        return GetOEMCP_orig();
    }
    return CODEPAGE_SHIFT_JIS;
}

// GetACP alone is not enough: GDI / bm2dx call GetCPInfo(CP_ACP) for MaxCharSize
// and LeadByte ranges. On a Western host that still returns SBCS info while GetACP
// says 932 → fullwidth colon (SJIS 8146) drawn as two overlapping glyphs.
static BOOL WINAPI GetCPInfo_hook(UINT CodePage, LPCPINFO lpCPInfo) {
    if (module_is_eam3(_ReturnAddress()) && GetCPInfo_orig) {
        return GetCPInfo_orig(CodePage, lpCPInfo);
    }
    switch (CodePage) {
        case CP_ACP:
        case CP_OEMCP:
        case CP_THREAD_ACP:
            CodePage = CODEPAGE_SHIFT_JIS;
            break;
        default:
            break;
    }
    return GetCPInfo_orig(CodePage, lpCPInfo);
}

static HFONT WINAPI CreateFontA_hook(
        int cHeight, int cWidth, int cEscapement, int cOrientation, int cWeight,
        DWORD bItalic, DWORD bUnderline, DWORD bStrikeOut, DWORD iCharSet,
        DWORD iOutPrecision, DWORD iClipPrecision, DWORD iQuality,
        DWORD iPitchAndFamily, LPCSTR pszFaceName)
{
    if (iCharSet == DEFAULT_CHARSET || iCharSet == ANSI_CHARSET) {
        iCharSet = SHIFTJIS_CHARSET;
    }
    return CreateFontA_orig(
            cHeight, cWidth, cEscapement, cOrientation, cWeight,
            bItalic, bUnderline, bStrikeOut, iCharSet,
            iOutPrecision, iClipPrecision, iQuality,
            iPitchAndFamily, pszFaceName);
}

static HFONT WINAPI CreateFontIndirectA_hook(const LOGFONTA *lplf) {
    LOGFONTA lf = *lplf;
    if (lf.lfCharSet == DEFAULT_CHARSET || lf.lfCharSet == ANSI_CHARSET) {
        lf.lfCharSet = SHIFTJIS_CHARSET;
    }
    return CreateFontIndirectA_orig(&lf);
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
            // Force Shift-JIS for legacy Japanese titles on non-JP hosts.
            // Do not SetThreadLocale here: a process-wide trampoline would
            // also hit eam3lib XML parsing and crash in wtof_l (seen on C02
            // after NETWORK OK with read at 0x1).
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
    if (module_is_eam3(_ReturnAddress())) {
        if (IsDBCSLeadByte_orig) {
            return IsDBCSLeadByte_orig(TestChar);
        }
        if (IsDBCSLeadByteEx_orig) {
            return IsDBCSLeadByteEx_orig(CP_ACP, TestChar);
        }
    }
    if (IsDBCSLeadByteEx_orig) {
        return IsDBCSLeadByteEx_orig(CODEPAGE_SHIFT_JIS, TestChar);
    }

    return IsDBCSLeadByteEx(CODEPAGE_SHIFT_JIS, TestChar);
}

static BOOL WINAPI IsDBCSLeadByteEx_hook(
    UINT CodePage,
    BYTE TestChar)
{
    if (module_is_eam3(_ReturnAddress())) {
        return IsDBCSLeadByteEx_orig(CodePage, TestChar);
    }
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

    // Prefer kernelbase: gdi32full imports GetACP/GetOEMCP/GetCPInfo via api-ms-*
    // which resolve to kernelbase, not the kernel32 jmp stubs. Hooking only
    // kernel32 leaves GDI on the host ACP (colon overlap on IIDX 9-13 status).
    {
        decltype(GetACP) *orig = nullptr;
        if (detour::trampoline_try("kernelbase.dll", "GetACP", GetACP_hook, &orig) && orig) {
            GetACP_orig = orig;
        } else {
            orig = nullptr;
            detour::trampoline_try("kernel32.dll", "GetACP", GetACP_hook, &GetACP_orig);
        }
        orig = nullptr;
        if (detour::trampoline_try("kernelbase.dll", "GetOEMCP", GetOEMCP_hook, &orig) && orig) {
            GetOEMCP_orig = orig;
        } else {
            orig = nullptr;
            detour::trampoline_try("kernel32.dll", "GetOEMCP", GetOEMCP_hook, &GetOEMCP_orig);
        }
        decltype(GetCPInfo) *cp_orig = nullptr;
        if (detour::trampoline_try("kernelbase.dll", "GetCPInfo", GetCPInfo_hook, &cp_orig)
                && cp_orig) {
            GetCPInfo_orig = cp_orig;
            log_info("hooks::lang", "GetCPInfo trampoline installed (kernelbase.dll)");
        } else {
            cp_orig = nullptr;
            if (detour::trampoline_try("kernel32.dll", "GetCPInfo", GetCPInfo_hook, &cp_orig)
                    && cp_orig) {
                GetCPInfo_orig = cp_orig;
                log_info("hooks::lang", "GetCPInfo trampoline installed (kernel32.dll)");
            }
        }
    }

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
        // One export only (kernelbase preferred): kernel32 stubs jmp into
        // kernelbase; dual hooks re-enter and AV. gdi32full calls these via
        // api-ms → kernelbase, so kernel32-only hooks miss GDI text layout.
        log_info("hooks::lang", "hooking IsDBCSLeadByte");
        {
            decltype(IsDBCSLeadByteEx) *orig_ex = nullptr;
            if (detour::trampoline_try(
                        "kernelbase.dll",
                        "IsDBCSLeadByteEx",
                        IsDBCSLeadByteEx_hook,
                        &orig_ex)
                    && orig_ex) {
                IsDBCSLeadByteEx_orig = orig_ex;
            } else {
                orig_ex = nullptr;
                detour::trampoline_try(
                        "kernel32.dll",
                        "IsDBCSLeadByteEx",
                        IsDBCSLeadByteEx_hook,
                        &IsDBCSLeadByteEx_orig);
            }

            decltype(IsDBCSLeadByte) *orig = nullptr;
            if (detour::trampoline_try(
                        "kernelbase.dll",
                        "IsDBCSLeadByte",
                        IsDBCSLeadByte_hook,
                        &orig)
                    && orig) {
                IsDBCSLeadByte_orig = orig;
            } else {
                orig = nullptr;
                detour::trampoline_try(
                        "kernel32.dll",
                        "IsDBCSLeadByte",
                        IsDBCSLeadByte_hook,
                        &IsDBCSLeadByte_orig);
            }
        }

        // GDI text extent: GetACP/GetCPInfo/IsDBCS + RtlMultiByteToUnicodeN cover
        // layout. Do NOT trampoline MultiByteToWideChar process-wide on legacy
        // IIDX — eam3lib XML parsing (xrpc_data_get) AVs on C02 when CP_ACP is
        // forced to 932 for every caller. Game EXE IAT is still hooked in init().
        if (avs::game::is_model({ "C02", "D01", "E11", "ECO", "FDD" })) {
            // bemanitools ACP hook: gdi32full imports RtlMultiByteToUnicodeN from
            // ntdll for ANSI text. IAT walk can miss late loads; trampoline catches all.
            if (detour::trampoline_try(
                        "ntdll.dll",
                        "RtlMultiByteToUnicodeN",
                        reinterpret_cast<void *>(RtlMultiByteToUnicodeN_hook),
                        &RtlMultiByteToUnicodeN_orig)) {
                log_info("hooks::lang",
                        "RtlMultiByteToUnicodeN trampoline installed for legacy IIDX");
            }

            // Force SHIFTJIS_CHARSET so ExtTextOutA picks a CJK face on Western hosts.
            if (detour::trampoline_try(
                        "gdi32.dll",
                        "CreateFontA",
                        CreateFontA_hook,
                        &CreateFontA_orig)
                    && CreateFontA_orig) {
                log_info("hooks::lang", "CreateFontA trampoline installed for legacy IIDX");
            }
            if (detour::trampoline_try(
                        "gdi32.dll",
                        "CreateFontIndirectA",
                        CreateFontIndirectA_hook,
                        &CreateFontIndirectA_orig)
                    && CreateFontIndirectA_orig) {
                log_info("hooks::lang",
                        "CreateFontIndirectA trampoline installed for legacy IIDX");
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

    // Keep IAT coverage for modules that imported before the ntdll trampoline.
    detour::iat_try("RtlMultiByteToUnicodeN", RtlMultiByteToUnicodeN_hook, nullptr, "ntdll.dll");
    if (!RtlMultiByteToUnicodeN_orig) {
        detour::trampoline_try(
                "ntdll.dll",
                "RtlMultiByteToUnicodeN",
                reinterpret_cast<void *>(RtlMultiByteToUnicodeN_hook),
                &RtlMultiByteToUnicodeN_orig);
    }

    // Preserve MinHook trampoline orig if early_init already installed it.
    //
    // For IIDX 9-13 (C02–FDD): only IAT-hook the game image. PEB-wide IAT and
    // kernelbase trampolines also patch eam3lib, which then AVs in xml_parse
    // after services connect (seen on C02). Font layout uses GetACP/GetCPInfo/
    // IsDBCS + RtlMultiByteToUnicodeN instead.
    const bool legacy_iidx_mb2wc =
            avs::game::is_model({ "C02", "D01", "E11", "ECO", "FDD" });

    if (legacy_iidx_mb2wc) {
        if (avs::game::DLL_INSTANCE) {
            auto *prev = detour::iat_try(
                    "MultiByteToWideChar",
                    MultiByteToWideChar_hook,
                    avs::game::DLL_INSTANCE,
                    "kernel32.dll");
            if (!MultiByteToWideChar_orig && prev) {
                MultiByteToWideChar_orig = prev;
            }
        }
    } else {
        auto *prev = detour::iat_try(
                "MultiByteToWideChar",
                MultiByteToWideChar_hook,
                nullptr,
                "kernel32.dll");
        if (!MultiByteToWideChar_orig && prev) {
            MultiByteToWideChar_orig = prev;
        }

        // Fallback trampoline if early_init did not cover this model.
        // One export only — dual kernel32+kernelbase hooks AV on Win10+ forwarders.
        if (!MultiByteToWideChar_orig) {
            decltype(MultiByteToWideChar) *orig = nullptr;
            if (detour::trampoline_try(
                        "kernelbase.dll",
                        "MultiByteToWideChar",
                        MultiByteToWideChar_hook,
                        &orig)
                    && orig) {
                MultiByteToWideChar_orig = orig;
            } else {
                orig = nullptr;
                if (detour::trampoline_try(
                            "kernel32.dll",
                            "MultiByteToWideChar",
                            MultiByteToWideChar_hook,
                            &orig)
                        && orig) {
                    MultiByteToWideChar_orig = orig;
                }
            }
        }
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
