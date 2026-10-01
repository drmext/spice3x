#include <winsock2.h>
#include <ws2tcpip.h>

#include <windows.h>
#include <iphlpapi.h>
#include <stdlib.h>
#include <string>
#include <mutex>
#include <stddef.h>
#include <cstring>

#include "avs/core.h"
#include "avs/ea3.h"
#include "avs/game.h"
#include "util/logging.h"
#include "util/detour.h"
#include "util/fileutils.h"
#include "util/libutils.h"
#include "util/deferlog.h"
#include "hooks/icmphook_net.h"

// hooking related stuff
static decltype(GetAdaptersInfo) *GetAdaptersInfo_orig = nullptr;
static decltype(GetIpAddrTable) *GetIpAddrTable_orig = nullptr;
static decltype(bind) *bind_orig = nullptr;
static decltype(connect) *connect_orig = nullptr;
static decltype(gethostbyname) *gethostbyname_orig = nullptr;

// IIDX 9-13 eamuse3 resolves the literal hostname "services".
static uint32_t legacy_eamuse_addr = 0; // network byte order
static uint16_t legacy_eamuse_port = 80; // host byte order
static bool legacy_eamuse_enabled = false;

// C02 eam3lib xml_parser_new malloc(92) zeroes callbacks through +0x54
// (comment) but leaves +0x58 (xmlDecl) uninitialized. xml_parse then does
// call [parser+0x58] on <?xml ...?> and jumps into free memory (minidump:
// EIP=EAX=garbage, stack return at eam3lib xmlDecl dispatch). ECO/D01/E11/FDD
// zero +0x58; only C02 is missing `mov [esi+58h], edi`.
using xml_parser_new_t = void *(__cdecl *)(int, int, int, int, int);
static xml_parser_new_t xml_parser_new_orig = nullptr;

static void *__cdecl xml_parser_new_hook(int a1, int a2, int a3, int a4, int a5) {
    void *parser = xml_parser_new_orig(a1, a2, a3, a4, a5);
    if (parser) {
        *reinterpret_cast<uint32_t *>(reinterpret_cast<uint8_t *>(parser) + 0x58) = 0;
    }
    return parser;
}

static bool eam3lib_xml_parser_new_leaks_xmldecl(HMODULE mod) {
    auto *p = reinterpret_cast<uint8_t *>(GetProcAddress(mod, "xml_parser_new"));
    if (!p) {
        return false;
    }
    // Prologue scan: mov [esi+54h],edi without the following mov [esi+58h],edi.
    for (size_t i = 0; i + 5 < 0xA0; i++) {
        if (p[i] == 0x89 && p[i + 1] == 0x7E && p[i + 2] == 0x54) {
            return !(p[i + 3] == 0x89 && p[i + 4] == 0x7E && p[i + 5] == 0x58);
        }
    }
    return false;
}

static void patch_eam3lib_xml_parser_new_bug(HMODULE eam3) {
    if (!eam3 || !eam3lib_xml_parser_new_leaks_xmldecl(eam3)) {
        return;
    }
    if (detour::trampoline_try(
            "eam3lib.dll", "xml_parser_new",
            xml_parser_new_hook, &xml_parser_new_orig)) {
        log_info("network",
                "legacy eamuse3: patched eam3lib xml_parser_new "
                "(zero uninitialized xmlDecl callback at +0x58)");
    } else {
        log_warning("network",
                "legacy eamuse3: failed to patch eam3lib xml_parser_new; "
                "C02 may AV in xml_parse after services");
    }
}

// settings
std::string NETWORK_ADDR = "10.9.0.0";
std::string NETWORK_SUBNET = "255.255.0.0";
static bool GetAdaptersInfo_log = true;
static bool GetIpAddrTable_log = true;

// network structs
static struct in_addr network;
static struct in_addr prefix;
static struct in_addr subnet;

static void defer_network_adapter_error() {
    static std::once_flag printed;
    std::call_once(printed, []() {
        deferredlogs::defer_error_messages({
            "network adapter issue detected!",
            "    ensure you have at least one network adapter with a valid IPv4 address",
            "    the IPv4 address can be external or internal, it just needs to be valid",
            "    the network adapter can be a wired or wireless connection",
            "    you still need to do this even if you are connecting to a local server!",
            });
    });
}

static bool is_valid_ipaddr_row(const MIB_IPADDRROW &row) {
    static const auto loopback = inet_addr("127.0.0.1");

    return row.dwAddr != 0 && row.dwAddr != loopback;
}

static MIB_IPADDRROW *find_preferred_ipaddr_row(PMIB_IPADDRTABLE table) {

    if (table == nullptr || table->dwNumEntries == 0) {
        return nullptr;
    }

    // prefer the row matching -adapternetwork/-adaptersubnet
    for (DWORD i = 0; i < table->dwNumEntries; i++) {
        auto &row = table->table[i];
        if (!is_valid_ipaddr_row(row)) {
            continue;
        }

        auto row_prefix = row.dwAddr & row.dwMask;
        if (row_prefix == prefix.s_addr && row.dwMask == subnet.s_addr) {
            return &row;
        }
    }

    // fall back to the interface Windows would route through by default
    PMIB_IPFORWARDTABLE pIpForwardTable = (MIB_IPFORWARDTABLE *) malloc(sizeof(MIB_IPFORWARDTABLE));
    DWORD dwSize = 0;
    if (GetIpForwardTable(pIpForwardTable, &dwSize, TRUE) == ERROR_INSUFFICIENT_BUFFER) {
        free(pIpForwardTable);
        pIpForwardTable = (MIB_IPFORWARDTABLE *) malloc(dwSize);
    }
    if (GetIpForwardTable(pIpForwardTable, &dwSize, TRUE) != NO_ERROR || pIpForwardTable->dwNumEntries == 0) {
        free(pIpForwardTable);
        return nullptr;
    }

    DWORD best = pIpForwardTable->table[0].dwForwardIfIndex;
    free(pIpForwardTable);

    for (DWORD i = 0; i < table->dwNumEntries; i++) {
        auto &row = table->table[i];
        if (row.dwIndex == best && is_valid_ipaddr_row(row)) {
            return &row;
        }
    }

    // last resort: keep a deterministic valid row instead of exposing all adapters
    for (DWORD i = 0; i < table->dwNumEntries; i++) {
        auto &row = table->table[i];
        if (is_valid_ipaddr_row(row)) {
            return &row;
        }
    }

    return nullptr;
}

static void keep_only_ipaddr_row(PMIB_IPADDRTABLE table, MIB_IPADDRROW *row) {
    if (table == nullptr || row == nullptr) {
        return;
    }

    if (GetIpAddrTable_log) {
        in_addr addr {};
        addr.s_addr = row->dwAddr;
        log_info("network", "Using preferred IP address row: {}", inet_ntoa(addr));
    }

    table->table[0] = *row;
    table->dwNumEntries = 1;
    GetIpAddrTable_log = false;
}

static ULONG WINAPI GetAdaptersInfo_hook(PIP_ADAPTER_INFO pAdapterInfo, PULONG pOutBufLen) {

    // call orig
    ULONG ret = GetAdaptersInfo_orig(pAdapterInfo, pOutBufLen);
    if (ret != ERROR_SUCCESS) {

        // workaround for QMA not having enough buffer space
        if (pAdapterInfo != nullptr && avs::game::is_model({ "LMA", "MMA" })) {

            // allocate the output buffer size
            auto pAdapterInfo2 = (PIP_ADAPTER_INFO) malloc(*pOutBufLen);

            // call ourself with an appropriate buffer size
            ret = GetAdaptersInfo_hook(pAdapterInfo2, pOutBufLen);
            if (ret != ERROR_SUCCESS) {
                return ret;
            }

            // copy best interface
            memcpy(pAdapterInfo, pAdapterInfo2, sizeof(*pAdapterInfo));
            pAdapterInfo->Next = nullptr;

            // free our allocated memory
            free(pAdapterInfo2);
        }

        if (ret != ERROR_SUCCESS && ret != ERROR_BUFFER_OVERFLOW) {
            defer_network_adapter_error();
            log_warning(
                "network",
                "GetAdaptersInfo failed with {}; "
                "check if you have at least one network adapter with a valid IPv4 address!",
                ret);
        }

        return ret;
    }

    // set the best network adapter
    PIP_ADAPTER_INFO info = pAdapterInfo;
    while (info != nullptr) {

        // set subnet
        struct in_addr info_subnet;
        info_subnet.s_addr = inet_addr(info->IpAddressList.IpMask.String);

        // set prefix
        struct in_addr info_prefix;
        info_prefix.s_addr = inet_addr(info->IpAddressList.IpAddress.String) & info_subnet.s_addr;

        // check base IP and subnet
        bool isCorrectBaseIp = prefix.s_addr == info_prefix.s_addr;
        bool isCorrectSubnetMask = subnet.s_addr == info_subnet.s_addr;

        // check if requirements are met
        if (isCorrectBaseIp && isCorrectSubnetMask) {

            // log adapter
            if (GetAdaptersInfo_log)
                log_info("network", "Using preferred network adapter: {}, {}",
                        info->AdapterName,
                        info->Description);

            // set adapter information
            memcpy(pAdapterInfo, info, sizeof(*info));
            pAdapterInfo->Next = nullptr;

            // we're done
            GetAdaptersInfo_log = false;
            return ret;
        }

        // iterate
        info = info->Next;
    }

    // get IP forward table
    PMIB_IPFORWARDTABLE pIpForwardTable = (MIB_IPFORWARDTABLE *) malloc(sizeof(MIB_IPFORWARDTABLE));
    DWORD dwSize = 0;
    if (GetIpForwardTable(pIpForwardTable, &dwSize, 1) == ERROR_INSUFFICIENT_BUFFER) {
        free(pIpForwardTable);
        pIpForwardTable = (MIB_IPFORWARDTABLE *) malloc(dwSize);
    }
    if (GetIpForwardTable(pIpForwardTable, &dwSize, 1) != NO_ERROR || pIpForwardTable->dwNumEntries == 0) {
        defer_network_adapter_error();
        if (GetAdaptersInfo_log) {
            log_warning("network", "GetIpForwardTable failed");
        }
        return ret;
    }

    // determine best interface
    DWORD best = pIpForwardTable->table[0].dwForwardIfIndex;
    free(pIpForwardTable);

    // find fallback adapter
    info = pAdapterInfo;
    while (info != nullptr) {

        // check if this the adapter we search for
        if (info->Index == best) {

            // log information
            if (GetAdaptersInfo_log)
                log_info("network", "Using fallback network adapter: {}, {}",
                        info->AdapterName,
                        info->Description);


            // set adapter information
            memcpy(pAdapterInfo, info, sizeof(*info));
            pAdapterInfo->Next = nullptr;

            // exit the loop
            break;
        }

        // iterate
        info = info->Next;
    }

    if (pAdapterInfo->IpAddressList.IpAddress.String[0] == 0 ||
        pAdapterInfo->IpAddressList.IpAddress.String[0] == '0') {
        defer_network_adapter_error();
        if (GetAdaptersInfo_log) {
            log_warning(
                "network",
                "invalid IPv4 address for adapter {}, {} = {}; "
                "ensure you have at least one network adapter with valid IPv4 address!",
                pAdapterInfo->AdapterName,
                pAdapterInfo->Description,
                pAdapterInfo->IpAddressList.IpAddress.String);
        }
    }

    // return original value
    GetAdaptersInfo_log = false;
    return ret;
}

static DWORD WINAPI GetIpAddrTable_hook(PMIB_IPADDRTABLE pIpAddrTable, PULONG pdwSize, BOOL bOrder) {

    auto input_size = pdwSize != nullptr ? *pdwSize : 0;
    auto ret = GetIpAddrTable_orig(pIpAddrTable, pdwSize, bOrder);

    if (ret == NO_ERROR) {
        auto row = find_preferred_ipaddr_row(pIpAddrTable);
        if (row != nullptr) {
            keep_only_ipaddr_row(pIpAddrTable, row);
        }
        return ret;
    }

    if (ret != ERROR_INSUFFICIENT_BUFFER || pIpAddrTable == nullptr || pdwSize == nullptr) {
        return ret;
    }

    // If the caller's buffer is large enough for the filtered single-row table,
    // satisfy the call even when Windows needed more room for all adapters.
    const auto one_row_size = offsetof(MIB_IPADDRTABLE, table) + sizeof(MIB_IPADDRROW);
    if (input_size < one_row_size) {
        return ret;
    }

    auto full_size = *pdwSize;
    auto table = (PMIB_IPADDRTABLE) malloc(full_size);
    if (table == nullptr) {
        return ret;
    }

    auto full_ret = GetIpAddrTable_orig(table, &full_size, bOrder);
    if (full_ret == NO_ERROR) {
        auto row = find_preferred_ipaddr_row(table);
        if (row != nullptr) {
            keep_only_ipaddr_row(pIpAddrTable, row);
            *pdwSize = one_row_size;
            ret = NO_ERROR;
        }
    }

    free(table);
    return ret;
}

static int WINAPI bind_hook(SOCKET s, const struct sockaddr *name, int namelen) {

#ifdef __clang__
#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCDFAInspection"
#endif

    int icmp_bind_result = 0;
    if (icmphook_try_bind(s, name, namelen, &icmp_bind_result)) {
        return icmp_bind_result;
    }

    // cast to sockaddr_in
    struct sockaddr_in *in_name = (struct sockaddr_in *) name;

#ifdef __clang__
#pragma clang diagnostic pop
#endif

    // override bind to allow all hosts
    in_name->sin_addr.s_addr = inet_addr("0.0.0.0");

    // call original
    int ret = bind_orig(s, name, namelen);
    if (ret != 0) {
        log_warning("network", "bind failed: {}", WSAGetLastError());
    }

    // return result
    return ret;
}

static bool parse_legacy_eamuse_url(const std::string &url, uint32_t *addr_out, uint16_t *port_out) {
    if (url.empty() || !addr_out || !port_out) {
        return false;
    }

    std::string host = url;
    if (auto pos = host.find("://"); pos != std::string::npos) {
        host = host.substr(pos + 3);
    }
    if (auto pos = host.find('/'); pos != std::string::npos) {
        host = host.substr(0, pos);
    }

    uint16_t port = 80;
    auto colon = host.rfind(':');
    if (colon != std::string::npos) {
        port = static_cast<uint16_t>(atoi(host.c_str() + colon + 1));
        if (port == 0) {
            port = 80;
        }
        host = host.substr(0, colon);
    }
    if (host.empty()) {
        return false;
    }

    unsigned long addr = inet_addr(host.c_str());
    if (addr == INADDR_NONE) {
        if (host == "localhost") {
            addr = inet_addr("127.0.0.1");
        } else {
            auto *resolver = gethostbyname_orig ? gethostbyname_orig : ::gethostbyname;
            auto *he = resolver(host.c_str());
            if (!he || !he->h_addr_list || !he->h_addr_list[0]) {
                return false;
            }
            memcpy(&addr, he->h_addr_list[0], sizeof(addr));
        }
    }

    *addr_out = static_cast<uint32_t>(addr);
    *port_out = port;
    return true;
}

static hostent *WSAAPI gethostbyname_legacy_hook(const char *name) {
    if (legacy_eamuse_enabled && name && strcmp(name, "services") == 0) {
        static hostent ret {};
        static char *addr_list[2] {};
        static uint32_t addr = 0;
        static bool init = false;
        if (!init) {
            ret.h_length = 4;
            ret.h_addrtype = AF_INET;
            ret.h_addr_list = addr_list;
            addr_list[0] = reinterpret_cast<char *>(&addr);
            addr_list[1] = nullptr;
            init = true;
        }
        addr = legacy_eamuse_addr;
        log_info("network", "legacy eamuse3: gethostbyname(\"services\") -> {:08x}:{}",
                ntohl(legacy_eamuse_addr), legacy_eamuse_port);
        return &ret;
    }
    return gethostbyname_orig(name);
}

static int WSAAPI connect_legacy_hook(SOCKET s, const sockaddr *name, int namelen) {
    if (legacy_eamuse_enabled && name && name->sa_family == AF_INET) {
        auto *in = reinterpret_cast<sockaddr_in *>(const_cast<sockaddr *>(name));
        if (in->sin_addr.s_addr == legacy_eamuse_addr) {
            log_misc("network", "legacy eamuse3: patch connect port {} -> {}",
                    ntohs(in->sin_port), legacy_eamuse_port);
            in->sin_port = htons(legacy_eamuse_port);
        }
    }
    return connect_orig(s, name, namelen);
}

static void install_legacy_eamuse_hooks() {
    // Match bemanitools iidxhook1-3 eamuse.c: IIDX 9-13 resolve the literal
    // hostname "services" (not services.eamuse.konami.fun) and connect with a
    // hard-coded port — redirect both to -url.
    if (!avs::game::is_model({"C02", "D01", "E11", "ECO", "FDD"})) {
        log_misc("network", "legacy eamuse3: skip (model is not IIDX 9-13)");
        return;
    }

    std::string url = avs::ea3::URL_CUSTOM;
    if (url.empty()) {
        // Same default as -ea (easrv_port 8080). Injected path sets URL_CUSTOM
        // from -url before networkhook_init; empty means user passed neither.
        url = "localhost:8080";
        log_info("network", "legacy eamuse3: URL_CUSTOM empty, defaulting to '{}'", url);
    }

    if (!parse_legacy_eamuse_url(url, &legacy_eamuse_addr, &legacy_eamuse_port)) {
        log_warning("network", "legacy eamuse3: failed to resolve services URL '{}'", url);
        return;
    }

    legacy_eamuse_enabled = true;

    // Ensure ws2_32 is mapped before MinHook (injected C02 may not have touched
    // Winsock yet). trampoline_try now LoadLibrary's if needed as well.
    libutils::try_library("ws2_32.dll");

    bool ghbn_ok = detour::trampoline_try(
            "ws2_32.dll", "gethostbyname",
            gethostbyname_legacy_hook, &gethostbyname_orig);
    bool conn_ok = detour::trampoline_try(
            "ws2_32.dll", "connect",
            connect_legacy_hook, &connect_orig);

    // Belt-and-suspenders like bemanitools hook_table_apply: patch IATs by name
    // and by frozen WS2_32 ordinals (4=connect, 52=gethostbyname). Captures
    // callers that somehow bypass the trampoline, and the injected game EXE.
    auto *ghbn_iat = detour::iat_try(
            "gethostbyname", gethostbyname_legacy_hook, nullptr, "ws2_32.dll");
    auto *conn_iat = detour::iat_try(
            "connect", connect_legacy_hook, nullptr, "ws2_32.dll");
    if (!gethostbyname_orig && ghbn_iat) {
        gethostbyname_orig = ghbn_iat;
    }
    if (!connect_orig && conn_iat) {
        connect_orig = conn_iat;
    }

    if (avs::game::DLL_INSTANCE) {
        auto *ghbn_ord = detour::iat_try_ordinal(
                "ws2_32.dll", 52, gethostbyname_legacy_hook, avs::game::DLL_INSTANCE);
        auto *conn_ord = detour::iat_try_ordinal(
                "ws2_32.dll", 4, connect_legacy_hook, avs::game::DLL_INSTANCE);
        if (!gethostbyname_orig && ghbn_ord) {
            gethostbyname_orig = ghbn_ord;
        }
        if (!connect_orig && conn_ord) {
            connect_orig = conn_ord;
        }
        // Named IAT on the game image (PEB walk skips process EXE).
        auto *ghbn_exe = detour::iat_try(
                "gethostbyname", gethostbyname_legacy_hook,
                avs::game::DLL_INSTANCE, "ws2_32.dll");
        auto *conn_exe = detour::iat_try(
                "connect", connect_legacy_hook,
                avs::game::DLL_INSTANCE, "ws2_32.dll");
        if (!gethostbyname_orig && ghbn_exe) {
            gethostbyname_orig = ghbn_exe;
        }
        if (!connect_orig && conn_exe) {
            connect_orig = conn_exe;
        }
    }

    // eam3lib resolves "services"; avs.dll's avs_socket_connect calls ws2_32
    // connect with the default HTTP port from http://services/. Patch both IATs
    // even if already mapped before networkhook_init (static imports).
    for (const char *mod_name : {"eam3lib.dll", "avs.dll"}) {
        HMODULE mod = libutils::try_module(mod_name);
        if (!mod) {
            continue;
        }
        auto *ghbn = detour::iat_try(
                "gethostbyname", gethostbyname_legacy_hook, mod, "ws2_32.dll");
        auto *conn = detour::iat_try(
                "connect", connect_legacy_hook, mod, "ws2_32.dll");
        if (!gethostbyname_orig && ghbn) {
            gethostbyname_orig = ghbn;
        }
        if (!connect_orig && conn) {
            connect_orig = conn;
        }
        // Ordinals too (some builds import by ordinal only).
        auto *ghbn_o = detour::iat_try_ordinal(
                "ws2_32.dll", 52, gethostbyname_legacy_hook, mod);
        auto *conn_o = detour::iat_try_ordinal(
                "ws2_32.dll", 4, connect_legacy_hook, mod);
        if (!gethostbyname_orig && ghbn_o) {
            gethostbyname_orig = ghbn_o;
        }
        if (!connect_orig && conn_o) {
            connect_orig = conn_o;
        }
        log_info("network", "legacy eamuse3: patched IAT on {}", mod_name);
        if (std::strcmp(mod_name, "eam3lib.dll") == 0) {
            patch_eam3lib_xml_parser_new_bug(mod);
        }
    }

    if (!gethostbyname_orig) {
        gethostbyname_orig = ::gethostbyname;
    }
    if (!connect_orig) {
        connect_orig = ::connect;
    }

    log_info("network",
            "legacy eamuse3 services redirect enabled "
            "(url='{}' -> {:08x}:{}, trampoline ghbn={} connect={})",
            url, ntohl(legacy_eamuse_addr), legacy_eamuse_port,
            ghbn_ok, conn_ok);
}

void networkhook_init() {

    // announce init
    log_info("network", "SpiceTools Network");

    // IIDX 9-13: redirect eamuse3 "services" hostname to -url / local easrv.
    install_legacy_eamuse_hooks();

    // set some same defaults
    network.s_addr = inet_addr(NETWORK_ADDR.c_str());
    subnet.s_addr = inet_addr(NETWORK_SUBNET.c_str());
    prefix.s_addr = network.s_addr & subnet.s_addr;

    // inet_ntoa(...) reuses the same char array so the results must be copied
    char s_network[17]{}, s_subnet[17]{}, s_prefix[17]{};
    strncpy(s_network, inet_ntoa(network), 16);
    strncpy(s_subnet, inet_ntoa(subnet), 16);
    strncpy(s_prefix, inet_ntoa(prefix), 16);

    // log preferences
    // log_info("network", "Network preferences: {}, {}, {}", s_network, s_subnet, s_prefix);

    // GetAdaptersInfo hook
    auto orig_addr = detour::iat_try(
        "GetAdaptersInfo", GetAdaptersInfo_hook, nullptr);
    if (!orig_addr) {
        libutils::try_library("iphlpapi.dll");
        if (detour::trampoline_try(
                "iphlpapi.dll", "GetAdaptersInfo",
                GetAdaptersInfo_hook, &GetAdaptersInfo_orig)) {
            log_info("network", "GetAdaptersInfo trampoline installed");
        } else {
            log_warning("network", "Could not hook GetAdaptersInfo");
        }
    } else if (GetAdaptersInfo_orig == nullptr) {
        GetAdaptersInfo_orig = orig_addr;
    }

    // GetIpAddrTable hook
    auto ip_addr_table_orig_addr = detour::iat_try(
        "GetIpAddrTable", GetIpAddrTable_hook, nullptr);
    if (!ip_addr_table_orig_addr) {
        // Injected 9-13 often miss this in the PEB IAT walk; trampoline instead.
        // Load iphlpapi first — MinHook GetModuleHandle fails if it is not mapped.
        libutils::try_library("iphlpapi.dll");
        if (detour::trampoline_try(
                "iphlpapi.dll", "GetIpAddrTable",
                GetIpAddrTable_hook, &GetIpAddrTable_orig)) {
            log_info("network", "GetIpAddrTable trampoline installed");
        } else if (avs::game::DLL_INSTANCE &&
                (ip_addr_table_orig_addr = detour::iat_try(
                        "GetIpAddrTable", GetIpAddrTable_hook,
                        avs::game::DLL_INSTANCE, "iphlpapi.dll"))) {
            GetIpAddrTable_orig = ip_addr_table_orig_addr;
            log_info("network", "GetIpAddrTable IAT hooked on game module");
        } else {
            log_warning("network",
                    "Could not hook GetIpAddrTable (IAT miss, trampoline also failed)");
        }
    } else if (GetIpAddrTable_orig == nullptr) {
        GetIpAddrTable_orig = ip_addr_table_orig_addr;
    }

    /*
     * Bind Hook
     */
    bool bind_hook_enabled = true;

    // disable hook for DDR A since the bind hook crashes there for some reason
    if (fileutils::file_exists(MODULE_PATH / "gamemdx.dll")) {
        bind_hook_enabled = false;
    }

    // hook bind
    if (bind_hook_enabled) {

        // hook by name
        auto new_bind_orig = detour::iat_try("bind", bind_hook, nullptr);
        if (bind_orig == nullptr) {
            bind_orig = new_bind_orig;
        }

        // hook ESS by ordinal
        HMODULE ess = libutils::try_module("ess.dll");
        if (ess) {
            auto new_bind_orig2 = detour::iat_try_ordinal("WS2_32.dll", 2, bind_hook, ess);

            // try to get some valid pointer
            if (bind_orig == nullptr && new_bind_orig2 != nullptr) {
                bind_orig = new_bind_orig2;
            }
        }
    }
}
