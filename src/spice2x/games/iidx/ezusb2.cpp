#include "ezusb2.h"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <string>

#include "avs/ea3.h"
#include "avs/game.h"
#include "external/hash-library/md5.h"
#include "games/iidx/iidx.h"
#include "games/iidx/io.h"
#include "rawinput/rawinput.h"
#include "util/logging.h"
#include "util/utils.h"

namespace games::iidx {
namespace {

// Classic ezusb.sys IOCTLs (Ezusb_IOCTL_INDEX 0x0800)
constexpr DWORD IOCTL_EZUSB_GET_DEVICE_DESCRIPTOR = 0x222004;
constexpr DWORD IOCTL_EZUSB_VENDOR_REQUEST = 0x222014;
constexpr DWORD IOCTL_EZUSB_ANCHOR_DOWNLOAD_BUF = 0x22201C;
constexpr DWORD IOCTL_EZUSB_BULK_READ = 0x22204E;
constexpr DWORD IOCTL_EZUSB_BULK_WRITE = 0x222051;
constexpr DWORD IOCTL_EZUSB_ANCHOR_DOWNLOAD = 0x22206D;

// Sirius (JDJ) uses the 2235 identity; Gold–EMPRESS use FX2LP.
constexpr uint16_t EZUSB_VID_2235 = 0x0547;
constexpr uint16_t EZUSB_PID_2235 = 0x2235;
constexpr uint16_t EZUSB_VID_FX2 = 0x04B4;
constexpr uint16_t EZUSB_PID_FX2 = 0x8613;

constexpr size_t EZUSB_PAGESIZE = 62;
constexpr size_t SECURITY2_NPAGES = 5;
constexpr size_t SRAM_NPAGES = 12;
constexpr size_t EEPROM_NPAGES = 3;

enum PipeNum : ULONG {
    PIPE_INT_OUT = 0,
    PIPE_INT_IN = 1,
    PIPE_BULK_OUT = 2,
    PIPE_BULK_IN = 3,
};

enum NodeId : uint8_t {
    NODE_NONE = 0x00,
    NODE_SECURITY_PLUG = 0x01,
    NODE_EEPROM = 0x02,
    NODE_FPGA_V2 = 0x04,
    NODE_16SEG = 0x05,
    NODE_COIN = 0x09,
    NODE_WDT = 0x0C,
    NODE_SRAM = 0x40,
    NODE_SECURITY_MEM = 0xFE,
};

enum DongleSlot : uint8_t {
    SLOT_BLACK = 0x00,
    SLOT_WHITE = 0x01,
};

enum DongleMem : uint8_t {
    MEM_ROM = 0x00,
    MEM_DATA = 0x01,
};

enum SecPlugCmd : uint8_t {
    SECPLUG_SEARCH = 0x01,
    SECPLUG_READ_DATA = 0x02,
    SECPLUG_READ_ROM = 0x06,
    SECPLUG_SELECT_1 = 0x07,
    SECPLUG_SELECT_2 = 0x08,
    SECPLUG_SELECT_3 = 0x09,
    SECPLUG_SELECT_4 = 0x0A,
    SECPLUG_SELECT_5 = 0x0B,
};

enum SecPlugStatus : uint8_t {
    SECPLUG_SEARCH_OK = 0x12,
    SECPLUG_READ_DATA_OK = 0x13,
    SECPLUG_READ_ROM_OK = 0x15,
    SECPLUG_SEL_OK = 0x16,
    SECPLUG_FAIL = 0xFE,
};

enum SecMemCmd : uint8_t {
    SECMEM_INIT = 0x00,
};

enum SecMemStatus : uint8_t {
    SECMEM_INIT_OK = 0x11,
    SECMEM_FAULT = 0xFE,
};

enum CoinCmd : uint8_t {
    COIN_MODE_1 = 0x01,
    COIN_MODE_2 = 0x02,
};

enum CoinStatus : uint8_t {
    COIN_OK = 0x00,
    COIN_FAULT = 0xFE,
};

enum Seg16Cmd : uint8_t {
    SEG16_WRITE = 0x03,
};

enum FpgaCmd : uint8_t {
    FPGA_INIT = 0x01,
    FPGA_CHECK = 0x02,
    FPGA_WRITE = 0x03,
    FPGA_WRITE_DONE = 0x04,
};

enum FpgaStatus : uint8_t {
    FPGA_INIT_OK = 0x41,
    FPGA_CHECK_OK = 0x42,
    FPGA_WRITE_OK = 0x43,
    FPGA_FAULT = 0xFE,
};

enum SramCmd : uint8_t {
    SRAM_CMD_READ = 0x02,
    SRAM_CMD_WRITE = 0x03,
    SRAM_CMD_DONE = 0x04,
};

enum EepromCmd : uint8_t {
    EEPROM_CMD_READ = 0x02,
    EEPROM_CMD_WRITE = 0x03,
};

enum EepromStatus : uint8_t {
    EEPROM_READ_OK = 0x21,
    EEPROM_WRITE_OK = 0x22,
    EEPROM_FAULT = 0xFE,
};

enum WdtCmd : uint8_t {
    WDT_CMD_INIT = 0x3C,
};

enum WdtStatus : uint8_t {
    WDT_OK = 0x00,
    WDT_FAULT = 0xFE,
};

#pragma pack(push, 1)
struct UsbDeviceDescriptor {
    uint8_t bLength;
    uint8_t bDescriptorType;
    uint16_t bcdUSB;
    uint8_t bDeviceClass;
    uint8_t bDeviceSubClass;
    uint8_t bDeviceProtocol;
    uint8_t bMaxPacketSize0;
    uint16_t idVendor;
    uint16_t idProduct;
    uint16_t bcdDevice;
    uint8_t iManufacturer;
    uint8_t iProduct;
    uint8_t iSerialNumber;
    uint8_t bNumConfigurations;
};

// Natural alignment of the ezusb.sys struct: one pad byte before the USHORTs.
struct VendorOrClassRequestControl {
    uint8_t direction;
    uint8_t request_type;
    uint8_t recipient;
    uint8_t request_type_reserved_bits;
    uint8_t request;
    uint8_t pad;
    uint16_t value;
    uint16_t index;
};

struct AnchorDownloadControl {
    uint16_t offset;
};

struct BulkTransferControl {
    ULONG pipe_num;
};

// EzusbTransfer1 (Sirius / JDJ) uses 16-byte interrupt pipes.
// Node and cmd are at 2 and 3. Deck lights are the leading uint16.
struct InterruptWritePacket {
    uint16_t deck_lights;
    uint8_t node;
    uint8_t cmd;
    uint8_t cmd_detail[2];
    uint8_t panel_lights;
    uint8_t unk0;
    uint8_t top_lamps;
    uint8_t top_neons;
    uint8_t fpga_run;
    uint8_t unk2;
    uint8_t unk3;
    uint8_t unk4;
    uint8_t unk5;
    uint8_t unk6;
};

// EzusbIodev1JDJ un-inverts this dword. Test is bit 28, service is bit 29.
struct InterruptReadPacket {
    uint32_t inverted_pad;
    uint8_t status;
    uint8_t unk0;
    uint8_t unk1;
    uint8_t p2_turntable;
    uint8_t p1_turntable;
    uint8_t seq_no;
    uint8_t fpga2_check_flag_unkn;
    uint8_t fpga_write_ready;
    uint8_t serial_io_busy_flag;
    uint8_t sliders[3];
};
static_assert(sizeof(InterruptReadPacket) == 16, "Sirius interrupt read is 16 bytes");

// Gold–EMPRESS FX2 endpoint expects 64-byte interrupt transfers (bemanitools
// ezusb2-iidx/msg.h). A short read makes SQ-INIT fail.
struct Fx2InterruptWritePacket {
    uint8_t unk0;
    uint8_t unk1;
    uint8_t node;
    uint8_t cmd;
    uint8_t cmd_detail[2];
    uint8_t unk2;
    uint8_t unk3;
    uint8_t panel_lights;
    uint8_t unk4;
    uint8_t unk5;
    uint16_t deck_lights;
    uint8_t unk6;
    uint8_t top_lamps;
    uint8_t top_neons;
    uint8_t seg16[9];
    uint8_t padding[39];
};
static_assert(sizeof(Fx2InterruptWritePacket) == 64, "FX2 interrupt write is 64 bytes");
static_assert(offsetof(Fx2InterruptWritePacket, panel_lights) == 8, "FX2 panel_lights offset");
static_assert(offsetof(Fx2InterruptWritePacket, deck_lights) == 11, "FX2 deck_lights offset");
static_assert(offsetof(Fx2InterruptWritePacket, top_lamps) == 14, "FX2 top_lamps offset");

struct Fx2InterruptReadPacket {
    uint8_t unk0;
    uint8_t unk1;
    uint8_t unk2;
    uint8_t seq_no;
    uint8_t status;
    uint8_t unk3;
    uint8_t unk4;
    uint8_t unk5;
    uint32_t inverted_pad;
    uint8_t unk6;
    uint8_t p2_turntable;
    uint8_t p1_turntable;
    uint8_t sliders[3];
    uint8_t padding[46];
};
static_assert(sizeof(Fx2InterruptReadPacket) == 64, "FX2 interrupt read is 64 bytes");

struct BulkPacket {
    uint8_t node;
    uint8_t page;
    uint8_t payload[EZUSB_PAGESIZE];
};

struct SecurityId {
    uint8_t header;
    uint8_t id[8];
    uint8_t checksum;
};

struct Rp2Eeprom {
    uint8_t signature[6];
    uint8_t packed_payload[6];
};
#pragma pack(pop)

static_assert(sizeof(UsbDeviceDescriptor) == 18, "USB device descriptor size");
static_assert(sizeof(VendorOrClassRequestControl) == 10, "vendor request size");
static_assert(sizeof(SecurityId) == 10, "security id size");

// Preloaded GOLD IO2 security memory (from bemanitools node-security-mem.c)
uint8_t g_sec_mem[EZUSB_PAGESIZE * SECURITY2_NPAGES] = {
        0x00, 0x90, 0x31, 0xCF, 0x95, 0x7A, 0x59, 0xE5, 0xD2, 0xBF, 0x2C, 0xDB,
        0xB5, 0x83, 0x4D, 0x03, 0x17, 0x5D, 0x25, 0x2A, 0xFD, 0x72, 0x1E, 0x01,
        0x02, 0x60, 0x88, 0x92, 0x9A, 0x9B, 0x2A, 0xA9, 0x73, 0x5A, 0x0E, 0x9B,
        0xC8, 0xCD, 0x85, 0x4D, 0xE0, 0xBA, 0xF4, 0xEC, 0x8A, 0x24, 0x76, 0x3C,
        0xDC, 0x35, 0xC7, 0xD7, 0xFF, 0xFF, 0x9C, 0x64, 0x44, 0x4C, 0xD7, 0x06,
        0x60, 0x17, 0xAD, 0x0E, 0x02, 0xEB, 0x46, 0x45, 0x96, 0xB0, 0xD6, 0xB9,
        0x7C, 0x34, 0xBE, 0x77, 0x75, 0xF2, 0xBE, 0x1B, 0x99, 0x62, 0xBC, 0x9B,
        0x92, 0x5C, 0x26, 0x39, 0x6C, 0xCD, 0x84, 0xFD, 0xC0, 0x58, 0x2B, 0xA8,
        0x7D, 0x10, 0xB3, 0x81, 0x25, 0xF3, 0x24, 0xE7, 0xB1, 0x4D, 0x6D, 0x12,
        0xF7, 0xAE, 0x27, 0xE0, 0xD2, 0x95, 0x30, 0x2D, 0xD1, 0x79, 0x27, 0x81,
        0xBB, 0x67, 0x47, 0x91, 0xAE, 0xC1, 0xB8, 0x79, 0x1F, 0x5E, 0xD5, 0x08,
        0x84, 0xA9, 0x6D, 0x1A, 0xF3, 0xEB, 0x8C, 0x58, 0x78, 0x5F, 0xD8, 0x51,
        0x74, 0x45, 0xFB, 0x4C, 0xBD, 0x91, 0x32, 0xC2, 0xD6, 0x65, 0x80, 0xE3,
        0x07, 0xFE, 0x92, 0x0C, 0x88, 0x31, 0xD7, 0xA0, 0xA8, 0x32, 0xD7, 0x1F,
        0x1C, 0xBE, 0x50, 0xF0, 0x49, 0x56, 0x23, 0xBB, 0xD5, 0xB5, 0x99, 0xBF,
        0x40, 0x24, 0x00, 0x0F, 0xCE, 0xDA, 0x35, 0x1D, 0x8D, 0x03, 0x1D, 0x74,
        0xC0, 0xAF, 0x8B, 0x12, 0x6F, 0x33, 0xB2, 0x4A, 0x6F, 0x3B, 0x93, 0x88,
        0xA0, 0x29, 0x81, 0xF6, 0xB2, 0xEC, 0x30, 0x56, 0x2D, 0xFE, 0x75, 0xFF,
        0x18, 0xA0, 0x18, 0x70, 0xEE, 0x0C, 0xE5, 0x4A, 0x3A, 0xC4, 0x69, 0x33,
        0xA0, 0x9A, 0x73, 0x77, 0x99, 0xA2, 0xDA, 0xD4, 0x9F, 0xB8, 0x90, 0x60,
        0x2F, 0xBC, 0x8E, 0xE7, 0x3E, 0x30, 0x9A, 0xB2, 0x95, 0x59, 0x7E, 0x14,
        0xBD, 0x9C, 0x9E, 0xB0};

uint8_t g_status = 0;
uint8_t g_seq_no = 0;
uint8_t g_cur_node = 0;
uint8_t g_coin_mode = 0;
DongleSlot g_dongle_slot = SLOT_BLACK;
DongleMem g_dongle_mem = MEM_ROM;
uint8_t g_rom_seed = 0;

uint8_t g_sram[EZUSB_PAGESIZE * SRAM_NPAGES] {};
uint8_t g_sram_last_cmd = 0;
int g_sram_read_page = 0;

uint8_t g_eeprom[EZUSB_PAGESIZE * EEPROM_NPAGES];
uint8_t g_eeprom_read_page = 0;
bool g_eeprom_ready = false;

void ensure_eeprom() {
    if (g_eeprom_ready) {
        return;
    }
    memset(g_eeprom, 0xFF, sizeof(g_eeprom));
    g_eeprom_ready = true;
}

constexpr char kBlackSignKey[8] = {'2', 'D', 'X', 'G', 'L', 'D', 'A', 'C'};
constexpr char kWhiteSignKey[8] = {'E', '-', 'A', 'M', 'U', 'S', 'E', '3'};
constexpr char kBlackMcode[8] = {'G', 'C', 'J', 'D', 'J', 'J', 'A', 'A'};
constexpr char kWhiteMcode[8] = {'@', '@', '@', '@', '@', '@', '@', '@'};

SecurityId g_pcbid {};
SecurityId g_eamid {};
bool g_ids_ready = false;

uint8_t sec_id_checksum(const uint8_t *id) {
    uint8_t bufcheck[7] = {
            id[1], id[7], id[6], id[5], id[4], id[3], id[2]};
    uint8_t result = 0;
    for (int byte_i = 0; byte_i < 7; byte_i++) {
        unsigned v6 = bufcheck[byte_i];
        for (int v7 = 0; v7 < 8; v7 += 4) {
            for (int s = 0; s < 4; s++) {
                int bit = (result ^ (uint8_t) (v6 >> (v7 + s))) & 1;
                result >>= 1;
                if (bit) {
                    result ^= 0x8C;
                }
            }
        }
    }
    return result;
}

bool parse_hex_security_id(const std::string &hex, SecurityId *out) {
    if (hex.size() != 20) {
        return false;
    }
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    uint8_t bytes[10] {};
    for (size_t i = 0; i < 10; i++) {
        int hi = nib(hex[i * 2]);
        int lo = nib(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            return false;
        }
        bytes[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    memcpy(out, bytes, sizeof(*out));
    return out->header == 0x01 && out->checksum == sec_id_checksum(out->id);
}

void ensure_security_ids() {
    if (g_ids_ready) {
        return;
    }

    // Default bemanitools PCBID/EAMID 0101020304050607086F
    g_pcbid = {0x01, {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}, 0x6F};
    if (!avs::ea3::PCBID_CUSTOM.empty()) {
        SecurityId parsed {};
        if (parse_hex_security_id(avs::ea3::PCBID_CUSTOM, &parsed)) {
            g_pcbid = parsed;
        } else {
            log_warning("iidx::ezusb2", "PCBID {} is not a 10-byte hex id; using default",
                    avs::ea3::PCBID_CUSTOM);
        }
    }
    g_eamid = g_pcbid;
    g_ids_ready = true;
    log_info("iidx::ezusb2", "security ids ready (PCBID checksum {:02X})", g_pcbid.checksum);
}

void encode_8_to_6(const uint8_t *in, uint8_t *out) {
    uint8_t tmp[8];
    for (int i = 0; i < 8; i++) {
        tmp[i] = (in[i] - 0x20) & 0x3F;
    }
    out[0] = (tmp[0] >> 0) | (tmp[1] << 6);
    out[1] = (tmp[1] >> 2) | (tmp[2] << 4);
    out[2] = (tmp[2] >> 4) | (tmp[3] << 2);
    out[3] = (tmp[4] >> 0) | (tmp[5] << 6);
    out[4] = (tmp[5] >> 2) | (tmp[6] << 4);
    out[5] = (tmp[6] >> 4) | (tmp[7] << 2);
}

void rp2_create_signature(const uint8_t *plug_id_enc, const uint8_t *sign_key_packed,
        uint8_t *out) {
    static const uint8_t scramble[16] = {
            0x0C, 0x02, 0x0F, 0x01, 0x07, 0x09, 0x04, 0x0A,
            0x00, 0x0E, 0x03, 0x0D, 0x0B, 0x05, 0x08, 0x06};

    uint8_t data[14];
    memcpy(data, plug_id_enc, 8);
    memcpy(data + 8, sign_key_packed, 6);

    MD5 md5;
    md5.add(data, 14);
    uint8_t digest[16];
    md5.getHash(digest);

    uint8_t buffer[18];
    for (int i = 0; i < 16; i++) {
        buffer[i] = digest[scramble[i]];
    }
    buffer[16] = 0xDE;
    buffer[17] = 0xAD;

    for (int i = 0; i < 6; i++) {
        out[i] = buffer[i + 12] ^ buffer[i + 6] ^ buffer[i];
    }
}

void rp2_signed_eeprom(bool black, const char sign_key[8], const char mcode[8],
        const SecurityId &id, Rp2Eeprom *out) {
    uint8_t sign_key_tmp[8];
    for (int i = 0; i < 8; i++) {
        sign_key_tmp[i] = static_cast<uint8_t>(sign_key[i]) ^ 0x40;
        if (black) {
            sign_key_tmp[i] ^= static_cast<uint8_t>(mcode[i]);
        }
    }

    uint8_t plug_id_enc[8];
    plug_id_enc[0] = id.checksum;
    memcpy(&plug_id_enc[1], &id.id[2], 6);
    plug_id_enc[7] = id.id[1];

    uint8_t sign_key_packed[8];
    encode_8_to_6(sign_key_tmp, sign_key_packed);
    rp2_create_signature(plug_id_enc, sign_key_packed, out->signature);
    encode_8_to_6(reinterpret_cast<const uint8_t *>(mcode), out->packed_payload);
}

uint8_t sec_mem_read(uint32_t pos) {
    if (pos < sizeof(g_sec_mem)) {
        return g_sec_mem[pos];
    }
    return 0;
}

void encrypt_rom_data(uint8_t *buffer, uint8_t length) {
    for (uint8_t i = 0; i < length; i++) {
        buffer[i] ^= sec_mem_read((g_rom_seed + i) & 0xFF);
    }
}

uint8_t process_secplug(uint8_t cmd, uint8_t detail0) {
    ensure_security_ids();
    switch (cmd) {
        case SECPLUG_SEARCH:
            g_dongle_mem = MEM_ROM;
            g_rom_seed = detail0;
            return SECPLUG_SEARCH_OK;
        case SECPLUG_READ_DATA:
            g_dongle_mem = MEM_DATA;
            return SECPLUG_READ_DATA_OK;
        case SECPLUG_READ_ROM:
            g_dongle_mem = MEM_ROM;
            g_rom_seed = detail0;
            return SECPLUG_READ_ROM_OK;
        case SECPLUG_SELECT_1:
        case SECPLUG_SELECT_2:
        case SECPLUG_SELECT_5:
            g_dongle_slot = SLOT_WHITE;
            return SECPLUG_SEL_OK;
        case SECPLUG_SELECT_3:
        case SECPLUG_SELECT_4:
            g_dongle_slot = SLOT_BLACK;
            return SECPLUG_SEL_OK;
        default:
            log_warning("iidx::ezusb2", "unknown secplug cmd {:02x}", cmd);
            return SECPLUG_FAIL;
    }
}

bool read_secplug_packet(BulkPacket *pkg) {
    ensure_security_ids();
    memset(pkg, 0, sizeof(*pkg));

    const bool black = g_dongle_slot == SLOT_BLACK;
    const SecurityId &id = black ? g_pcbid : g_eamid;

    if (g_dongle_mem == MEM_ROM) {
        pkg->node = 0x11;
        pkg->page = 0x00;
        memcpy(pkg->payload, &id, sizeof(id));
        encrypt_rom_data(pkg->payload, 10);
        return true;
    }

    pkg->node = 0x12;
    pkg->page = 0x00;
    Rp2Eeprom eeprom {};
    if (black) {
        rp2_signed_eeprom(true, kBlackSignKey, kBlackMcode, id, &eeprom);
    } else {
        rp2_signed_eeprom(false, kWhiteSignKey, kWhiteMcode, id, &eeprom);
    }
    memcpy(pkg->payload, &eeprom, sizeof(eeprom));
    return true;
}

uint8_t process_secmem(uint8_t cmd) {
    if (cmd == SECMEM_INIT) {
        return SECMEM_INIT_OK;
    }
    log_warning("iidx::ezusb2", "unknown secmem cmd {:02x}", cmd);
    return SECMEM_FAULT;
}

uint8_t process_coin(uint8_t cmd) {
    if (cmd == COIN_MODE_1) {
        g_coin_mode = 0;
        return COIN_OK;
    }
    if (cmd == COIN_MODE_2) {
        g_coin_mode = 1;
        return COIN_OK;
    }
    log_warning("iidx::ezusb2", "unknown coin cmd {:02x}", cmd);
    return COIN_FAULT;
}

uint8_t process_fpga(uint8_t cmd) {
    switch (cmd) {
        case FPGA_INIT:
            return FPGA_INIT_OK;
        case FPGA_CHECK:
            return FPGA_CHECK_OK;
        case FPGA_WRITE:
        case FPGA_WRITE_DONE:
            return FPGA_WRITE_OK;
        default:
            log_warning("iidx::ezusb2", "unknown fpga cmd {:02x}", cmd);
            return FPGA_FAULT;
    }
}

uint8_t process_sram(uint8_t cmd) {
    g_sram_last_cmd = cmd;
    switch (cmd) {
        case SRAM_CMD_READ:
        case SRAM_CMD_WRITE:
            g_sram_read_page = 0;
            break;
        case SRAM_CMD_DONE:
            break;
        default:
            log_warning("iidx::ezusb2", "unknown sram cmd {:02x}", cmd);
            break;
    }
    // bemani always returns 0 for SRAM commands
    return 0;
}

uint8_t process_eeprom(uint8_t cmd) {
    ensure_eeprom();
    switch (cmd) {
        case EEPROM_CMD_READ:
            g_eeprom_read_page = 0;
            return EEPROM_READ_OK;
        case EEPROM_CMD_WRITE:
            return EEPROM_WRITE_OK;
        default:
            log_warning("iidx::ezusb2", "unknown eeprom cmd {:02x}", cmd);
            return EEPROM_FAULT;
    }
}

uint8_t process_wdt(uint8_t cmd) {
    if (cmd == WDT_CMD_INIT) {
        return WDT_OK;
    }
    log_warning("iidx::ezusb2", "unknown wdt cmd {:02x}", cmd);
    return WDT_FAULT;
}

bool process_node_cmd(uint8_t node, uint8_t cmd, uint8_t d0, uint8_t d1) {
    switch (node) {
        case NODE_NONE:
            g_status = 0;
            return true;
        case NODE_SECURITY_PLUG:
            g_status = process_secplug(cmd, d0);
            return true;
        case NODE_SECURITY_MEM:
            g_status = process_secmem(cmd);
            return true;
        case NODE_COIN:
            g_status = process_coin(cmd);
            return true;
        case NODE_16SEG:
            g_status = (cmd == SEG16_WRITE) ? 0x00 : 0xFE;
            return true;
        case NODE_FPGA_V2:
            g_status = process_fpga(cmd);
            return true;
        case NODE_SRAM:
            g_status = process_sram(cmd);
            return true;
        case NODE_EEPROM:
            g_status = process_eeprom(cmd);
            return true;
        case NODE_WDT:
            g_status = process_wdt(cmd);
            return true;
        default:
            log_warning("iidx::ezusb2", "unknown node {:02x}", node);
            return false;
    }
}

struct PadBits {
    uint32_t panel;
    uint32_t sys;
    uint32_t keys;
};

PadBits read_pad_bits() {
    PadBits bits {};
    auto &buttons = get_buttons();

    auto pressed = [&](size_t index) {
        return GameAPI::Buttons::getState(RI_MGR, buttons.at(index));
    };

    if (pressed(Buttons::P1_Start)) bits.panel |= 1u << 0;
    if (pressed(Buttons::P2_Start)) bits.panel |= 1u << 1;
    if (pressed(Buttons::VEFX)) bits.panel |= 1u << 2;
    if (pressed(Buttons::Effect)) bits.panel |= 1u << 3;

    if (pressed(Buttons::Test)) bits.sys |= 1u << 0;
    if (pressed(Buttons::Service)) bits.sys |= 1u << 1;
    if (pressed(Buttons::CoinMech)) bits.sys |= 1u << 2;

    if (pressed(Buttons::P1_1)) bits.keys |= 1u << 0;
    if (pressed(Buttons::P1_2)) bits.keys |= 1u << 1;
    if (pressed(Buttons::P1_3)) bits.keys |= 1u << 2;
    if (pressed(Buttons::P1_4)) bits.keys |= 1u << 3;
    if (pressed(Buttons::P1_5)) bits.keys |= 1u << 4;
    if (pressed(Buttons::P1_6)) bits.keys |= 1u << 5;
    if (pressed(Buttons::P1_7)) bits.keys |= 1u << 6;
    if (pressed(Buttons::P2_1)) bits.keys |= 1u << 7;
    if (pressed(Buttons::P2_2)) bits.keys |= 1u << 8;
    if (pressed(Buttons::P2_3)) bits.keys |= 1u << 9;
    if (pressed(Buttons::P2_4)) bits.keys |= 1u << 10;
    if (pressed(Buttons::P2_5)) bits.keys |= 1u << 11;
    if (pressed(Buttons::P2_6)) bits.keys |= 1u << 12;
    if (pressed(Buttons::P2_7)) bits.keys |= 1u << 13;
    return bits;
}

// EzusbIodev1JDJ: keys<<8, panel<<24, sys<<28, coin-mech<<22.
// The game un-inverts the dword, so test lands on bit 28 and service on bit 29.
uint32_t build_iidx_pad() {
    const PadBits bits = read_pad_bits();
    uint32_t pad = ((bits.keys & 0x3FFFu) << 8)
            | ((bits.panel & 0x0Fu) << 24)
            | ((bits.sys & 0x07u) << 28)
            | (((bits.sys >> 2) & 0x01u) << 22);

    // Coin mode state in bit 31 (mode1 -> 0, mode2 -> 1)
    pad &= ~(1u << 31);
    if (g_coin_mode == 1) {
        pad |= (1u << 31);
    }
    return ~pad;
}

// Gold–EMPRESS FX2 pad map (bemanitools ezusb2-iidx-emu/msg.c).
uint32_t build_fx2_pad() {
    const PadBits bits = read_pad_bits();
    uint32_t pad = ((bits.keys & 0x3FFFu) << 16)
            | (bits.panel & 0x0Fu)
            | ((bits.sys & 0x07u) << 4)
            | (((bits.sys >> 2) & 0x01u) << 30);
    return ~pad;
}

bool is_fx2_packet() {
    return avs::game::is_model({"GLD", "HDD", "I00"});
}

bool interrupt_read_sirius(LPVOID lpOutBuffer, DWORD nOutBufferSize) {
    if (nOutBufferSize < sizeof(InterruptReadPacket) || !lpOutBuffer) {
        return false;
    }

    InterruptReadPacket msg {};
    msg.inverted_pad = build_iidx_pad();
    msg.status = g_status;
    g_status = 0;
    msg.p2_turntable = get_tt(1, false);
    msg.p1_turntable = get_tt(0, false);
    msg.seq_no = g_seq_no++;
    msg.fpga2_check_flag_unkn = 2;
    msg.fpga_write_ready = 1;
    msg.serial_io_busy_flag = 0;
    msg.sliders[0] = static_cast<uint8_t>((get_slider(1) << 4) | get_slider(0));
    msg.sliders[1] = static_cast<uint8_t>((get_slider(3) << 4) | get_slider(2));
    msg.sliders[2] = get_slider(4);

    memcpy(lpOutBuffer, &msg, sizeof(msg));
    return true;
}

bool interrupt_read_fx2(LPVOID lpOutBuffer, DWORD nOutBufferSize) {
    if (nOutBufferSize < sizeof(Fx2InterruptReadPacket) || !lpOutBuffer) {
        return false;
    }

    Fx2InterruptReadPacket msg {};
    msg.seq_no = g_seq_no++;
    msg.status = g_status;
    g_status = 0;
    msg.inverted_pad = build_fx2_pad();
    msg.p2_turntable = get_tt(1, false);
    msg.p1_turntable = get_tt(0, false);
    msg.sliders[0] = static_cast<uint8_t>((get_slider(1) << 4) | get_slider(0));
    msg.sliders[1] = static_cast<uint8_t>((get_slider(3) << 4) | get_slider(2));
    msg.sliders[2] = get_slider(4);

    memcpy(lpOutBuffer, &msg, sizeof(msg));
    return true;
}

bool interrupt_read(LPVOID lpOutBuffer, DWORD nOutBufferSize) {
    if (is_fx2_packet()) {
        return interrupt_read_fx2(lpOutBuffer, nOutBufferSize);
    }
    return interrupt_read_sirius(lpOutBuffer, nOutBufferSize);
}

bool interrupt_write_sirius(LPCVOID lpOutBuffer, DWORD nOutBufferSize) {
    if (nOutBufferSize < sizeof(InterruptWritePacket) || !lpOutBuffer) {
        return false;
    }

    InterruptWritePacket msg {};
    memcpy(&msg, lpOutBuffer, sizeof(msg));

    write_lamp(msg.deck_lights);
    write_led(msg.panel_lights);
    write_top_lamp(msg.top_lamps);
    write_top_neon(msg.top_neons);
    if (RI_MGR) {
        RI_MGR->devices_flush_output();
    }

    g_cur_node = msg.node;
    if (!process_node_cmd(msg.node, msg.cmd, msg.cmd_detail[0], msg.cmd_detail[1])) {
        g_cur_node = 0;
        return false;
    }
    return true;
}

bool interrupt_write_fx2(LPCVOID lpOutBuffer, DWORD nOutBufferSize) {
    if (nOutBufferSize < sizeof(Fx2InterruptWritePacket) || !lpOutBuffer) {
        return false;
    }

    Fx2InterruptWritePacket msg {};
    memcpy(&msg, lpOutBuffer, sizeof(msg));

    write_lamp(msg.deck_lights);
    write_led(msg.panel_lights);
    write_top_lamp(msg.top_lamps);
    write_top_neon(msg.top_neons);

    IIDX_LED_TICKER_LOCK.lock();
    if (!IIDXIO_LED_TICKER_READONLY) {
        memcpy(IIDXIO_LED_TICKER, msg.seg16, 9);
        IIDXIO_LED_TICKER[9] = '\0';
    }
    IIDX_LED_TICKER_LOCK.unlock();

    if (RI_MGR) {
        RI_MGR->devices_flush_output();
    }

    g_cur_node = msg.node;
    if (!process_node_cmd(msg.node, msg.cmd, msg.cmd_detail[0], msg.cmd_detail[1])) {
        g_cur_node = 0;
        return false;
    }
    return true;
}

bool interrupt_write(LPCVOID lpOutBuffer, DWORD nOutBufferSize) {
    if (is_fx2_packet()) {
        return interrupt_write_fx2(lpOutBuffer, nOutBufferSize);
    }
    return interrupt_write_sirius(lpOutBuffer, nOutBufferSize);
}

bool bulk_read(LPVOID lpOutBuffer, DWORD nOutBufferSize) {
    if (nOutBufferSize < sizeof(BulkPacket) || !lpOutBuffer) {
        return false;
    }

    BulkPacket pkg {};
    switch (g_cur_node) {
        case NODE_SECURITY_PLUG:
            if (!read_secplug_packet(&pkg)) {
                return false;
            }
            break;
        case NODE_SRAM:
            if (g_sram_last_cmd != SRAM_CMD_READ) {
                log_warning("iidx::ezusb2", "sram bulk read without READ cmd ({:02x})",
                        g_sram_last_cmd);
                return false;
            }
            if (g_sram_read_page >= static_cast<int>(SRAM_NPAGES)) {
                log_warning("iidx::ezusb2", "sram read overrun");
                return false;
            }
            // Gold to Sirius require node 0x40 on the returned page
            pkg.node = NODE_SRAM;
            pkg.page = static_cast<uint8_t>(g_sram_read_page);
            memcpy(pkg.payload, g_sram + g_sram_read_page * EZUSB_PAGESIZE, EZUSB_PAGESIZE);
            g_sram_read_page++;
            break;
        case NODE_EEPROM: {
            ensure_eeprom();
            if (g_eeprom_read_page >= EEPROM_NPAGES) {
                log_warning("iidx::ezusb2", "eeprom read overrun");
                return false;
            }
            // Game only accepts pages whose node byte is 0x22
            pkg.node = 0x22;
            pkg.page = g_eeprom_read_page;
            memcpy(pkg.payload, g_eeprom + g_eeprom_read_page * EZUSB_PAGESIZE, EZUSB_PAGESIZE);
            g_eeprom_read_page++;
            break;
        }
        case NODE_SECURITY_MEM:
        case NODE_NONE:
        case NODE_FPGA_V2:
        case NODE_WDT:
            // FPGA/security-mem/wdt stub: empty page
            break;
        default:
            log_warning("iidx::ezusb2", "bulk read unsupported on node {:02x}", g_cur_node);
            return false;
    }

    memcpy(lpOutBuffer, &pkg, sizeof(pkg));
    return true;
}

bool bulk_write(LPCVOID lpOutBuffer, DWORD nOutBufferSize) {
    if (nOutBufferSize < sizeof(BulkPacket) || !lpOutBuffer) {
        return false;
    }

    BulkPacket pkg {};
    memcpy(&pkg, lpOutBuffer, sizeof(pkg));

    switch (pkg.node) {
        case NODE_SECURITY_MEM:
            if (pkg.page >= SECURITY2_NPAGES) {
                return false;
            }
            memcpy(g_sec_mem + pkg.page * EZUSB_PAGESIZE, pkg.payload, EZUSB_PAGESIZE);
            return true;
        case NODE_SRAM:
            if (pkg.page >= SRAM_NPAGES) {
                log_warning("iidx::ezusb2", "sram write overrun page {:02x}", pkg.page);
                return false;
            }
            memcpy(g_sram + pkg.page * EZUSB_PAGESIZE, pkg.payload, EZUSB_PAGESIZE);
            return true;
        case NODE_EEPROM:
            ensure_eeprom();
            if (pkg.page >= EEPROM_NPAGES) {
                log_warning("iidx::ezusb2", "eeprom write overrun page {:02x}", pkg.page);
                return false;
            }
            memcpy(g_eeprom + pkg.page * EZUSB_PAGESIZE, pkg.payload, EZUSB_PAGESIZE);
            return true;
        case NODE_SECURITY_PLUG:
        case NODE_NONE:
        case NODE_16SEG:
        case NODE_FPGA_V2:
        case NODE_WDT:
            // accept and discard FPGA firmware / wdt pages
            return true;
        default:
            log_warning("iidx::ezusb2", "bulk write unsupported on node {:02x}", pkg.node);
            return false;
    }
}

int ioctl_get_device_descriptor(LPVOID lpOutBuffer, DWORD nOutBufferSize) {
    if (nOutBufferSize < sizeof(UsbDeviceDescriptor) || !lpOutBuffer) {
        return -1;
    }

    UsbDeviceDescriptor desc {};
    desc.bLength = sizeof(desc);
    desc.bDescriptorType = 0x01;
    if (is_fx2_packet()) {
        desc.idVendor = EZUSB_VID_FX2;
        desc.idProduct = EZUSB_PID_FX2;
    } else {
        desc.idVendor = EZUSB_VID_2235;
        desc.idProduct = EZUSB_PID_2235;
    }
    memcpy(lpOutBuffer, &desc, sizeof(desc));
    return static_cast<int>(sizeof(desc));
}

int ioctl_vendor_request(LPVOID lpInBuffer, DWORD nInBufferSize) {
    if (nInBufferSize < sizeof(VendorOrClassRequestControl) || !lpInBuffer) {
        return -1;
    }

    auto *vc = reinterpret_cast<VendorOrClassRequestControl *>(lpInBuffer);
    if (vc->request == 0x00 && vc->value == 0x0001 && vc->index == 0x0100) {
        log_info("iidx::ezusb2", "vendor req: reset hold");
        return 0;
    }
    if (vc->request == 0x00 && vc->value == 0x0001 && vc->index == 0x0000) {
        log_info("iidx::ezusb2", "vendor req: reset release");
        return 0;
    }

    log_warning("iidx::ezusb2", "unknown vendor req {:02x} value {:04x} index {:04x}",
            vc->request, vc->value, vc->index);
    return 0;
}

int ioctl_anchor_download(LPVOID lpInBuffer, DWORD nInBufferSize,
        DWORD nOutBufferSize) {
    if (nInBufferSize < sizeof(AnchorDownloadControl) || !lpInBuffer) {
        return -1;
    }
    // Accept firmware chunk; do not execute it
    return static_cast<int>(nOutBufferSize);
}

int ioctl_pipe_read(LPVOID lpInBuffer, DWORD nInBufferSize,
        LPVOID lpOutBuffer, DWORD nOutBufferSize) {
    if (nInBufferSize < sizeof(BulkTransferControl) || !lpInBuffer) {
        return -1;
    }

    auto *ctl = reinterpret_cast<BulkTransferControl *>(lpInBuffer);
    switch (ctl->pipe_num) {
        case PIPE_INT_IN:
            if (!interrupt_read(lpOutBuffer, nOutBufferSize)) {
                return -1;
            }
            // Report the packet size, not the caller's buffer (bemani read.pos).
            // FX2 needs the full 64 bytes or SQ-INIT fails on a short transfer.
            return is_fx2_packet()
                    ? static_cast<int>(sizeof(Fx2InterruptReadPacket))
                    : static_cast<int>(sizeof(InterruptReadPacket));
        case PIPE_BULK_IN:
            if (!bulk_read(lpOutBuffer, nOutBufferSize)) {
                return -1;
            }
            return static_cast<int>(sizeof(BulkPacket));
        default:
            log_warning("iidx::ezusb2", "no such read pipe {}", ctl->pipe_num);
            return -1;
    }
}

int ioctl_pipe_write(LPVOID lpInBuffer, DWORD nInBufferSize,
        LPVOID lpOutBuffer, DWORD nOutBufferSize) {
    if (nInBufferSize < sizeof(BulkTransferControl) || !lpInBuffer) {
        return -1;
    }

    auto *ctl = reinterpret_cast<BulkTransferControl *>(lpInBuffer);
    // METHOD_IN_DIRECT: payload is in lpOutBuffer (bemani/ezusb quirk)
    switch (ctl->pipe_num) {
        case PIPE_INT_OUT:
            if (!interrupt_write(lpOutBuffer, nOutBufferSize)) {
                return -1;
            }
            return static_cast<int>(nOutBufferSize);
        case PIPE_BULK_OUT:
            if (!bulk_write(lpOutBuffer, nOutBufferSize)) {
                return -1;
            }
            return static_cast<int>(nOutBufferSize);
        default:
            log_warning("iidx::ezusb2", "no such write pipe {}", ctl->pipe_num);
            return -1;
    }
}

} // namespace

bool EZUSB2Handle::open(LPCWSTR lpFileName) {
    return wcscmp(lpFileName, L"\\\\.\\Ezusb-0") == 0;
}

int EZUSB2Handle::read(LPVOID, DWORD) {
    return -1;
}

int EZUSB2Handle::write(LPCVOID, DWORD) {
    return -1;
}

bool EZUSB2Handle::close() {
    return true;
}

int EZUSB2Handle::device_io(DWORD dwIoControlCode, LPVOID lpInBuffer, DWORD nInBufferSize,
        LPVOID lpOutBuffer, DWORD nOutBufferSize) {

    switch (dwIoControlCode) {
        case IOCTL_EZUSB_GET_DEVICE_DESCRIPTOR:
            return ioctl_get_device_descriptor(lpOutBuffer, nOutBufferSize);

        case IOCTL_EZUSB_VENDOR_REQUEST:
            return ioctl_vendor_request(lpInBuffer, nInBufferSize);

        case IOCTL_EZUSB_ANCHOR_DOWNLOAD:
        case IOCTL_EZUSB_ANCHOR_DOWNLOAD_BUF:
            return ioctl_anchor_download(lpInBuffer, nInBufferSize, nOutBufferSize);

        case IOCTL_EZUSB_BULK_READ:
            return ioctl_pipe_read(lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize);

        case IOCTL_EZUSB_BULK_WRITE:
            return ioctl_pipe_write(lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize);

        default:
            log_warning("iidx::ezusb2", "unknown ioctl {:08x}", dwIoControlCode);
            return -1;
    }
}

}
