#include "ezusb2.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <string>
#include <vector>

#include "avs/ea3.h"
#include "external/hash-library/md5.h"
#include "games/iidx/iidx.h"
#include "games/iidx/io.h"
#include "rawinput/rawinput.h"
#include "util/logging.h"
#include "util/utils.h"

namespace games::iidx {
namespace {

// CTL_CODE(FILE_DEVICE_UNKNOWN, 8/9, METHOD_BUFFERED, FILE_ANY_ACCESS)
constexpr DWORD IOCTL_ADAPT_SEND_EP0_CONTROL_TRANSFER = 0x220020;
constexpr DWORD IOCTL_ADAPT_SEND_NON_EP0_TRANSFER = 0x220024;

constexpr uint8_t PIPE_INT_OUT = 0x01;
constexpr uint8_t PIPE_BULK_OUT = 0x02;
constexpr uint8_t PIPE_INT_IN = 0x81;
constexpr uint8_t PIPE_BULK_IN = 0x86;

constexpr uint16_t FX2_VID = 0x04B4;
constexpr uint16_t FX2_PID = 0x8613;

constexpr size_t EZUSB_PAGESIZE = 62;
constexpr size_t SECURITY2_NPAGES = 5;
constexpr size_t MAX_IOCTL_BUFFER = 4096;

enum NodeId : uint8_t {
    NODE_NONE = 0x00,
    NODE_SECURITY_PLUG = 0x01,
    NODE_16SEG = 0x05,
    NODE_COIN = 0x09,
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

#pragma pack(push, 1)
struct SetupPacket {
    uint8_t bmRequest;
    uint8_t bRequest;
    uint16_t wValue;
    uint16_t wIndex;
    uint16_t wLength;
    uint32_t ulTimeOut;
};

struct SingleTransfer {
    SetupPacket setup;
    uint8_t reserved;
    uint8_t endpoint;
    uint32_t nt_status;
    uint32_t usbd_status;
    uint32_t iso_packet_offset;
    uint32_t iso_packet_length;
    uint32_t buffer_offset;
    uint32_t buffer_length;
};

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

struct UsbStringDescriptor {
    uint8_t length;
    uint8_t desc_type;
    uint16_t unicode_str[9];
};

struct InterruptWritePacket {
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

struct InterruptReadPacket {
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

static_assert(sizeof(InterruptWritePacket) == 64, "FX2 write packet size");
static_assert(sizeof(InterruptReadPacket) == 64, "FX2 read packet size");
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

uint8_t process_node_cmd(uint8_t node, uint8_t cmd, uint8_t d0, uint8_t d1) {
    switch (node) {
        case NODE_NONE:
            return 0;
        case NODE_SECURITY_PLUG:
            return process_secplug(cmd, d0);
        case NODE_SECURITY_MEM:
            return process_secmem(cmd);
        case NODE_COIN:
            return process_coin(cmd);
        case NODE_16SEG:
            return (cmd == SEG16_WRITE) ? 0x00 : 0xFE;
        default:
            log_warning("iidx::ezusb2", "unknown node {:02x}", node);
            return 0xFE;
    }
}

uint32_t build_fx2_pad() {
    uint32_t panel = 0;
    uint32_t sys = 0;
    uint32_t keys = 0;
    auto &buttons = get_buttons();

    auto pressed = [&](size_t index) {
        return GameAPI::Buttons::getState(RI_MGR, buttons.at(index));
    };

    if (pressed(Buttons::P1_Start)) panel |= 1u << 0;
    if (pressed(Buttons::P2_Start)) panel |= 1u << 1;
    if (pressed(Buttons::VEFX)) panel |= 1u << 2;
    if (pressed(Buttons::Effect)) panel |= 1u << 3;

    if (pressed(Buttons::Test)) sys |= 1u << 0;
    if (pressed(Buttons::Service)) sys |= 1u << 1;
    if (pressed(Buttons::CoinMech)) sys |= 1u << 2;

    if (pressed(Buttons::P1_1)) keys |= 1u << 0;
    if (pressed(Buttons::P1_2)) keys |= 1u << 1;
    if (pressed(Buttons::P1_3)) keys |= 1u << 2;
    if (pressed(Buttons::P1_4)) keys |= 1u << 3;
    if (pressed(Buttons::P1_5)) keys |= 1u << 4;
    if (pressed(Buttons::P1_6)) keys |= 1u << 5;
    if (pressed(Buttons::P1_7)) keys |= 1u << 6;
    if (pressed(Buttons::P2_1)) keys |= 1u << 7;
    if (pressed(Buttons::P2_2)) keys |= 1u << 8;
    if (pressed(Buttons::P2_3)) keys |= 1u << 9;
    if (pressed(Buttons::P2_4)) keys |= 1u << 10;
    if (pressed(Buttons::P2_5)) keys |= 1u << 11;
    if (pressed(Buttons::P2_6)) keys |= 1u << 12;
    if (pressed(Buttons::P2_7)) keys |= 1u << 13;

    // Match iidxhook3 interrupt pad packing, then invert
    uint32_t pad = ((keys & 0x3FFFu) << 16)
            | (panel & 0x0Fu)
            | ((sys & 0x07u) << 4)
            | (((sys >> 2) & 0x01u) << 30);
    return ~pad;
}

bool interrupt_read(uint8_t *payload, size_t nbytes, size_t *written) {
    if (nbytes < sizeof(InterruptReadPacket)) {
        return false;
    }

    InterruptReadPacket msg {};
    msg.p1_turntable = get_tt(0, false);
    msg.p2_turntable = get_tt(1, false);
    msg.sliders[0] = static_cast<uint8_t>((get_slider(1) << 4) | get_slider(0));
    msg.sliders[1] = static_cast<uint8_t>((get_slider(3) << 4) | get_slider(2));
    msg.sliders[2] = get_slider(4);
    msg.inverted_pad = build_fx2_pad();
    msg.status = g_status;
    g_status = 0;
    msg.seq_no = g_seq_no++;

    memcpy(payload, &msg, sizeof(msg));
    *written = sizeof(msg);
    return true;
}

bool interrupt_write(const uint8_t *payload, size_t nbytes) {
    if (nbytes < sizeof(InterruptWritePacket)) {
        return false;
    }

    InterruptWritePacket msg {};
    memcpy(&msg, payload, sizeof(msg));

    write_lamp(msg.deck_lights);
    write_led(msg.panel_lights);
    write_top_lamp(msg.top_lamps);
    write_top_neon(msg.top_neons);
    if (RI_MGR) {
        RI_MGR->devices_flush_output();
    }

    g_cur_node = msg.node;
    switch (msg.node) {
        case NODE_NONE:
        case NODE_SECURITY_PLUG:
        case NODE_SECURITY_MEM:
        case NODE_COIN:
        case NODE_16SEG:
            g_status = process_node_cmd(msg.node, msg.cmd, msg.cmd_detail[0],
                    msg.cmd_detail[1]);
            return true;
        default:
            g_cur_node = 0;
            log_warning("iidx::ezusb2", "unrecognised node {:02x}", msg.node);
            return false;
    }
}

bool bulk_read(uint8_t *payload, size_t nbytes, size_t *written) {
    if (nbytes < sizeof(BulkPacket)) {
        return false;
    }

    BulkPacket pkg {};
    switch (g_cur_node) {
        case NODE_SECURITY_PLUG:
            if (!read_secplug_packet(&pkg)) {
                return false;
            }
            break;
        case NODE_SECURITY_MEM:
        case NODE_NONE:
            break;
        default:
            log_warning("iidx::ezusb2", "bulk read unsupported on node {:02x}", g_cur_node);
            return false;
    }

    memcpy(payload, &pkg, sizeof(pkg));
    *written = sizeof(pkg);
    return true;
}

bool bulk_write(const uint8_t *payload, size_t nbytes) {
    if (nbytes < sizeof(BulkPacket)) {
        return false;
    }

    BulkPacket pkg {};
    memcpy(&pkg, payload, sizeof(pkg));

    switch (pkg.node) {
        case NODE_SECURITY_MEM:
            if (pkg.page >= SECURITY2_NPAGES) {
                return false;
            }
            memcpy(g_sec_mem + pkg.page * EZUSB_PAGESIZE, pkg.payload, EZUSB_PAGESIZE);
            return true;
        case NODE_SECURITY_PLUG:
        case NODE_NONE:
        case NODE_16SEG:
            return true;
        default:
            log_warning("iidx::ezusb2", "bulk write unsupported on node {:02x}", pkg.node);
            return false;
    }
}

bool ioctl_ep0(SingleTransfer *req, const uint8_t *write, size_t write_len,
        uint8_t *read, size_t read_len, size_t *read_pos) {
    if (req->setup.bmRequest == 0x80 && req->setup.bRequest == 0x06) {
        if (req->setup.wValue == 0x0100) {
            if (read_len < sizeof(UsbDeviceDescriptor)) {
                return false;
            }
            UsbDeviceDescriptor desc {};
            desc.bLength = sizeof(desc);
            desc.bDescriptorType = 0x01;
            desc.idVendor = FX2_VID;
            desc.idProduct = FX2_PID;
            memcpy(read, &desc, sizeof(desc));
            *read_pos = sizeof(desc);
            return true;
        }
        if (req->setup.wValue == 0x0301) {
            if (read_len < sizeof(UsbStringDescriptor)) {
                return false;
            }
            UsbStringDescriptor desc {};
            desc.length = sizeof(desc);
            desc.desc_type = 0x03;
            memcpy(desc.unicode_str, L"KONAMI", 12);
            memcpy(read, &desc, sizeof(desc));
            *read_pos = sizeof(desc);
            return true;
        }
        log_warning("iidx::ezusb2", "unsupported EP0 GET {:04x}", req->setup.wValue);
        return false;
    }

    if (req->setup.bmRequest == 0x40 && req->setup.bRequest == 0xA0) {
        // reset / firmware download — accept and ignore payload
        return true;
    }

    log_warning("iidx::ezusb2", "invalid EP0 {:02x}/{:02x}",
            req->setup.bmRequest, req->setup.bRequest);
    return false;
}

bool ioctl_epx(SingleTransfer *req, const uint8_t *write, size_t write_len,
        uint8_t *read, size_t read_len, size_t *read_pos) {
    switch (req->endpoint) {
        case PIPE_INT_OUT:
            return interrupt_write(write, write_len);
        case PIPE_BULK_OUT:
            return bulk_write(write, write_len);
        case PIPE_INT_IN:
            return interrupt_read(read, read_len, read_pos);
        case PIPE_BULK_IN:
            return bulk_read(read, read_len, read_pos);
        default:
            log_warning("iidx::ezusb2", "unhandled endpoint {:02x}", req->endpoint);
            return false;
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

    if (dwIoControlCode != IOCTL_ADAPT_SEND_EP0_CONTROL_TRANSFER
            && dwIoControlCode != IOCTL_ADAPT_SEND_NON_EP0_TRANSFER) {
        log_warning("iidx::ezusb2", "unknown ioctl {:08x}", dwIoControlCode);
        return -1;
    }

    const DWORD nbytes = (nInBufferSize > nOutBufferSize) ? nInBufferSize : nOutBufferSize;
    if (nbytes < sizeof(SingleTransfer) || nbytes > MAX_IOCTL_BUFFER) {
        return -1;
    }

    uint8_t local[MAX_IOCTL_BUFFER] {};
    if (lpInBuffer && nInBufferSize > 0) {
        memcpy(local, lpInBuffer, nInBufferSize);
    } else if (lpOutBuffer && nOutBufferSize > 0) {
        memcpy(local, lpOutBuffer, nOutBufferSize);
    }

    auto *req = reinterpret_cast<SingleTransfer *>(local);
    uint8_t *payload = local + sizeof(SingleTransfer);
    const size_t payload_len = nbytes - sizeof(SingleTransfer);
    size_t read_pos = 0;

    bool ok = false;
    if (dwIoControlCode == IOCTL_ADAPT_SEND_EP0_CONTROL_TRANSFER) {
        ok = ioctl_ep0(req, payload, payload_len, payload, payload_len, &read_pos);
    } else {
        ok = ioctl_epx(req, payload, payload_len, payload, payload_len, &read_pos);
    }
    if (!ok) {
        return -1;
    }

    const int result = static_cast<int>(sizeof(SingleTransfer) + read_pos);
    if (lpOutBuffer && nOutBufferSize > 0) {
        memcpy(lpOutBuffer, local, (std::min)(nOutBufferSize, static_cast<DWORD>(result)));
    }
    return result;
}

}
