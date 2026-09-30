#include "ezusb_serial.h"

#include <cstring>
#include <iterator>
#include <mutex>
#include <vector>

#include "avs/game.h"
#include "misc/eamuse.h"
#include "util/logging.h"

namespace games::iidx::ezusb_serial {
namespace {

constexpr size_t kPage = 62;
constexpr size_t kBuf = 512;
constexpr size_t kHdr = 4; // msg_cmd, node_id, node_cmd, payload_len
constexpr uint8_t HEADER_BYTE = 0xAA;
constexpr uint8_t CMD_NODE_REQ = 0x00;
constexpr uint8_t CMD_NODE_RESP = 0x01;
constexpr uint8_t CMD_H8_REQ = 0xAA;
constexpr uint8_t CMD_H8_RESP = 0xA5;
constexpr uint8_t H8_NODE_ENUM = 0x01;
constexpr uint8_t H8_GET_VERSION = 0x02;
constexpr uint8_t H8_PROG_EXEC = 0x03;
constexpr uint8_t NODE_CARD_INIT = 0x00;
constexpr uint8_t NODE_KEYBOARD_INIT = 0x10;
constexpr uint8_t NODE_CARD_RW_STATUS = 0x12;
constexpr uint8_t NODE_CARD_SLOT_STATE = 0x14;
constexpr uint8_t NODE_CARD_WRITE = 0x16;
constexpr uint8_t NODE_CARD_READ = 0x18;
constexpr uint8_t NODE_CARD_FORMAT_DONE = 0x1E;
constexpr uint8_t NODE_CARD_GET_STATUS = 0x20;
constexpr uint8_t NODE_KEYBOARD_GET_STATUS = 0x24;
constexpr uint8_t NODE_KEYBOARD_READ = 0x26;
constexpr uint8_t NODE_KEYBOARD_BUF_SIZE = 0x27;
constexpr uint8_t SERIAL_OK = 0x00;
constexpr uint8_t SERIAL_FAULT = 0xFE;

#pragma pack(push, 1)
struct SerialMsg {
    uint8_t msg_cmd;
    uint8_t node_id;
    uint8_t node_cmd;
    uint8_t payload_len;
    uint8_t payload[255];
};
#pragma pack(pop)

std::mutex g_mu;
bool g_read_busy = false;
bool g_write_busy = false;
uint8_t g_read_buf[kBuf] {};
uint8_t g_write_buf[kBuf] {};
uint16_t g_read_len = 0;
uint16_t g_write_len = 0;
uint8_t g_read_page = 0;
uint8_t g_write_page = 0;

struct Slot {
    bool card_present = false;
    uint8_t card_id[8] {};
    uint8_t keypad_code = 0;
    uint16_t last_keypad = 0;
    uint8_t card_slot_state = 0;
    bool write_loopback_valid = false;
    uint8_t write_loopback[128] {};
};
Slot g_slot[2] {};

#pragma pack(push, 1)
struct MagCardData {
    struct {
        uint8_t flags;
        uint8_t card_version[3];
        uint8_t checksum;
    } header;
    struct {
        uint8_t card_id[8];
        uint8_t card_type;
        uint8_t checksum;
    } sector[5];
    uint8_t padding[8];
    uint8_t checksum[2];
};
#pragma pack(pop)

uint8_t crc8(const uint8_t *data, size_t len) {
    uint8_t crc = 0xFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int bit = 0; bit < 8; bit++) {
            crc = (crc & 1) ? static_cast<uint8_t>((crc >> 1) ^ 0x8C) : crc >> 1;
        }
    }
    return static_cast<uint8_t>(~crc);
}

uint16_t crc16_reflected(const uint8_t *data, size_t len, bool complement) {
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int bit = 0; bit < 8; bit++) {
            crc = (crc & 1) ? static_cast<uint16_t>((crc >> 1) ^ 0x8408) : crc >> 1;
        }
    }
    return complement ? static_cast<uint16_t>(~crc) : crc;
}

const char *card_version() {
    if (avs::game::is_model("D01")) return "D01";
    if (avs::game::is_model("E11")) return "E11";
    if (avs::game::is_model("ECO")) return "ECO";
    return "C02";
}

void generate_mag_card(uint8_t *out, const uint8_t card_id[8]) {
    MagCardData card {};
    const char *version = card_version();

    card.header.flags = (1 << 3) | (1 << 6);
    card.header.card_version[2] = 1;
    card.header.card_version[0] =
            (card.header.card_version[0] & 0xC0) | ((version[0] - 0x20) & 0x3F);
    card.header.card_version[1] =
            static_cast<uint8_t>(((version[1] - 0x20) & 0x3F) << 2)
            | static_cast<uint8_t>(((version[2] - 0x20) >> 4) & 0x03);
    card.header.card_version[2] =
            static_cast<uint8_t>(((version[2] - 0x20) & 0x0F) << 4)
            | (card.header.card_version[2] & 0x0F);
    card.header.checksum = crc8(&card.header.flags, 4);

    uint8_t reversed[8];
    for (int i = 0; i < 8; i++) {
        reversed[7 - i] = card_id[i];
    }
    for (auto &sector : card.sector) {
        auto *raw = reinterpret_cast<uint8_t *>(&sector);
        if (strcmp(version, "C02") == 0) {
            raw[0] = 0; // 9th stores card type before the id
            memcpy(raw + 1, reversed, sizeof(reversed));
        } else {
            memcpy(raw, reversed, sizeof(reversed));
            raw[8] = 0;
        }
        raw[9] = crc8(raw, 9);
    }

    const auto *payload = reinterpret_cast<const uint8_t *>(&card.sector[0]);
    // 10th uses the raw reflected result; 9th/RED/HS complement it.
    const uint16_t whole_crc = crc16_reflected(
            payload, sizeof(card.sector) + sizeof(card.padding),
            strcmp(version, "D01") != 0);
    memcpy(card.checksum, &whole_crc, sizeof(whole_crc));
    memcpy(out, &card, sizeof(card));
}

uint8_t keypad_scan_code(uint8_t bit) {
    static constexpr uint8_t codes[12] = {
            0x70, // raw 0: 0
            0x69, // raw 1: 1
            0x6B, // raw 2: 4
            0x6C, // raw 3: 7
            0x70, // raw 4: 00 (use 0)
            0x72, // raw 5: 2
            0x73, // raw 6: 5
            0x75, // raw 7: 8
            0x00, // raw 8: decimal (unsupported by the reader)
            0x7A, // raw 9: 3
            0x74, // raw 10: 6
            0x7D, // raw 11: 9
    };
    return bit < std::size(codes) ? codes[bit] : 0;
}

uint8_t checksum(const uint8_t *data, uint16_t len) {
    uint8_t sum = 0;
    for (uint16_t i = 0; i < len; i++) {
        sum += data[i];
    }
    return sum;
}

void poll_slot(uint8_t node) {
    if (node < 1 || node > 2) {
        return;
    }
    Slot &s = g_slot[node - 1];
    const size_t unit = node - 1;

    // Card insert edge from spice overlay / file
    if (eamuse_card_insert_consume(2, static_cast<int>(unit))) {
        if (eamuse_get_card(2, static_cast<int>(unit), s.card_id)) {
            s.card_present = true;
        }
    }

    const uint16_t kp = eamuse_get_keypad_state(unit);
    const uint16_t rise = kp & (s.last_keypad ^ kp);
    s.last_keypad = kp;
    if (rise) {
        // Lowest set bit index as a simple scan code for the H8 path
        for (uint8_t i = 0; i < 16; i++) {
            if (rise & (1u << i)) {
                s.keypad_code = keypad_scan_code(i);
                break;
            }
        }
    }
}

// Inner SerialMsg only (no 0xAA frame, no trailing checksum).
// payload_bytes may exceed payload_len_field (GET_VERSION quirk in ezusb).
void build_inner(std::vector<uint8_t> &out, uint8_t msg_cmd, uint8_t node_id,
        uint8_t node_cmd, uint8_t payload_len_field,
        const uint8_t *payload, uint8_t payload_bytes) {
    out.clear();
    out.push_back(msg_cmd);
    out.push_back(node_id);
    out.push_back(node_cmd);
    out.push_back(payload_len_field);
    for (uint8_t i = 0; i < payload_bytes; i++) {
        out.push_back(payload[i]);
    }
}

void build_status(std::vector<uint8_t> &out, uint8_t msg_cmd, uint8_t node_id,
        uint8_t node_cmd) {
    const uint8_t st = 0;
    build_inner(out, msg_cmd, node_id, node_cmd, 1, &st, 1);
}

bool handle_msg(const SerialMsg *in, uint16_t in_len, std::vector<uint8_t> &out) {
    if (in_len < kHdr) {
        return false;
    }

    if (in->msg_cmd == CMD_H8_REQ) {
        if (in->node_cmd == H8_NODE_ENUM) {
            const uint8_t total = 2;
            build_inner(out, CMD_H8_RESP, 0, in->node_cmd, 1, &total, 1);
            return true;
        }
        if (in->node_cmd == H8_GET_VERSION) {
            // payload_len field is 5, but the body is the full 13-byte struct
            // (uint32 type, dup, maj/min/rev, comment[5]) — bemanitools match.
            uint8_t ver[13] = {
                    0x03, 0x00, 0x00, 0x00,
                    0x00,
                    1, 6, 0,
                    'I', 'C', 'C', 'A', 0,
            };
            build_inner(out, CMD_H8_RESP, in->node_id, in->node_cmd, 5, ver, 13);
            return true;
        }
        if (in->node_cmd == H8_PROG_EXEC) {
            build_status(out, CMD_H8_RESP, in->node_id, in->node_cmd);
            return true;
        }
        log_warning("iidx::serial", "unknown H8 cmd {:02x}", in->node_cmd);
        return false;
    }

    if (in->msg_cmd != CMD_NODE_REQ) {
        log_warning("iidx::serial", "unknown msg_cmd {:02x}", in->msg_cmd);
        return false;
    }

    poll_slot(in->node_id);
    const uint8_t node = in->node_id;
    Slot *slot = (node >= 1 && node <= 2) ? &g_slot[node - 1] : nullptr;

    switch (in->node_cmd) {
        case NODE_CARD_INIT:
        case NODE_KEYBOARD_INIT:
        case NODE_CARD_GET_STATUS:
        case NODE_KEYBOARD_GET_STATUS:
        case NODE_CARD_FORMAT_DONE:
            build_status(out, CMD_NODE_RESP, node, in->node_cmd);
            return true;
        case NODE_CARD_RW_STATUS: {
            uint8_t st = 0;
            if (slot && slot->card_present) {
                st = static_cast<uint8_t>(128 | 2); // back sensor + present
            }
            build_inner(out, CMD_NODE_RESP, node, in->node_cmd, 1, &st, 1);
            return true;
        }
        case NODE_CARD_SLOT_STATE: {
            if (slot && in->payload_len >= 1) {
                const uint8_t state = in->payload[0];
                slot->card_slot_state = state;
                if (state == 2 /* eject */) {
                    slot->card_present = false;
                }
            }
            build_status(out, CMD_NODE_RESP, node, in->node_cmd);
            return true;
        }
        case NODE_CARD_WRITE: {
            if (slot && in_len >= kHdr + 128) {
                memcpy(slot->write_loopback, in->payload, sizeof(slot->write_loopback));
                slot->write_loopback_valid = true;
            }
            build_status(out, CMD_NODE_RESP, node, in->node_cmd);
            return true;
        }
        case NODE_CARD_READ: {
            uint8_t data[1 + 128] {};
            data[0] = 0x48;
            if (slot && slot->write_loopback_valid) {
                memcpy(&data[1], slot->write_loopback, sizeof(slot->write_loopback));
                slot->write_loopback_valid = false;
            } else if (slot && slot->card_present) {
                generate_mag_card(&data[1], slot->card_id);
            }
            // The driver expects 24 in the field although 129 payload bytes follow.
            build_inner(out, CMD_NODE_RESP, node, in->node_cmd, 24, data, 129);
            return true;
        }
        case NODE_KEYBOARD_BUF_SIZE: {
            uint8_t payload[2] = {0, 0};
            if (slot && slot->keypad_code != 0) {
                payload[0] = 1; // little-endian uint16 size type
            }
            build_inner(out, CMD_NODE_RESP, node, in->node_cmd, 2, payload, 2);
            return true;
        }
        case NODE_KEYBOARD_READ: {
            uint8_t size_type = in->payload_len >= 1 ? in->payload[0] : 0;
            uint8_t payload[64] {};
            if (size_type >= 1 && slot && slot->keypad_code != 0) {
                payload[0] = slot->keypad_code;
                slot->keypad_code = 0;
            }
            static constexpr uint8_t sizes[] = {0, 1, 2, 4, 8, 16, 32, 64};
            const uint8_t payload_bytes =
                    size_type < std::size(sizes) ? sizes[size_type] : 0;
            build_inner(out, CMD_NODE_RESP, node, in->node_cmd,
                    size_type, payload, payload_bytes);
            return true;
        }
        default:
            log_warning("iidx::serial", "unknown node cmd {:02x}", in->node_cmd);
            build_status(out, CMD_NODE_RESP, node, in->node_cmd);
            return true;
    }
}

void set_read_buf(const uint8_t *data, size_t len) {
    if (len > kBuf) {
        log_warning("iidx::serial", "response too large {}", len);
        g_write_len = 0;
        return;
    }
    memcpy(g_read_buf, data, len);
    g_read_len = static_cast<uint16_t>(len);
    g_read_page = 0;
    g_read_busy = true;
    g_write_len = 0;
}

void exec_write_buf() {
    if (g_write_len == 0) {
        return;
    }

    // Match bemanitools: echo null-prefixed trash, and the short uart init
    // that is four bytes starting with 0xAA, unchanged.
    if (g_write_buf[0] == 0x00
            || (g_write_len == 4 && g_write_buf[0] == HEADER_BYTE)) {
        set_read_buf(g_write_buf, g_write_len);
        return;
    }

    if (g_write_buf[0] != HEADER_BYTE) {
        log_warning("iidx::serial", "frame missing 0xAA header");
        g_write_len = 0;
        return;
    }
    if (g_write_len < 3) {
        g_write_len = 0;
        return;
    }
    if (g_write_buf[g_write_len - 1]
            != checksum(g_write_buf + 1, static_cast<uint16_t>(g_write_len - 2))) {
        log_warning("iidx::serial", "invalid serial checksum");
        g_write_len = 0;
        return;
    }

    const uint8_t *msg_buf = g_write_buf + 1;
    const uint16_t msg_len = static_cast<uint16_t>(g_write_len - 2);

    // UART reset: echo AA AA with framing
    if (msg_len == 2 && msg_buf[0] == HEADER_BYTE && msg_buf[1] == HEADER_BYTE) {
        uint8_t frame[4] = {HEADER_BYTE, HEADER_BYTE, HEADER_BYTE, 0};
        frame[3] = checksum(frame + 1, 2);
        set_read_buf(frame, 4);
        return;
    }

    auto *msg = reinterpret_cast<const SerialMsg *>(msg_buf);
    std::vector<uint8_t> inner;
    if (!handle_msg(msg, msg_len, inner) || inner.empty()) {
        g_write_len = 0;
        return;
    }

    std::vector<uint8_t> frame;
    if (msg->msg_cmd == CMD_H8_REQ && msg->node_cmd == H8_NODE_ENUM) {
        // Node enum: response only (no request echo)
        frame.push_back(HEADER_BYTE);
        frame.insert(frame.end(), inner.begin(), inner.end());
        frame.push_back(checksum(inner.data(), static_cast<uint16_t>(inner.size())));
    } else {
        // Everything else: request echo, then framed response
        frame.insert(frame.end(), g_write_buf, g_write_buf + g_write_len);
        frame.push_back(HEADER_BYTE);
        frame.insert(frame.end(), inner.begin(), inner.end());
        frame.push_back(checksum(inner.data(), static_cast<uint16_t>(inner.size())));
    }

    set_read_buf(frame.data(), frame.size());
}

} // namespace

void init() {
    std::lock_guard lock(g_mu);
    g_read_busy = false;
    g_write_busy = false;
    g_read_len = 0;
    g_write_len = 0;
    g_read_page = 0;
    g_write_page = 0;
    memset(g_read_buf, 0, sizeof(g_read_buf));
    memset(g_write_buf, 0, sizeof(g_write_buf));
    g_slot[0] = {};
    g_slot[1] = {};
}

uint8_t process_cmd(uint8_t cmd) {
    std::lock_guard lock(g_mu);
    switch (cmd) {
        case 0x02: // READ_BUFFER
            g_read_busy = false;
            g_read_page = 0;
            return SERIAL_OK;
        case 0x03: // WRITE_BUFFER
            g_write_busy = false;
            g_write_page = 0;
            return SERIAL_OK;
        case 0x04: // CLEAR_READ
            g_read_busy = false;
            g_read_page = 0;
            g_read_len = 0;
            return SERIAL_OK;
        case 0x05: // CLEAR_WRITE
            g_write_busy = false;
            g_write_page = 0;
            g_write_len = 0;
            return SERIAL_OK;
        default:
            log_warning("iidx::serial", "unknown serial cmd {:02x}", cmd);
            return SERIAL_FAULT;
    }
}

bool read_packet(uint8_t *pkg60) {
    std::lock_guard lock(g_mu);
    // BulkPacket: node, page, payload[62]
    pkg60[0] = 0x42;
    pkg60[1] = g_read_page;
    memset(pkg60 + 2, 0xFF, kPage);

    const uint16_t offset = static_cast<uint16_t>(g_read_page * kPage);
    uint16_t data_length = 0;
    if (g_read_len >= kPage) {
        data_length = kPage;
        g_read_len = static_cast<uint16_t>(g_read_len - kPage);
        g_read_page++;
    } else {
        data_length = g_read_len;
        pkg60[1] = static_cast<uint8_t>(0x40 + data_length);
        g_read_len = 0;
    }
    if (data_length) {
        memcpy(pkg60 + 2, g_read_buf + offset, data_length);
    }
    return true;
}

bool write_packet(const uint8_t *pkg60) {
    std::lock_guard lock(g_mu);
    const uint8_t page = pkg60[1];
    const uint8_t *payload = pkg60 + 2;
    bool execute = false;
    uint16_t data_length = 0;
    const uint16_t offset = static_cast<uint16_t>(g_write_page * kPage);

    if (page >= 0x42) {
        data_length = static_cast<uint16_t>(page - 0x42);
        execute = true;
    } else {
        data_length = kPage;
        g_write_page++;
    }

    if (offset + data_length > kBuf) {
        log_warning("iidx::serial", "write buffer overrun");
        return false;
    }
    memcpy(g_write_buf + offset, payload, data_length);
    g_write_len = static_cast<uint16_t>(g_write_len + data_length);

    if (execute) {
        exec_write_buf();
        g_write_page = 0;
    }
    return true;
}

bool read_busy() {
    std::lock_guard lock(g_mu);
    return g_read_busy;
}

bool write_busy() {
    std::lock_guard lock(g_mu);
    return g_write_busy;
}

} // namespace games::iidx::ezusb_serial
