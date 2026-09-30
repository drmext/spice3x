#include "ezusb_serial.h"

#include <atomic>
#include <chrono>
#include <cstring>
#include <iterator>
#include <mutex>
#include <thread>
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

constexpr uint8_t SLOT_CLOSE = 0;
constexpr uint8_t SLOT_OPEN = 1;
constexpr uint8_t SLOT_EJECT = 2;
constexpr uint8_t SLOT_FORMAT = 3;
constexpr uint8_t SLOT_READ = 4;
constexpr uint8_t SLOT_WRITE = 5;

enum class EmuState : uint8_t {
    Uninit = 0,
    Init = 1,
    Loop = 2,
    ReqCard = 3,
    CardRead = 4,
    Error = 5,
};

#pragma pack(push, 1)
struct SerialMsg {
    uint8_t msg_cmd;
    uint8_t node_id;
    uint8_t node_cmd;
    uint8_t payload_len;
    uint8_t payload[255];
};

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
    EmuState emu = EmuState::Uninit;
    bool sensor_front = false;
    bool sensor_back = false;
    uint8_t card_id[8] {};
    uint8_t keypad_code = 0;
    uint16_t last_keypad = 0;
    uint8_t card_slot_state = SLOT_CLOSE;
    bool write_loopback_valid = false;
    uint8_t write_loopback[128] {};
};
Slot g_slot[2] {};
std::atomic<bool> g_poll_run{false};
std::thread g_poll_thread;

uint8_t keypad_scan_code(uint8_t bit);

void poll_keypad_locked(uint8_t node) {
    if (node < 1 || node > 2) {
        return;
    }
    Slot &s = g_slot[node - 1];
    const size_t unit = node - 1;
    const uint16_t kp = eamuse_get_keypad_state(unit);
    const uint16_t rise = kp & static_cast<uint16_t>(~s.last_keypad);
    s.last_keypad = kp;
    // Only latch a new code when the buffer is empty; keep last_keypad updated
    // so a held key does not re-fire, matching bemanitools' single-byte buffer.
    if (rise && s.keypad_code == 0) {
        for (uint8_t i = 0; i < 12; i++) {
            if (rise & (1u << i)) {
                const uint8_t code = keypad_scan_code(i);
                if (code != 0) {
                    s.keypad_code = code;
                }
                break;
            }
        }
    }
}

void poll_thread_main() {
    // bemanitools node-serial emu thread: sample eamio ~100Hz so brief keypad
    // presses are not missed between rare KEYBOARD_* serial commands.
    while (g_poll_run.load(std::memory_order_relaxed)) {
        {
            std::lock_guard lock(g_mu);
            poll_keypad_locked(1);
            poll_keypad_locked(2);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

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
    // bemanitools eamio_mapping order: 0 1 4 7 O 2 5 8 E 3 6 9
    static constexpr uint8_t codes[12] = {
            0x70, // 0
            0x69, // 1
            0x6B, // 4
            0x6C, // 7
            0x70, // 00 -> 0
            0x72, // 2
            0x73, // 5
            0x75, // 8
            0x66, // backspace / E
            0x7A, // 3
            0x74, // 6
            0x7D, // 9
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

void clear_card(Slot &s) {
    memset(s.card_id, 0, sizeof(s.card_id));
    s.sensor_front = false;
    s.sensor_back = false;
}

bool card_id_valid(const uint8_t id[8]) {
    for (int i = 0; i < 8; i++) {
        if (id[i] != 0) {
            return true;
        }
    }
    return false;
}

void try_read_card(Slot &s, size_t unit) {
    if (s.emu != EmuState::ReqCard) {
        return;
    }
    // Prefer an id already captured while the slot was OPEN; otherwise poll eamuse.
    if (!card_id_valid(s.card_id)) {
        eamuse_get_card(2, static_cast<int>(unit), s.card_id);
    }
    if (card_id_valid(s.card_id)) {
        s.sensor_front = true;
        s.sensor_back = true;
        s.emu = EmuState::CardRead;
        log_info("iidx::serial", "node {} card read ok", unit + 1);
    } else {
        clear_card(s);
        s.emu = EmuState::Error;
        log_warning("iidx::serial", "node {} card read failed", unit + 1);
    }
}

void poll_slot(uint8_t node) {
    if (node < 1 || node > 2) {
        return;
    }
    Slot &s = g_slot[node - 1];
    const size_t unit = node - 1;

    // Accept overlay/file inserts only while the slot is open.
    if (s.card_slot_state == SLOT_OPEN
            && eamuse_card_insert_consume(2, static_cast<int>(unit))) {
        if (eamuse_get_card(2, static_cast<int>(unit), s.card_id)) {
            s.sensor_front = true;
            s.sensor_back = true;
            log_info("iidx::serial", "node {} card inserted (slot open)", node);
        }
    }

    // Complete a pending READ request without a background card thread.
    if (s.card_slot_state == SLOT_READ) {
        try_read_card(s, unit);
    }

    // Keypad is sampled on the poll thread; keep a pass here so serial-only
    // paths still work if the thread is not running yet.
    poll_keypad_locked(node);
}

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
        uint8_t node_cmd, uint8_t status = 0) {
    build_inner(out, msg_cmd, node_id, node_cmd, 1, &status, 1);
}

bool handle_msg(const SerialMsg *in, uint16_t in_len, std::vector<uint8_t> &out) {
    if (in_len < kHdr) {
        return false;
    }

    if (in->msg_cmd == CMD_H8_REQ) {
        if (in->node_cmd == H8_NODE_ENUM) {
            const uint8_t total = 2;
            log_misc("iidx::serial", "H8_NODE_ENUM");
            build_inner(out, CMD_H8_RESP, 0, in->node_cmd, 1, &total, 1);
            return true;
        }
        if (in->node_cmd == H8_GET_VERSION) {
            // payload_len field is 5, but the body is the full 13-byte struct.
            uint8_t ver[13] = {
                    0x03, 0x00, 0x00, 0x00,
                    0x00,
                    1, 6, 0,
                    'I', 'C', 'C', 'A', 0,
            };
            log_misc("iidx::serial", "H8_GET_VERSION node {}", in->node_id);
            build_inner(out, CMD_H8_RESP, in->node_id, in->node_cmd, 5, ver, 13);
            return true;
        }
        if (in->node_cmd == H8_PROG_EXEC) {
            uint8_t status = 0;
            if (in->node_id >= 1 && in->node_id <= 2) {
                Slot &s = g_slot[in->node_id - 1];
                if (s.emu == EmuState::Uninit) {
                    // bemanitools waits for a thread INIT->LOOP; do it inline.
                    s.emu = EmuState::Loop;
                    log_misc("iidx::serial", "H8_PROG_EXEC node {} -> LOOP", in->node_id);
                } else if (s.emu == EmuState::Error) {
                    status = 0xFF;
                    log_warning("iidx::serial", "H8_PROG_EXEC node {} in ERROR", in->node_id);
                } else {
                    log_misc("iidx::serial", "H8_PROG_EXEC node {} ok (state {})",
                            in->node_id, static_cast<int>(s.emu));
                }
            }
            build_status(out, CMD_H8_RESP, in->node_id, in->node_cmd, status);
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
            log_misc("iidx::serial", "CARD_INIT node {}", node);
            build_status(out, CMD_NODE_RESP, node, in->node_cmd);
            return true;
        case NODE_KEYBOARD_INIT:
            log_misc("iidx::serial", "KEYBOARD_INIT node {}", node);
            build_status(out, CMD_NODE_RESP, node, in->node_cmd);
            return true;
        case NODE_CARD_GET_STATUS:
        case NODE_KEYBOARD_GET_STATUS:
        case NODE_CARD_FORMAT_DONE:
            build_status(out, CMD_NODE_RESP, node, in->node_cmd);
            return true;
        case NODE_CARD_RW_STATUS: {
            uint8_t st = 0;
            if (slot) {
                if (slot->emu == EmuState::Error) {
                    st = 0xFF;
                } else {
                    if (slot->sensor_back) {
                        st = static_cast<uint8_t>(st | 128 | 2);
                    }
                    if (slot->sensor_front) {
                        st = static_cast<uint8_t>(st | 64 | 2);
                    }
                }
            }
            build_inner(out, CMD_NODE_RESP, node, in->node_cmd, 1, &st, 1);
            return true;
        }
        case NODE_CARD_SLOT_STATE: {
            if (slot && in->payload_len >= 1) {
                const uint8_t state = in->payload[0];
                slot->card_slot_state = state;
                switch (state) {
                    case SLOT_CLOSE:
                        log_misc("iidx::serial", "SLOT_CLOSE node {}", node);
                        break;
                    case SLOT_OPEN:
                        log_misc("iidx::serial", "SLOT_OPEN node {}", node);
                        break;
                    case SLOT_EJECT:
                        log_info("iidx::serial", "SLOT_EJECT node {}", node);
                        clear_card(*slot);
                        if (slot->emu == EmuState::Error || slot->emu == EmuState::CardRead
                                || slot->emu == EmuState::ReqCard) {
                            slot->emu = EmuState::Loop;
                        }
                        break;
                    case SLOT_FORMAT:
                        log_misc("iidx::serial", "SLOT_FORMAT node {}", node);
                        break;
                    case SLOT_READ:
                        log_misc("iidx::serial", "SLOT_READ node {}", node);
                        slot->emu = EmuState::ReqCard;
                        try_read_card(*slot, node - 1);
                        break;
                    case SLOT_WRITE:
                        log_misc("iidx::serial", "SLOT_WRITE node {}", node);
                        break;
                    default:
                        log_warning("iidx::serial", "invalid slot state {} node {}",
                                state, node);
                        break;
                }
            }
            build_status(out, CMD_NODE_RESP, node, in->node_cmd);
            return true;
        }
        case NODE_CARD_WRITE: {
            if (slot && in_len >= kHdr + 128) {
                memcpy(slot->write_loopback, in->payload, sizeof(slot->write_loopback));
                slot->write_loopback_valid = true;
                log_misc("iidx::serial", "CARD_WRITE node {} (loopback cached)", node);
            }
            build_status(out, CMD_NODE_RESP, node, in->node_cmd);
            return true;
        }
        case NODE_CARD_READ: {
            uint8_t data[1 + 128] {};
            data[0] = 0x48;
            uint8_t payload_len_field = 24;
            uint8_t payload_bytes = 129;

            if (slot && slot->write_loopback_valid) {
                memcpy(&data[1], slot->write_loopback, sizeof(slot->write_loopback));
                slot->write_loopback_valid = false;
                log_misc("iidx::serial", "CARD_READ node {} loopback", node);
            } else if (slot) {
                // Finish a pending read inline if the game asks before poll ran.
                if (slot->emu == EmuState::ReqCard) {
                    try_read_card(*slot, node - 1);
                }
                if (slot->emu == EmuState::CardRead && card_id_valid(slot->card_id)) {
                    generate_mag_card(&data[1], slot->card_id);
                    slot->emu = EmuState::Loop;
                    log_misc("iidx::serial", "CARD_READ node {} mag payload", node);
                } else if (slot->emu == EmuState::Error) {
                    // bemanitools still sends the full 129-byte body; payload_len=1
                    // and data[0]=0xFF indicate the read failure to the driver.
                    payload_len_field = 1;
                    data[1] = 0xFF;
                    log_warning("iidx::serial", "CARD_READ node {} error status", node);
                } else {
                    // Empty slot: return blank mag blob with the usual header.
                    log_misc("iidx::serial", "CARD_READ node {} empty", node);
                }
            }
            build_inner(out, CMD_NODE_RESP, node, in->node_cmd,
                    payload_len_field, data, payload_bytes);
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
            return false;
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
    // Match bemanitools node-serial.c: read/write busy flags are never raised.
    // ezusb.dll polls INT offset for busy clear after CLEAR_READ/WRITE; leaving
    // busy stuck true (or raising it on replies) breaks uart INIT0 / H8 init.
    g_read_busy = false;
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
        log_misc("iidx::serial", "uart echo (trash/init) len={}", g_write_len);
        set_read_buf(g_write_buf, g_write_len);
        return;
    }

    if (g_write_buf[0] != HEADER_BYTE) {
        log_warning("iidx::serial", "frame missing 0xAA header (len {})", g_write_len);
        g_write_len = 0;
        return;
    }
    if (g_write_len < 3) {
        log_warning("iidx::serial", "frame too short ({})", g_write_len);
        g_write_len = 0;
        return;
    }
    if (g_write_buf[g_write_len - 1]
            != checksum(g_write_buf + 1, static_cast<uint16_t>(g_write_len - 2))) {
        log_warning("iidx::serial", "invalid serial checksum (len {})", g_write_len);
        g_write_len = 0;
        return;
    }

    const uint8_t *msg_buf = g_write_buf + 1;
    const uint16_t msg_len = static_cast<uint16_t>(g_write_len - 2);

    // UART reset: echo AA AA with framing
    if (msg_len == 2 && msg_buf[0] == HEADER_BYTE && msg_buf[1] == HEADER_BYTE) {
        uint8_t frame[4] = {HEADER_BYTE, HEADER_BYTE, HEADER_BYTE, 0};
        frame[3] = checksum(frame + 1, 2);
        log_misc("iidx::serial", "uart reset AA AA echo");
        set_read_buf(frame, 4);
        return;
    }

    auto *msg = reinterpret_cast<const SerialMsg *>(msg_buf);
    std::vector<uint8_t> inner;
    if (!handle_msg(msg, msg_len, inner) || inner.empty()) {
        log_warning("iidx::serial",
                "dropped serial frame msg={:02x} node={} cmd={:02x} len={}",
                msg->msg_cmd, msg->node_id, msg->node_cmd, msg_len);
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

    log_misc("iidx::serial", "reply msg={:02x} node={} cmd={:02x} out={}",
            msg->msg_cmd, msg->node_id, msg->node_cmd, frame.size());
    set_read_buf(frame.data(), frame.size());
}

} // namespace

void reset_buffers() {
    std::lock_guard lock(g_mu);
    g_read_busy = false;
    g_write_busy = false;
    g_read_len = 0;
    g_write_len = 0;
    g_read_page = 0;
    g_write_page = 0;
    memset(g_read_buf, 0, sizeof(g_read_buf));
    memset(g_write_buf, 0, sizeof(g_write_buf));
}

void init() {
    // Stop a previous poll thread if init() is called again (ezusb reopen).
    if (g_poll_run.exchange(false)) {
        if (g_poll_thread.joinable()) {
            g_poll_thread.join();
        }
    }

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
    log_info("iidx::serial", "magnetic reader emulation initialized");

    g_poll_run = true;
    g_poll_thread = std::thread(poll_thread_main);
}

uint8_t process_cmd(uint8_t cmd) {
    std::lock_guard lock(g_mu);
    log_misc("iidx::serial", "process_cmd {:02x} read_len={}", cmd, g_read_len);
    switch (cmd) {
        case 0x02: // READ_BUFFER
            g_read_busy = false;
            g_read_page = 0;
            return SERIAL_OK;
        case 0x03: // WRITE_BUFFER
            g_write_busy = false;
            g_write_page = 0;
            return SERIAL_OK;
        case 0x04: // CLEAR_READ — bemanitools clears busy/page only
            g_read_busy = false;
            g_read_page = 0;
            return SERIAL_OK;
        case 0x05: // CLEAR_WRITE — bemanitools clears busy/page only
            g_write_busy = false;
            g_write_page = 0;
            return SERIAL_OK;
        default:
            log_warning("iidx::serial", "unknown serial cmd {:02x}", cmd);
            return SERIAL_FAULT;
    }
}

bool read_packet(uint8_t *packet) {
    std::lock_guard lock(g_mu);
    // BulkPacket: node, page, payload[62]
    packet[0] = 0x42;
    packet[1] = g_read_page;
    memset(packet + 2, 0xFF, kPage);

    const uint16_t offset = static_cast<uint16_t>(g_read_page * kPage);
    uint16_t data_length = 0;
    if (g_read_len >= kPage) {
        data_length = kPage;
        g_read_len = static_cast<uint16_t>(g_read_len - kPage);
        g_read_page++;
    } else {
        data_length = g_read_len;
        packet[1] = static_cast<uint8_t>(0x40 + data_length);
        g_read_len = 0;
    }
    if (data_length) {
        memcpy(packet + 2, g_read_buf + offset, data_length);
    }
    return true;
}

bool write_packet(const uint8_t *packet) {
    std::lock_guard lock(g_mu);
    const uint8_t page = packet[1];
    const uint8_t *payload = packet + 2;
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
        log_misc("iidx::serial", "serial write exec page={:02x} len={}", page, g_write_len);
        exec_write_buf();
        // bemanitools only clears write_buf_data_len here; WRITE_BUFFER /
        // CLEAR_WRITE reset the page. Keep page sticky across execute.
        g_write_len = 0;
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
