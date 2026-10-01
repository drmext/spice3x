#include "icca.h"

#include "acio/icca/icca.h"
#include "avs/game.h"
#include "games/sdvx/sdvx.h"
#include "misc/eamuse.h"
#include "util/logging.h"
#include "util/precise_timer.h"
#include "util/utils.h"

using namespace acioemu;

namespace acioemu {
    bool ICCA_DEVICE_HACK = false;
}

ICCADevice::ICCADevice(bool flip_order, bool keypad_thread, uint8_t node_count) {

    // init defaults
    this->type_new = false;
    this->flip_order = flip_order;
    this->node_count = node_count;
    this->cards = new uint8_t *[node_count] {};
    this->cards_time = new time_t[node_count] {};
    this->status = new uint8_t[node_count * 16] {};
    this->accept = new bool[node_count] {};
    for (int i = 0; i < node_count; i++) {
        this->accept[i] = true;
    }
    this->hold = new bool[node_count] {};
    this->keypad_started = new bool[node_count] {};
    this->polling_started = new bool[node_count] {};
    this->keypad = new uint16_t[node_count] {};
    this->last_keypad = new uint16_t[node_count] {};
    this->keypad_candidate = new uint16_t[node_count] {};
    this->keypad_stable_count = new uint8_t[node_count] {};
    this->key_events = new uint8_t[node_count][2] {};
    this->key_event_q = new KeyEventQueue[node_count] {};
    this->crypt = new std::optional<Crypt>[node_count] {};
    this->counter = new uint8_t[node_count] {};
    for (int i = 0; i < node_count; i++) {
        this->counter[i] = 2;
    }

    // Sole edge owner when enabled — status path only refreshes held mask +
    // drains the event queue. ~5ms matches bemanitools serial keypad thread.
    this->keypad_thread = nullptr;
    if (keypad_thread) {
        this->keypad_thread = new std::thread([this]() {
            timeutils::PreciseSleepTimer timer;
            while (this->cards) {
                for (int unit = 0; unit < this->node_count; unit++) {
                    std::lock_guard<std::mutex> lock(this->keypad_mutex);
                    this->refresh_keypad_level(unit);
                    this->sample_keypad_edges(unit);
                }
                timer.sleep(5);
            }
        });
    }
}

ICCADevice::~ICCADevice() {

    // stop thread
    delete keypad_thread;

    // delete cards in array
    for (int i = 0; i < node_count; i++) {
        delete cards[i];
    }

    // delete the rest
    delete[] cards;
    delete[] cards_time;
    delete[] status;
    delete[] accept;
    delete[] hold;
    delete[] keypad_started;
    delete[] polling_started;
    delete[] keypad;
    delete[] last_keypad;
    delete[] keypad_candidate;
    delete[] keypad_stable_count;
    delete[] key_events;
    delete[] key_event_q;
    delete[] crypt;
    delete[] counter;
}

bool ICCADevice::parse_msg(MessageData *msg_in,
                           circular_buffer<uint8_t> *response_buffer) {

    // get unit
    int unit = msg_in->addr - 1;
    if (this->flip_order) {
        unit = this->node_count - unit - 1;
    }
    if (unit != 0 && unit != 1) {
        log_fatal("icca", "invalid unit: {}", unit);
    }

#ifdef ACIOEMU_LOG
    log_info("acioemu", "ICCA ADDR: {}, CMD: 0x{:04x}", unit, msg_in->cmd.code);
#endif

    // check command
    switch (msg_in->cmd.code) {
        case ACIO_CMD_GET_VERSION: {

            // send version data
            auto msg = this->create_msg(msg_in, MSG_VERSION_SIZE);
            if (avs::game::is_model({"LDJ", "TBS", "UJK", "XIF"}) ||
                games::sdvx::is_valkyrie_model()) {
                this->set_version(msg, 0x3, 0, 1, 7, 0, "ICCA");
            } else if (avs::game::is_model("VFG")) {
                this->set_version(msg, 0x3, 0, 1, 7, 0, "ICCB");
            } else {
                this->set_version(msg, 0x3, 0, 1, 6, 0, "ICCA");
            }
            write_msg(msg, response_buffer);
            delete msg;
            break;
        }
        case 0x0130: { // QUEUE_LOOP_START / REINITIALIZE
            // bemanitools: reset fault and mark polling started
            this->polling_started[unit] = true;
            auto msg = this->create_msg_status(msg_in, 0x00);
            write_msg(msg, response_buffer);
            delete msg;
            break;
        }
        case 0x0131: { // ENGAGE (bemanitools AC_IO_ICCA_CMD_ENGAGE)
            // Must return the real 16-byte state. Forcing IDLE (0x01) while
            // sensors/UID still show a card makes FDD–JDJ throw
            // CARD DEVICE ERROR (UNKNOW STATUS) after test-menu insert.
            auto msg = this->create_msg(msg_in, 16);
            update_card(unit);
            update_keypad(unit);
            update_status(unit);
            memcpy(msg->cmd.raw, &status[unit * 16], 16);
            write_msg(msg, response_buffer);
            delete msg;
            break;
        }
        case 0x0135: { // SET_SLOT_STATE

            uint8_t subcmd = 0;
            // check for data
            if (msg_in->cmd.data_size >= 2) {
                subcmd = msg_in->cmd.raw[1];

                // subcommand
                switch (subcmd) {
                    case 0x00: // ACCEPT DISABLE / CLOSE
                        this->accept[unit] = false;
                        break;
                    case 0x11: // ACCEPT ENABLE / OPEN
                        this->accept[unit] = true;
                        break;
                    case 0x12: // EJECT
                        if (this->cards[unit] != nullptr) {
                            delete this->cards[unit];
                        }
                        this->cards[unit] = nullptr;
                        this->hold[unit] = false;
                        break;
                    default:
                        break;
                }
            }

            // bemanitools replies with the subcmd as the 1-byte status for
            // non-v150. FDD–JDJ (slotted COM ICCA / shared libacio era) expect 0;
            // returning subcmd makes Sirius (and likely Troopers) throw
            // CARD DEVICE ERROR (UNKNOW STATUS).
            const uint8_t st = avs::game::is_model({"FDD", "GLD", "HDD", "I00", "JDJ"})
                    ? 0x00 : subcmd;
            auto msg = this->create_msg_status(msg_in, st);
            write_msg(msg, response_buffer);
            delete msg;
            break;
        }
        case 0x0134: { // GET STATUS

            // build data array
            auto msg = this->create_msg(msg_in, 16);

            // update things
            update_card(unit);
            update_keypad(unit);
            update_status(unit);

            // copy status
            memcpy(msg->cmd.raw, &status[unit * 16], 16);

            // write message
            write_msg(msg, response_buffer);
            delete msg;
            break;
        }
        case 0x0160: { // KEY EXCHANGE

            // if this cmd is called, the reader type must be new
            this->type_new = true;

            // build data array
            auto msg = this->create_msg(msg_in, 4);

            // set key
            msg->cmd.raw[0] = 0xBE;
            msg->cmd.raw[1] = 0xEF;
            msg->cmd.raw[2] = 0xCA;
            msg->cmd.raw[3] = 0xFE;

            // convert keys
            uint32_t game_key =
                    msg_in->cmd.raw[0] << 24 |
                    msg_in->cmd.raw[1] << 16 |
                    msg_in->cmd.raw[2] << 8 |
                    msg_in->cmd.raw[3];
            uint32_t reader_key =
                    msg->cmd.raw[0] << 24 |
                    msg->cmd.raw[1] << 16 |
                    msg->cmd.raw[2] << 8 |
                    msg->cmd.raw[3];

            log_info("icca", "client key: {:08x}", game_key);
            log_info("icca", "reader key: {:08x}", reader_key);

            this->crypt[unit].emplace();
            this->crypt[unit]->set_keys(reader_key, game_key);

            // write message
            write_msg(msg, response_buffer);
            delete msg;
            break;
        }
        case 0x0161: { // READ CARD UID NEW

            // if this cmd is called, the reader type must be new
            this->type_new = true;

            // decide on answer
            int answer_type = 0;
            //if (avs::game::is_model("LDJ"))
                //answer_type = 1;
            // SDVX Old cabinet mode
            if (avs::game::is_model("KFC") && avs::game::SPEC[0] != 'G' && avs::game::SPEC[0] != 'H')
                answer_type = 1;
            if (avs::game::is_model({ "L44", "T44" }))
                answer_type = 2;

            // check answer type
            switch (answer_type) {
                case 1: {

                    // send status 1
                    auto msg = this->create_msg_status(msg_in, 1);
                    write_msg(msg, response_buffer);
                    delete msg;
                    break;
                }
                case 2: {

                    // build data array
                    auto msg = this->create_msg(msg_in, 16);

                    // update card
                    update_card(unit);

                    // check for card
                    if (this->cards[unit] != nullptr) {

                        // copy into data buffer
                        memcpy(msg->cmd.raw, this->cards[unit], 8);

                        // delete card
                        delete this->cards[unit];
                        this->cards[unit] = nullptr;
                        this->hold[unit] = false;
                    }

                    // write message
                    write_msg(msg, response_buffer);
                    delete msg;
                    break;
                }
                default: {

                    // send response with no data
                    auto msg = this->create_msg(msg_in, 0);
                    write_msg(msg, response_buffer);
                    delete msg;
                    break;
                }
            }
            break;
        }
        case 0x0164: { // GET STATUS ENC

            // build data array
            auto msg = this->create_msg(msg_in, 18);

            // update things
            update_card(unit);
            update_keypad(unit);
            update_status(unit);

            // copy status
            memcpy(msg->cmd.raw, &status[unit * 16], 16);

            if (this->crypt[unit].has_value()) {
                auto &crypt = this->crypt[unit];
                uint16_t crc = crypt->crc(msg->cmd.raw, 16);

                msg->cmd.raw[16] = (uint8_t) (crc >> 8);
                msg->cmd.raw[17] = (uint8_t) crc;

                crypt->crypt(msg->cmd.raw, 18);
            } else {
                log_warning("icca", "'GET STATUS ENC' message received with no crypt keys initialized");
            }

            // write message
            write_msg(msg, response_buffer);
            delete msg;
            break;
        }
        case 0x013A: { // DEVICE_CONTROL (bemanitools AC_IO_ICCA_CMD_DEVICE_CONTROL)
            // LDJ / wavepass 1.7 uses a countdown; FDD–JDJ (and bemanitools)
            // expect status 0 and keypad_started=true. Wrong reply here makes
            // Troopers show CARD DEVICE ERROR (UNKNOW STATUS) on test menu.
            if (avs::game::is_model({"LDJ", "TBS", "XIF"})
                    || games::sdvx::is_valkyrie_model()) {
                if (this->counter[unit] > 0) {
                    this->counter[unit]--;
                }
                auto msg = this->create_msg_status(msg_in, this->counter[unit]);
                write_msg(msg, response_buffer);
                delete msg;
            } else {
                this->keypad_started[unit] = true;
                auto msg = this->create_msg_status(msg_in, 0x00);
                write_msg(msg, response_buffer);
                delete msg;
            }
            break;
        }
        case ACIO_CMD_STARTUP:
            // bemanitools START_UP only clears wavepass detection
            // (detected_new_reader). Keep polling_started / keypad_started so
            // test-menu re-init does not force FAULT (buffer[0]=0) or
            // buffer[11]=0 → CARD DEVICE ERROR (UNKNOW STATUS) on FDD–JDJ.
            this->type_new = false;
            // fallthrough
        case ACIO_CMD_CLEAR:
        case 0x30: // GetBoardProductNumber
        case 0x31: // GetMicomInfo
        case 0x3A: // ???
        case 0x0116: // ???
        case 0x0120: // ???
        case 0xFF: // BROADCAST
        {
            // send status 0
            auto msg = this->create_msg_status(msg_in, 0x00);
            write_msg(msg, response_buffer);
            delete msg;
            break;
        }
        default:
            return false;
    }

    // mark as handled
    return true;
}

void ICCADevice::update_card(int unit) {

    // wavepass timeout after 10s
    if (this->cards[unit] != nullptr) {
        time_t t_now;
        time(&t_now);

        if (difftime(t_now, this->cards_time[unit]) >= 10.f) {
            if (this->cards[unit] != nullptr) {
                delete this->cards[unit];
            }
            this->cards[unit] = nullptr;
            this->hold[unit] = false;
        }
    }

    bool kb_insert_press = false;

    // eamio keypress
    kb_insert_press |= static_cast<bool>(eamuse_get_keypad_state((size_t) unit) & (1 << EAM_IO_INSERT));

    // check for card
    if (this->cards[unit] == nullptr && (eamuse_card_insert_consume(this->node_count, unit) || kb_insert_press)) {
        auto card = new uint8_t[8];

        if (!eamuse_get_card(this->node_count, unit, card)) {

            // invalid card found
            delete[] card;

        } else {
            this->cards[unit] = card;
            time(&this->cards_time[unit]);
        }
    }
}

static int KEYPAD_EAMUSE_MAPPING[] = {
        0, 1, 5, 9, 2, 6, 10, 3, 7, 11, 8, 4
};

// map for KEYPAD_KEY_CODES:
//  7 8 9  | 800 8000 8
//  4 5 6  | 400 4000 4
//  1 2 3  | 200 2000 2
//  0 00 . | 100 1000 1
static int KEYPAD_KEY_CODES[]{
        0x100,  // 0
        0x200,  // 1
        0x2000, // 2
        2,      // 3
        0x400,  // 4
        0x4000, // 5
        4,      // 6
        0x800,  // 7
        0x8000, // 8
        8,      // 9
        1,      // .
        0x1000  // 00
};

// map for KEYPAD_KEY_CODES_ALT:
//  7 8 9  | 8 80 800
//  4 5 6  | 4 40 400
//  1 2 3  | 2 20 200
//  0 00 . | 1 10 100
//
// note that the only game that needs this (SDVX VM) does not accept decimal,
// so that key is untested
static int KEYPAD_KEY_CODES_ALT[]{
        1,      // 0
        2,      // 1
        0x20,   // 2
        0x200,  // 3
        4,      // 4
        0x40,   // 5
        0x400,  // 6
        8,      // 7
        0x80,   // 8
        0x800,  // 9
        0x100,  // .
        0x10    // 00
};

void ICCADevice::refresh_keypad_level(int unit) {
    this->keypad[unit] = 0;
    uint16_t eamu_state = eamuse_get_keypad_state((size_t) unit);
    for (int n = 0; n < 12; n++) {
        if (eamu_state & (1 << KEYPAD_EAMUSE_MAPPING[n])) {
            if (ICCA_DEVICE_HACK) {
                this->keypad[unit] |= KEYPAD_KEY_CODES_ALT[n];
            } else {
                this->keypad[unit] |= KEYPAD_KEY_CODES[n];
            }
        }
    }
}

void ICCADevice::sample_keypad_edges(int unit) {
    uint16_t eamu_state = eamuse_get_keypad_state((size_t) unit);

    if (eamu_state == this->keypad_candidate[unit]) {
        if (this->keypad_stable_count[unit] < KEY_DEBOUNCE_SAMPLES) {
            this->keypad_stable_count[unit]++;
        }
    } else {
        this->keypad_candidate[unit] = eamu_state;
        this->keypad_stable_count[unit] = 1;
    }
    if (this->keypad_stable_count[unit] < KEY_DEBOUNCE_SAMPLES) {
        return;
    }

    uint16_t rise = eamu_state & (this->last_keypad[unit] ^ eamu_state);
    this->last_keypad[unit] = eamu_state;
    if (!rise) {
        return;
    }

    uint8_t prev = this->key_events[unit][0];
    if (this->key_event_q[unit].count > 0) {
        const size_t last_i = (this->key_event_q[unit].tail + KEY_EVENT_Q - 1)
                % KEY_EVENT_Q;
        prev = this->key_event_q[unit].buf[last_i];
    }

    for (unsigned long bit = 0; bit < 16; bit++) {
        if (!(rise & (1u << bit))) {
            continue;
        }
        uint8_t event = prev ? (uint8_t) ((prev + 0x10) & 0xF0) : 0x00;
        event |= (uint8_t) (0x80 | bit);
        this->key_event_q[unit].push(event);
        prev = event;
    }
}

void ICCADevice::drain_key_events(int unit) {
    // At most two events per status (wire has key_events[2]).
    for (int n = 0; n < 2; n++) {
        uint8_t event = 0;
        if (!this->key_event_q[unit].try_pop(&event)) {
            break;
        }
        this->key_events[unit][1] = this->key_events[unit][0];
        this->key_events[unit][0] = event;
    }
}

void ICCADevice::update_keypad(int unit) {
    std::lock_guard<std::mutex> lock(this->keypad_mutex);
    this->refresh_keypad_level(unit);
    // Thread owns edges when present — avoid double-sampling duplicates.
    if (this->keypad_thread == nullptr) {
        this->sample_keypad_edges(unit);
    }
    this->drain_key_events(unit);
}

void ICCADevice::update_status(int unit) {

    // get buffer
    uint8_t *buffer = &this->status[unit * 16];

    // clear buffer
    memset(buffer, 0x00, 16);

    // check for card
    bool card = false;
    if (this->cards[unit] != nullptr) {

        // copy card into buffer
        memcpy(buffer + 2, this->cards[unit], 8);
        card = true;
    }

    // check for reader type
    if (this->type_new) {

        // check for card
        if (card) {

            // set status to card present
            buffer[0] = 0x02;

            /*
             * set card type
             * 0x00 - ISO15696
             * 0x01 - FELICA
             */
            bool felica = buffer[2] != 0xE0 && buffer[3] != 0x04;
            buffer[1] = felica ? 0x01 : 0x00;
            buffer[10] = felica ? 0x01 : 0x00;

        } else if (avs::game::is_model({"LDJ", "TBS", "XIF"}) || games::sdvx::is_valkyrie_model()) {
            // set status to 0 otherwise reader power on fails
            buffer[0] = 0x00;
        } else {

            // set status to no card present (1 or 4)
            buffer[0] = 0x04;
        }
    } else { // old reader

        // check for card
        if (card && accept[unit]) {
            this->hold[unit] = true;
        }

        // check for hold
        if (this->hold[unit]) {

            // set status to card present
            buffer[0] = 0x02;

            /*
             * sensors
             * 0x10 - OLD READER FRONT
             * 0x20 - OLD READER BACK
             */

            // activate both sensors
            buffer[1] = 0x30;
        } else {

            // card present but reader isn't accepting it
            if (card) {

                // set card present
                buffer[0] = 0x02;

                // set front sensor
                buffer[1] = 0x10;

            } else {

                // no card present
                buffer[0] = 0x01;
            }
        }

        // card type not present for old reader
        buffer[10] = 0x00;
    }

    // bemanitools: keypad_started must be 0x03 once DEVICE_CONTROL ran (or on
    // wavepass); otherwise slotted readers throw UNKNOW STATUS.
    if (this->keypad_started[unit] || this->type_new) {
        buffer[11] = 0x03;
    } else {
        buffer[11] = 0x00;
    }
    // Until QUEUE_LOOP_START, report FAULT like bemanitools (SDVX / boot).
    if (!this->polling_started[unit]) {
        buffer[0] = 0x00;
    }
    buffer[12] = this->key_events[unit][0];
    buffer[13] = this->key_events[unit][1];
    buffer[14] = (uint8_t) (keypad[unit] >> 8);
    buffer[15] = (uint8_t) (keypad[unit] & 0xFF);
}
