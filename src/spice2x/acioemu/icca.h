#pragma once

#include <cstring>
#include <ctime>
#include <mutex>
#include <optional>
#include <thread>

#include "device.h"
#include "hooks/sleephook.h"
#include "reader/crypt.h"

namespace acioemu {
    extern bool ICCA_DEVICE_HACK;

    class ICCADevice : public ACIODeviceEmu {
    private:
        static constexpr size_t KEY_EVENT_Q = 16;
        static constexpr uint8_t KEY_DEBOUNCE_SAMPLES = 2;

        struct KeyEventQueue {
            uint8_t buf[KEY_EVENT_Q] {};
            size_t head = 0;
            size_t tail = 0;
            size_t count = 0;

            void clear() {
                head = tail = count = 0;
            }

            void push(uint8_t event) {
                if (count == KEY_EVENT_Q) {
                    head = (head + 1) % KEY_EVENT_Q;
                    count--;
                }
                buf[tail] = event;
                tail = (tail + 1) % KEY_EVENT_Q;
                count++;
            }

            bool try_pop(uint8_t *out) {
                if (count == 0) {
                    return false;
                }
                *out = buf[head];
                head = (head + 1) % KEY_EVENT_Q;
                count--;
                return true;
            }
        };

        bool type_new;
        bool flip_order;
        std::thread *keypad_thread;
        std::mutex keypad_mutex;
        uint8_t **cards;
        time_t *cards_time;
        uint8_t *status;
        bool *accept;
        bool *hold;
        bool *keypad_started;
        bool *polling_started;
        uint16_t *keypad;
        uint16_t *last_keypad;
        uint16_t *keypad_candidate;
        uint8_t *keypad_stable_count;
        uint8_t (*key_events)[2];
        KeyEventQueue *key_event_q;
        std::optional<Crypt> *crypt;
        uint8_t *counter;

        void refresh_keypad_level(int unit);
        void sample_keypad_edges(int unit);
        void drain_key_events(int unit);

    public:
        explicit ICCADevice(bool flip_order, bool keypad_thread, uint8_t node_count);
        ~ICCADevice() override;

        bool parse_msg(MessageData *msg_in, circular_buffer<uint8_t> *response_buffer) override;

        void update_card(int unit);
        void update_keypad(int unit);
        void update_status(int unit);
    };
}
