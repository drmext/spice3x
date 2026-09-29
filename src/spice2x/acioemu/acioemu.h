#pragma once

#include <cstdint>
#include <vector>

#include "util/circular_buffer.h"

#include "device.h"
#include "icca.h"

namespace acioemu {

    class ACIOEmu {
    private:
        std::vector<ACIODeviceEmu *> *devices;
        circular_buffer<uint8_t> *response_buffer;
        circular_buffer<uint8_t> *read_buffer;
        bool invert = false;
        // Old libacio (IIDX 13-18) counts raw 0xAA for autobaud, then parses
        // one frame. A sticky handshake counter was prefixing 0xAA 0xAA onto
        // the next real reply, and that shifted frame has no matching request.
        bool legacy_mode = false;

        void msg_parse();

    public:

        explicit ACIOEmu();
        ~ACIOEmu();

        void add_device(ACIODeviceEmu *device);
        void set_legacy_mode(bool enabled);

        void write(uint8_t byte);
        std::optional<uint8_t> read();
        size_t bytes_available();
    };
}
