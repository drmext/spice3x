#pragma once

#include <cstdint>

namespace games::iidx {

// Magnetic-card H8 serial node (ezusb node 0x04) for IIDX 9-12.
namespace ezusb_serial {

void init();
uint8_t process_cmd(uint8_t cmd);
bool read_packet(uint8_t *packet);   // BulkPacket: node, page, payload[62]
bool write_packet(const uint8_t *packet);
bool read_busy();
bool write_busy();

} // namespace ezusb_serial
} // namespace games::iidx
