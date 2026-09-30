#pragma once

#include <cstdint>

namespace games::iidx {

// Magnetic-card H8 serial node (ezusb node 0x04) for IIDX 9-12.
namespace ezusb_serial {

// One-shot process init (slots + buffers). Safe to call repeatedly.
void init();
// Soft buffer/paging reset only — does not wipe card/slot state.
void reset_buffers();
uint8_t process_cmd(uint8_t cmd);
bool read_packet(uint8_t *packet);   // BulkPacket: node, page, payload[62]
bool write_packet(const uint8_t *packet);
bool read_busy();
bool write_busy();

} // namespace ezusb_serial
} // namespace games::iidx
