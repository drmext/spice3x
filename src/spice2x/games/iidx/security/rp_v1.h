#pragma once

#include <cstdint>
#include <cstddef>

namespace games::iidx::security {

struct RpEeprom {
    uint8_t signature[6];
    uint8_t packed_payload[6];
};

// Roundplug v1 signed EEPROM (IIDX 9-13). boot_version is 8 bytes (e.g. "GEC02   "),
// boot_seeds are three numbers 0-9, plug_mcode is 8 bytes (e.g. "GEC02JAA"),
// plug_id is the 10-byte security id (header + 8 id bytes + checksum).
void rp_generate_signed_eeprom(
        const char boot_version[8],
        const uint32_t boot_seeds[3],
        const char plug_mcode[8],
        const uint8_t plug_id[10],
        RpEeprom *out);

} // namespace games::iidx::security
