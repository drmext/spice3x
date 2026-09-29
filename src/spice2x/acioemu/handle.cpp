#include "handle.h"

#include <algorithm>
#include <cstring>

#include "acioemu/device.h"
#include "misc/eamuse.h"
#include "rawinput/rawinput.h"
#include "util/utils.h"

acioemu::ACIOHandle::ACIOHandle(LPCWSTR lpCOMPort, uint8_t iccaNodeCount, bool legacyMode) {
    this->com_port = lpCOMPort;
    this->icca_node_count = iccaNodeCount;
    this->legacy_mode = legacyMode;
    if (legacyMode) {
        acio_emu.set_legacy_mode(true);
    }
}

bool acioemu::ACIOHandle::open(LPCWSTR lpFileName) {
    if (wcscmp(lpFileName, com_port) != 0) {
        return false;
    }

    log_info("acioemu", "Opened {} (ACIO{})", ws2s(com_port),
            legacy_mode ? ", legacy" : "");

    // ACIO device
    acio_emu.add_device(new acioemu::ICCADevice(false, true, icca_node_count));

    return true;
}

void acioemu::ACIOHandle::legacy_drain_emu() {
    while (true) {
        auto cur_byte = acio_emu.read();
        if (!cur_byte.has_value()) {
            break;
        }
        legacy_pending.push_back(cur_byte.value());
    }
}

size_t acioemu::ACIOHandle::legacy_next_frame_size() const {
    // Framed message: AA AA + escaped(header + payload + checksum)
    size_t i = 0;
    const size_t n = legacy_pending.size();

    // Find SOF SOF
    while (i + 1 < n) {
        if (legacy_pending[i] == ACIO_SOF && legacy_pending[i + 1] == ACIO_SOF) {
            break;
        }
        i++;
    }
    if (i + 1 >= n || legacy_pending[i] != ACIO_SOF || legacy_pending[i + 1] != ACIO_SOF) {
        return 0;
    }

    const size_t frame_start = i;
    i += 2;

    bool escape = false;
    size_t unescaped = 0;
    size_t expected = SIZE_MAX;
    uint8_t decoded[8] {};

    while (i < n && unescaped < expected) {
        uint8_t b = legacy_pending[i++];
        if (escape) {
            b = static_cast<uint8_t>(~b);
            escape = false;
        } else if (b == ACIO_ESCAPE) {
            escape = true;
            continue;
        }

        if (unescaped < sizeof(decoded)) {
            decoded[unescaped] = b;
        }
        unescaped++;

        if (unescaped == 1 && decoded[0] == ACIO_BROADCAST) {
            // broadcast: addr + data_size + data + checksum
            // need data_size next
        } else if (unescaped == 2 && decoded[0] == ACIO_BROADCAST) {
            expected = 2 + decoded[1] + 1;
        } else if (unescaped == 5 && decoded[0] != ACIO_BROADCAST) {
            // addr + code(2) + pid + data_size + data + checksum
            expected = 5 + decoded[4] + 1;
        }
    }

    if (escape || unescaped < expected || expected == SIZE_MAX) {
        return 0;
    }

    return i - frame_start;
}

bool acioemu::ACIOHandle::legacy_ensure_frame() {
    legacy_drain_emu();

    if (legacy_frame_left > 0) {
        // Mid-frame delivery: remaining bytes are already at the front
        return legacy_pending.size() >= legacy_frame_left;
    }

    // Drop leading junk before SOF SOF
    while (legacy_pending.size() >= 2
            && !(legacy_pending[0] == ACIO_SOF && legacy_pending[1] == ACIO_SOF)) {
        legacy_pending.erase(legacy_pending.begin());
    }

    const size_t frame_size = legacy_next_frame_size();
    if (frame_size == 0) {
        return false;
    }

    // Drop any junk before the frame so it sits at index 0
    while (legacy_pending.size() >= 2
            && !(legacy_pending[0] == ACIO_SOF && legacy_pending[1] == ACIO_SOF)) {
        legacy_pending.erase(legacy_pending.begin());
    }

    legacy_frame_left = frame_size;
    return true;
}

int acioemu::ACIOHandle::read(LPVOID lpBuffer, DWORD nNumberOfBytesToRead) {
    auto buffer = reinterpret_cast<uint8_t *>(lpBuffer);

    if (!legacy_mode) {
        // read from emu
        DWORD bytes_read = 0;
        while (bytes_read < nNumberOfBytesToRead) {
            auto cur_byte = acio_emu.read();

            if (cur_byte.has_value()) {
                buffer[bytes_read++] = cur_byte.value();
            } else {
                break;
            }
        }

        return (int) bytes_read;
    }

    if (nNumberOfBytesToRead == 0) {
        return 0;
    }

    legacy_drain_emu();

    // Autobaud is a run of raw 0xAA with no frame behind it. libacio's init
    // counts those bytes. Waiting for a framed message here drops them, and
    // the reader never leaves CHECKING.
    if (legacy_frame_left == 0 && !legacy_pending.empty()) {
        size_t aas = 0;
        while (aas < legacy_pending.size() && legacy_pending[aas] == ACIO_SOF) {
            aas++;
        }
        if (aas == legacy_pending.size()) {
            const size_t n = (std::min)(static_cast<size_t>(nNumberOfBytesToRead), aas);
            memcpy(buffer, legacy_pending.data(), n);
            legacy_pending.erase(legacy_pending.begin(),
                    legacy_pending.begin() + static_cast<std::ptrdiff_t>(n));
            return static_cast<int>(n);
        }
    }

    // Old libacio reads in short chunks; deliver a prefix of one frame and
    // keep the rest for the next ReadFile. Do not start a second frame here.
    if (!legacy_ensure_frame()) {
        return 0;
    }

    const size_t n = (std::min)(static_cast<size_t>(nNumberOfBytesToRead), legacy_frame_left);
    memcpy(buffer, legacy_pending.data(), n);
    legacy_pending.erase(legacy_pending.begin(),
            legacy_pending.begin() + static_cast<std::ptrdiff_t>(n));
    legacy_frame_left -= n;
    return static_cast<int>(n);
}

int acioemu::ACIOHandle::write(LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite) {
    auto buffer = reinterpret_cast<const uint8_t *>(lpBuffer);

    // write to emu
    for (DWORD i = 0; i < nNumberOfBytesToWrite; i++) {
        acio_emu.write(buffer[i]);
    }

    // return all data written
    return (int) nNumberOfBytesToWrite;
}

int acioemu::ACIOHandle::device_io(
        DWORD dwIoControlCode,
        LPVOID lpInBuffer,
        DWORD nInBufferSize,
        LPVOID lpOutBuffer,
        DWORD nOutBufferSize
) {
    return -1;
}

size_t acioemu::ACIOHandle::bytes_available() {
    if (!legacy_mode) {
        return acio_emu.bytes_available();
    }

    legacy_drain_emu();
    if (legacy_frame_left == 0 && !legacy_pending.empty()) {
        size_t aas = 0;
        while (aas < legacy_pending.size() && legacy_pending[aas] == ACIO_SOF) {
            aas++;
        }
        if (aas == legacy_pending.size()) {
            return aas;
        }
    }

    if (!legacy_ensure_frame()) {
        return 0;
    }
    return legacy_frame_left;
}

bool acioemu::ACIOHandle::close() {
    log_info("acioemu", "Closed {} (ACIO)", ws2s(com_port));
    legacy_pending.clear();
    legacy_frame_left = 0;

    return true;
}
