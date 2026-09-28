#include "handle.h"

#include <cstring>

#include "acioemu/device.h"
#include "misc/eamuse.h"
#include "rawinput/rawinput.h"
#include "util/utils.h"

acioemu::ACIOHandle::ACIOHandle(LPCWSTR lpCOMPort, uint8_t iccaNodeCount, bool legacyMode) {
    this->com_port = lpCOMPort;
    this->icca_node_count = iccaNodeCount;
    this->legacy_mode = legacyMode;
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

    // Old libacio (Sirius / iidxhook3): one framed message per ReadFile
    legacy_drain_emu();

    // Drop leading junk before SOF SOF
    while (legacy_pending.size() >= 2
            && !(legacy_pending[0] == ACIO_SOF && legacy_pending[1] == ACIO_SOF)) {
        legacy_pending.erase(legacy_pending.begin());
    }

    const size_t frame_size = legacy_next_frame_size();
    if (frame_size == 0 || frame_size > nNumberOfBytesToRead) {
        return 0;
    }

    memcpy(buffer, legacy_pending.data(), frame_size);
    legacy_pending.erase(legacy_pending.begin(),
            legacy_pending.begin() + static_cast<std::ptrdiff_t>(frame_size));
    return static_cast<int>(frame_size);
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
    const size_t frame_size = legacy_next_frame_size();
    if (frame_size > 0) {
        return frame_size;
    }
    // Hold a partial frame until it completes; report nothing yet
    return 0;
}

bool acioemu::ACIOHandle::close() {
    log_info("acioemu", "Closed {} (ACIO)", ws2s(com_port));
    legacy_pending.clear();

    return true;
}
