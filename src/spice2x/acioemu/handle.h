#pragma once

#include <vector>

#include "acioemu/acioemu.h"
#include "hooks/devicehook.h"

namespace acioemu {

    class ACIOHandle : public CustomHandle {
    private:
        LPCWSTR com_port;

        uint8_t icca_node_count;

        bool legacy_mode;

        // Staged escaped bytes for legacy one-frame-per-ReadFile mode
        std::vector<uint8_t> legacy_pending;

        // Bytes still left of the current complete frame at the front of pending
        size_t legacy_frame_left = 0;

        acioemu::ACIOEmu acio_emu;

        void legacy_drain_emu();

        // Size of the first complete framed message in legacy_pending, or 0
        size_t legacy_next_frame_size() const;

        // Ensure legacy_frame_left reflects a complete frame at pending[0]
        bool legacy_ensure_frame();

    public:
        ACIOHandle(LPCWSTR lpCOMPort, uint8_t iccaNodeCount = 2, bool legacyMode = false);

        bool open(LPCWSTR lpFileName) override;

        int read(LPVOID lpBuffer, DWORD nNumberOfBytesToRead) override;

        int write(LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite) override;

        int device_io(DWORD dwIoControlCode, LPVOID lpInBuffer, DWORD nInBufferSize, LPVOID lpOutBuffer,
                      DWORD nOutBufferSize) override;

        size_t bytes_available() override;

        bool close() override;
    };
}
