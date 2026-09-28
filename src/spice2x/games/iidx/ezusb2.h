#pragma once

#include "hooks/devicehook.h"

namespace games::iidx {

    // Cypress FX2 / IO2 board used by IIDX Gold through Sirius (iidxhook3).
    class EZUSB2Handle : public CustomHandle {
    public:
        bool open(LPCWSTR lpFileName) override;

        int read(LPVOID lpBuffer, DWORD nNumberOfBytesToRead) override;

        int write(LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite) override;

        int device_io(DWORD dwIoControlCode, LPVOID lpInBuffer, DWORD nInBufferSize,
                LPVOID lpOutBuffer, DWORD nOutBufferSize) override;

        bool close() override;
    };
}
