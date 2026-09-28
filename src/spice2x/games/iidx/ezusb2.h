#pragma once

#include "hooks/devicehook.h"

namespace games::iidx {

    // Sirius JDJ: ezusb.sys transport + ezusb-iidx v2 packets (security plug v2).
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
