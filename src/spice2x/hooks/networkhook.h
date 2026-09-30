#pragma once

#include <string>

// Named to avoid clash with Win32 typedef NETWORK_ADDRESS (ntddndis.h via iphlpapi).
extern std::string NETWORK_ADDR;
extern std::string NETWORK_SUBNET;

void networkhook_init();
