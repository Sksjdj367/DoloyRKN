#pragma once

#include <stdint.h>

namespace Net
{
uint32_t IPv4Tou32(const char* ip_str);
char* u32ToIPv4(const uint32_t ip_u32);
} // namespace Net
