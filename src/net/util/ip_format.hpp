#pragma once

#include <string>
#include <cstdint>

#include "net/protocol/l3.hpp"

namespace Net
{
uint32_t IPv4Tou32(const char* ip_str);
std::string u32ToIPv4(const uint32_t ip_u32);
std::string IPv6ToStr(const IPv6& ip);
} // namespace Net
