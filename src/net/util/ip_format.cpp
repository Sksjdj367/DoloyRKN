#include <format>
#include <cstdint>
#include <cstddef>
#include <cctype>
#include <cstdlib>
#include <string>

#include "net/util/byte_swap.hpp"
#include "util/log.hpp"

#include "net/util/ip_format.hpp"

namespace Net
{
uint32_t IPv4Tou32(const char* ip_str)
{
    if (!ip_str || !*ip_str)
        return 0;

    uint32_t result = 0;
    uint32_t octet = 0;
    int octet_count = 0;
    bool has_digit = false;

    while (*ip_str)
    {
        if (isdigit(*ip_str))
        {
            octet = octet * 10 + static_cast<uint32_t>((*ip_str - '0'));
            has_digit = true;
            if (octet > 255)
                return 0;
        }
        else if (*ip_str == '.')
        {
            if (!has_digit)
                return 0;
            result = (result << 8) | octet;
            octet = 0;
            octet_count++;
            has_digit = false;
        }
        else
        {
            return 0;
        }
        ip_str++;
    }

    if (octet_count != 3 || !has_digit)
        return 0;

    result = (result << 8) | octet;

    return HostToNetLong(result);
}

std::string u32ToIPv4(const uint32_t ip)
{
    return std::format("{}.{}.{}.{}",
        (NetToHostLong(ip) >> 24) & 0xFF,
        (NetToHostLong(ip) >> 16) & 0xFF,
        (NetToHostLong(ip) >> 8) & 0xFF,
        NetToHostLong(ip) & 0xFF);
}

/**
 * Incomplete and returns incompleted ip
*/
std::string IPv6ToStr(const IPv6& ip)
{
    return std::format("{:x}.{:x}.{:x}.{:x}.{:x}.{:x}.{:x}.{:x}",
        ip.addr[0],
        ip.addr[1],
        ip.addr[2],
        ip.addr[3],
        ip.addr[4],
        ip.addr[5],
        ip.addr[6],
        ip.addr[7]);
}
} // namespace Net
