#include <stdint.h>
#include <stddef.h>
#include <ctype.h>
#include <stdlib.h>

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

char* u32ToIPv4(const uint32_t ip_u32) { return nullptr; }
} // namespace Net
