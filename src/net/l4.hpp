// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "net/byte_swap.hpp"
#include "net/l3.hpp"

namespace Net
{
enum class TransportProtocol : uint8_t
{
    TCP = 6,
    UDP = 17,
};

#pragma pack(push, 1)
struct TCPHdr
{
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint16_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_ptr;

    uint8_t getDataOffset()
    {
        return NetToHostShort(flags) >> 12;
    }
};
#pragma pack(pop)

#pragma pack(push, 1)
struct UDPHdr
{
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t checksum;
};
#pragma pack(pop)
} // namespace Net
