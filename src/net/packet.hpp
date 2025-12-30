// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdint.h>
#include <stddef.h>

#include "net/l3.hpp"
#include "net/l4.hpp"

namespace Net
{
struct Packet
{
    uint8_t* data;
    uint8_t* end;
    uint32_t data_len;
    NetworkProtocol network_protocol;
    uint8_t* network_hdr;
    TransportProtocol transport_protocol;
    uint8_t* transport_hdr;
    uint8_t* payload;
    long int payload_len;
    bool is_outbound;

    uint16_t getL4AndPayloadLength() const
    {
        return end - transport_hdr + 1;
    }
};
} // namespace Net
