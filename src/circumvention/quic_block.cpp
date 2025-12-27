// SPDX-License-Identifier: GPL-3.0-or-later

#include "circumvention/quic_block.hpp"

#include "net/pkt.hpp"
#include "core/connection.hpp"

namespace Circumvention
{
bool isQUIC(Net::Packet* packet)
{
    if (!packet->payload)
    {
        return false;
    }

    auto payload = packet->payload;

    return payload && (payload[0] == 0xC0 || payload[0] == 0xFF);
}
} // namespace Circumvention
