// SPDX-License-Identifier: GPL-3.0-or-later

#include "circumvention/quic_block.hpp"

#include "net/packet.hpp"
#include "core/connection.hpp"

using namespace Net;

namespace Circumvention
{
bool isQUIC(Packet* packet)
{
    if (!packet->payload)
    {
        return false;
    }

    auto payload = packet->payload;

    return payload && (payload[0] == 0xC0 || payload[0] == 0xFF);
}
} // namespace Circumvention
