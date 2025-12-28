// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdio.h>

#include "util/log.hpp"
#include "net/packet.hpp"
#include "core/connection.hpp"
#include "circumvention/fake_packet.hpp"
#include "circumvention/quic_block.hpp"

using namespace Net;

namespace Circumvention
{
[[nodiscard]]
bool handlePkt(Packet* packet, Core::TrafficModifier* trafficModifier)
{
    const auto params = trafficModifier->getParams();

    if (params->do_block_quic)
    {
        if (isQUIC(packet))
        {
            return 0;
        }
    }

    if (params->do_fake_packet)
    {
        trySendFakePkt(packet, trafficModifier);
    }

    return 1;
}
} // namespace Circumvention
