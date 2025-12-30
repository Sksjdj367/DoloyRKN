// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdio.h>

#include "util/log.hpp"
#include "net/packet.hpp"
#include "core/connection.hpp"
#include "circumvention/dns.hpp"
#include "circumvention/fake_packet.hpp"
#include "circumvention/quic_block.hpp"

using namespace logs;
using namespace Net;

namespace Circumvention
{
[[nodiscard]]
bool handlePkt(Packet* packet, Core::TrafficModifier* trafficModifier)
{
    if (packet->transport_protocol != TransportProtocol::TCP &&
        packet->transport_protocol != TransportProtocol::UDP)
    {
        return true;
    }

    const auto params = trafficModifier->getParams();

    if (packet->is_outbound)
    {
        if (params->do_block_quic && isQUIC(packet))
        {
            return false;
        }

        if (params->do_dns_redirect && isDNSRequest(packet))
        {
            substituteDNSRequest(params, packet);
        }

        if (params->do_fake_packet)
        {
            trySendFakePkt(packet, trafficModifier);
        }
    }
    else
    {
        if (params->do_dns_redirect && isDNSResponse(packet))
        {
            substituteDNSResponse(packet);
        }
    }

    return true;
}
} // namespace Circumvention
