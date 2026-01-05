// SPDX-License-Identifier: GPL-3.0-or-later

#include <cstdio>
#include <chrono>

#include "util/log.hpp"
#include "net/protocol/packet.hpp"
#include "net/traffic_modifier/traffic_modifier.hpp"
#include "circumvention/dns.hpp"
#include "circumvention/fake_packet.hpp"
#include "circumvention/quic_block.hpp"

using namespace Logs;
using namespace Net;

namespace Circumvention
{
[[nodiscard]]
bool handlePkt(Packet* packet, TrafficModifier* trafficModifier)
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
            return false;

        if (params->do_dns_redirect && isDNSRequest(packet))
            handleDNSRequest(params, packet);

        if (params->do_fake_packet)
            trySendFakePkt(packet, trafficModifier);
    }
    else
    {
        if (params->do_dns_redirect && isDNSResponse(packet))
            handleDNSResponse(packet);
    }

    return true;
}
} // namespace Circumvention
