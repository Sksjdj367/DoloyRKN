// SPDX-License-Identifier: GPL-3.0-or-later

#include <unordered_map>
#include <string.h>

#include "util/log.hpp"
#include "cli/params.hpp"
#include "net/util/checksum.hpp"
#include "net/protocol/packet.hpp"

#include "circumvention/dns.hpp"

using namespace Logs;
using namespace cli;
using namespace Net;

namespace Circumvention
{
constexpr uint8_t DNSRequestResponseCounter[]{0, 0, 0, 0, 0, 0};

bool isDNSRequest(const Packet* packet)
{
    if (packet->network_protocol != NetworkProtocol::IPv4 ||
        packet->transport_protocol != TransportProtocol::UDP)
    {
        return false;
    }
    if (!packet->payload)
    {
        return false;
    }
    if (packet->payload_len < 12)
    {
        return false;
    }
    if (memcmp(packet->payload + 6, DNSRequestResponseCounter, 5) != 0)
    {
        return false;
    }
    if (reinterpret_cast<UDPHdr*>(packet->transport_hdr)->getDstPort() != 53)
    {
        return false;
    }

    return true;
}

bool isDNSResponse(const Packet* packet)
{
    if (packet->network_protocol != NetworkProtocol::IPv4 ||
        packet->transport_protocol != TransportProtocol::UDP)
    {
        return false;
    }
    if (!packet->payload)
    {
        return false;
    }
    if (packet->payload_len < 12)
    {
        return false;
    }
    if (reinterpret_cast<UDPHdr*>(packet->transport_hdr)->getSrcPort() != 53)
    {
        return false;
    }

    return true;
}

std::unordered_map<uint16_t, uint32_t> IPv4DNSAddresses = {};

void substituteDNSRequest(const Params* params, Packet* packet)
{
    IPv4DNSAddresses[reinterpret_cast<UDPHdr*>(packet->transport_hdr)->src_port] = reinterpret_cast<IPv4Hdr*>(packet->network_hdr)->dst_ip;
    reinterpret_cast<IPv4Hdr*>(packet->network_hdr)->dst_ip = params->dr_ipv4;

    calcChecksum(packet);
}

void substituteDNSResponse(Packet* packet)
{
    auto ip = IPv4DNSAddresses[reinterpret_cast<UDPHdr*>(packet->transport_hdr)->dst_port];
    if (!ip)
    {
        prErr("No cache! [%u]\n", reinterpret_cast<UDPHdr*>(packet->transport_hdr)->src_port);
        return;
    }

    reinterpret_cast<IPv4Hdr*>(packet->network_hdr)->src_ip = ip;

    calcChecksum(packet);
}
} // namespace Circumvention