// SPDX-License-Identifier: GPL-3.0-or-later

#include "net/util/checksum.hpp"

namespace Net
{
namespace
{
void calcL3Checksum(IPv4Hdr* ipv4_hdr)
{
    ipv4_hdr->checksum = 0;

    uint32_t checksum{};

    for (auto i = 0u; i < (sizeof(IPv4Hdr) / 2); i++)
        checksum += reinterpret_cast<uint16_t*>(ipv4_hdr)[i];

    while (checksum >> 16)
        checksum = (checksum & 0xFFFF) + (checksum >> 16);

    ipv4_hdr->checksum = static_cast<uint16_t>(~checksum);
}

void calcL4Checksum(Packet* packet)
{
    uint16_t* pchecksum;

    if (packet->transport_protocol == TransportProtocol::TCP)
        pchecksum = &reinterpret_cast<TCPHdr*>(packet->transport_hdr)->checksum;
    else if (packet->transport_protocol == TransportProtocol::UDP)
        pchecksum = &reinterpret_cast<UDPHdr*>(packet->transport_hdr)->checksum;
    else
    {
        return;
    }

    *pchecksum = 0;

    uint32_t checksum{};

    auto ipv4_hdr = reinterpret_cast<IPv4Hdr*>(packet->network_hdr);

    checksum += (ipv4_hdr->src_ip & 0xFFFF) + (ipv4_hdr->src_ip >> 16);
    checksum += (ipv4_hdr->dst_ip & 0xFFFF) + (ipv4_hdr->dst_ip >> 16);
    checksum += HostToNetShort(static_cast<uint16_t>(ipv4_hdr->protocol));
    checksum += HostToNetShort(packet->getL4AndPayloadLength());

    for (size_t i{}; i < (packet->getL4AndPayloadLength() / 2); i++)
        checksum += reinterpret_cast<uint16_t*>(packet->transport_hdr)[i];

    if ((packet->getL4AndPayloadLength()) % 2)
        checksum += NetToHostShort(static_cast<uint16_t>((*(packet->end - 1)) << 8));

    while (checksum >> 16)
        checksum = (checksum & 0xFFFF) + (checksum >> 16);

    checksum = ~static_cast<uint16_t>(checksum);

    if (checksum == 0x0000)
    {
        checksum = 0xFFFF;
    }

    *pchecksum = checksum;
}
} // namespace

void calcChecksum(Packet* packet)
{
    if (packet->network_protocol == NetworkProtocol::IPv4)
        calcL3Checksum(reinterpret_cast<IPv4Hdr*>(packet->network_hdr));

    calcL4Checksum(packet);
}
} // namespace Net
