// SPDX-License-Identifier: GPL-3.0-or-later

#include "net/checksum.hpp"

namespace Net
{
void calcL3Checksum(uint8_t* raw_ipv4_hdr)
{
    auto ipv4_hdr = reinterpret_cast<IPv4Hdr*>(raw_ipv4_hdr);
    ipv4_hdr->checksum = 0;

    uint32_t checksum{};
    for (auto i = 0u; i < (sizeof(IPv4Hdr) / 2); i++)
    {
        checksum += reinterpret_cast<uint16_t*>(ipv4_hdr)[i];
    }

    while (checksum >> 16)
    {
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
    }

    ipv4_hdr->checksum = static_cast<uint16_t>(~checksum);
}

static inline void zeroPacketL4Checksum(Packet* packet)
{
    if (packet->transport_protocol == TransportProtocol::TCP)
        reinterpret_cast<TCPHdr*>(packet->transport_hdr)->checksum = 0;
    else if (packet->transport_protocol == TransportProtocol::UDP)
        reinterpret_cast<UDPHdr*>(packet->transport_hdr)->checksum = 0;
}

static void addPseudoHdr(uint32_t& checksum, const Packet* packet)
{
    auto ipv4_hdr = reinterpret_cast<IPv4Hdr*>(packet->network_hdr);

    checksum += (ipv4_hdr->src_ip & 0xFFFF) + (ipv4_hdr->src_ip >> 16);
    checksum += (ipv4_hdr->dst_ip & 0xFFFF) + (ipv4_hdr->dst_ip >> 16);
    checksum += HostToNetShort(static_cast<uint16_t>(ipv4_hdr->protocol));
    checksum += HostToNetShort(packet->getL4AndPayloadLength());
}

static void addL4AndPayload(uint32_t& checksum, const Packet* packet)
{
    for (size_t i{}; i < (packet->getL4AndPayloadLength() / 2); i++)
    {
        checksum += reinterpret_cast<uint16_t*>(packet->transport_hdr)[i];
    }
}

static inline void addPadding(uint32_t& checksum, Packet* packet)
{
    if ((packet->getL4AndPayloadLength()) % 2)
    {
        checksum += NetToHostShort(static_cast<uint16_t>((*packet->end) << 8));
    }
}

static void shiftChecksum(uint32_t& checksum)
{
    while (checksum >> 16)
    {
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
    }
}

static inline void invertChecksum(uint32_t& checksum)
{
    checksum = ~static_cast<uint16_t>(checksum);
}

static inline void setPacketL4Checksum(uint32_t checksum, Packet* packet)
{
    if (packet->transport_protocol == TransportProtocol::TCP)
        reinterpret_cast<TCPHdr*>(packet->transport_hdr)->checksum = checksum;
    else if (packet->transport_protocol == TransportProtocol::UDP)
        reinterpret_cast<UDPHdr*>(packet->transport_hdr)->checksum = checksum;
}

void calcL4Checksum(Packet* packet)
{
    zeroPacketL4Checksum(packet);

    uint32_t checksum{};
    addPseudoHdr(checksum, packet);
    addL4AndPayload(checksum, packet);
    addPadding(checksum, packet);
    shiftChecksum(checksum);
    invertChecksum(checksum);
    setPacketL4Checksum(checksum, packet);
}

void calcChecksum(Packet* packet)
{
    if (packet->network_protocol == NetworkProtocol::IPv4)
    {
        calcL3Checksum(packet->network_hdr);
    }

    calcL4Checksum(packet);
}
} // namespace Net
