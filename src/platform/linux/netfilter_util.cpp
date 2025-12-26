// SPDX-License-Identifier: GPL-3.0-or-later

#include <errno.h>
#include <netinet/in.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>

#include "util/log.hpp"
#include "packet/l3.hpp"
#include "packet/l4.hpp"

#include "platform/linux/netfilter_util.hpp"

namespace Platform
{
using namespace logs;
[[nodiscard]]
bool fillPacketInfo(NetfilterPacketInfo* packetInfo, nfq_data* nfad)
{
    auto nfqnlHdr = nfq_get_msg_packet_hdr(nfad);
    if (!nfqnlHdr)
    {
        logs::pr_errno(errno, "Cannot get nfqnl packet header\n");
        return 0;
    }

    packetInfo->id = ntohl(nfqnlHdr->packet_id);

    if (packetInfo->id == 0)
    {
        logs::pr_errno(errno, "Cannot get packet id, id=0\n");
        return 0;
    }

    int payload_len = nfq_get_payload(nfad, &packetInfo->data);
    if (payload_len < 0)
    {
        logs::pr_errno(errno, "Cannot get payload");
        return 0;
    }
    packetInfo->data_len = static_cast<uint32_t>(payload_len);

    packetInfo->mark = nfq_get_nfmark(nfad);

    return 1;
}

bool setNetworkProtocol(Net::Packet* packet)
{
    switch (packet->data[0] >> 4)
    {
    case 4:
        packet->network_protocol = Net::NETWORK_PROTOCOLS::IPV4;
        packet->network_hdr = packet->data;
        break;

    case 6:
        packet->network_protocol = Net::NETWORK_PROTOCOLS::IPV6;
        packet->network_hdr = packet->data;
        break;

    default:
        return 0;
    }

    return 1;
}

bool setTransportProtocol(Net::Packet* packet)
{
    switch (packet->network_protocol)
    {
    case Net::NETWORK_PROTOCOLS::IPV4:
        packet->transport_protocol = static_cast<Net::TRANSPORT_PROTOCOLS>(
            reinterpret_cast<Net::ipv4_hdr*>(packet->network_hdr)->protocol);
        packet->transport_hdr = packet->network_hdr + sizeof(Net::ipv4_hdr);
        break;

    case Net::NETWORK_PROTOCOLS::IPV6:
        packet->transport_protocol = static_cast<Net::TRANSPORT_PROTOCOLS>(
            reinterpret_cast<Net::ipv6_hdr*>(packet->network_hdr)->next_hdr);
        packet->transport_hdr = packet->network_hdr + sizeof(Net::ipv6_hdr);
        break;

    default:
        return 0;
    }

    return 1;
}

bool setPayload(Net::Packet* packet)
{
    switch (packet->transport_protocol)
    {
    case Net::TRANSPORT_PROTOCOLS::TCP:
        packet->payload =
            packet->transport_hdr +
            (ntohs(reinterpret_cast<Net::TCPHdr*>(packet->transport_hdr)->flags) >> 12) * 4;
        break;

    case Net::TRANSPORT_PROTOCOLS::UDP:
        packet->payload = packet->transport_hdr + sizeof(Net::UDPHdr);
        break;

    default:
        packet->payload = nullptr;
        return 1;
    }

    return 1;
}

bool fillPacket(Net::Packet* packet, NetfilterPacketInfo* packetInfo)
{
    if (!packet || !packetInfo)
    {
        logs::err("pointers to packet or packetInfo is nullptr, what happen?\n");
        return 0;
    }

    packet->data = packetInfo->data;
    packet->data_len = packetInfo->data_len;
    packet->end = packet->data + packet->data_len;

    if (!setNetworkProtocol(packet))
    {
        logs::err("Could not identify network protocol\n");
        return 0;
    }

    if (!setTransportProtocol(packet))
    {
        logs::err("Could not identify transport protocol\n");
        return 0;
    }

    setPayload(packet);

    return 1;
}
} // namespace Platform
