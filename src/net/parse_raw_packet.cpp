#include "util/log.hpp"
#include "net/l3.hpp"
#include "net/l4.hpp"
#include "net/pkt.hpp"

#if defined(__linux__)
#include <netinet/in.h>
#elif defined(__WIN32) || defined(__WIN64)
#include <winsock2.h>
#else
#error "Could not find ntohs() function header for targeted platform"
#endif

#include "net/parse_raw_packet.hpp"

using namespace logs;

namespace Net
{
static bool parseNetworkLayer(Packet* packet)
{
    switch (packet->data[0] >> 4)
    {
    case 4:
        packet->network_protocol = NETWORK_PROTOCOLS::IPV4;
        packet->network_hdr = packet->data;
        break;

    case 6:
        packet->network_protocol = NETWORK_PROTOCOLS::IPV6;
        packet->network_hdr = packet->data;
        break;

    default:
        return 0;
    }

    return 1;
}

static bool parseTransportLayer(Packet* packet)
{
    switch (packet->network_protocol)
    {
    case NETWORK_PROTOCOLS::IPV4:
        packet->transport_protocol = static_cast<TRANSPORT_PROTOCOLS>(
            reinterpret_cast<ipv4_hdr*>(packet->network_hdr)->protocol);
        packet->transport_hdr = packet->network_hdr + sizeof(ipv4_hdr);
        break;

    case NETWORK_PROTOCOLS::IPV6:
        packet->transport_protocol = static_cast<TRANSPORT_PROTOCOLS>(
            reinterpret_cast<ipv6_hdr*>(packet->network_hdr)->next_hdr);
        packet->transport_hdr = packet->network_hdr + sizeof(ipv6_hdr);
        break;

    default:
        return 0;
    }

    return 1;
}

static bool parsePayload(Packet* packet)
{
    switch (packet->transport_protocol)
    {
    case TRANSPORT_PROTOCOLS::TCP:
        packet->payload =
            packet->transport_hdr +
            (ntohs(reinterpret_cast<TCPHdr*>(packet->transport_hdr)->flags) >> 12) * 4;
        break;

    case TRANSPORT_PROTOCOLS::UDP:
        packet->payload = packet->transport_hdr + sizeof(UDPHdr);
        break;

    default:
        packet->payload = nullptr;
        return 1;
    }

    return 1;
}

bool parseRawPacket(uint8_t* rawPacket, size_t rawPacketLen, Packet* packet)
{
    if (!rawPacket)
    {
        err("pointer to rawPacket is nullptr, cannot get data to parse.\n");
        return 0;
    }
    if (!packet)
    {
        err("pointer to packet is nullptr, cannot fill it with parsed data.\n");
        return 0;
    }

    packet->data = rawPacket;
    packet->data_len = rawPacketLen;
    packet->end = packet->data + packet->data_len;

    if (!parseNetworkLayer(packet))
    {
        logs::err("Could not parse network layer of packet.\n");
        return 0;
    }

    if (!parseTransportLayer(packet))
    {
        logs::err("Could not parse transport layer of packet.\n");
        return 0;
    }

    parsePayload(packet);

    return 1;
}
} // namespace Net
