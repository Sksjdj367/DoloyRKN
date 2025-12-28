#include "util/log.hpp"
#include "net/byte_swap.hpp"
#include "net/l3.hpp"
#include "net/l4.hpp"
#include "net/packet.hpp"

#include "net/parse_raw_packet.hpp"

using namespace logs;

namespace Net
{
static bool parseNetworkLayer(Packet* packet)
{
    switch (packet->data[0] >> 4)
    {
    case 4:
        packet->network_protocol = NetworkProtocol::IPv4;
        packet->network_hdr = packet->data;
        break;

    case 6:
        packet->network_protocol = NetworkProtocol::IPv6;
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
    case NetworkProtocol::IPv4:
        packet->transport_protocol = static_cast<TransportProtocol>(
            reinterpret_cast<IPv4Hdr*>(packet->network_hdr)->protocol);
        packet->transport_hdr = packet->network_hdr + sizeof(IPv4Hdr);
        break;

    case NetworkProtocol::IPv6:
        packet->transport_protocol = static_cast<TransportProtocol>(
            reinterpret_cast<IPv6Hdr*>(packet->network_hdr)->next_hdr);
        packet->transport_hdr = packet->network_hdr + sizeof(IPv6Hdr);
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
    case TransportProtocol::TCP:
        packet->payload = packet->transport_hdr +
                          reinterpret_cast<TCPHdr*>(packet->transport_hdr)->getDataOffset() * 4;
        break;

    case TransportProtocol::UDP:
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
