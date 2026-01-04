#include "util/log.hpp"
#include "net/util/byte_swap.hpp"
#include "net/protocol/l3.hpp"
#include "net/protocol/l4.hpp"
#include "net/protocol/packet.hpp"

#include "net/util/parse_raw_packet.hpp"

using namespace Logs;

namespace Net
{
static bool parseNetworkLayer(Packet& packet)
{
    switch (packet.data[0] >> 4)
    {
    case 4:
        packet.network_protocol = NetworkProtocol::IPv4;
        packet.network_hdr = packet.data;
        break;

    case 6:
        packet.network_protocol = NetworkProtocol::IPv6;
        packet.network_hdr = packet.data;
        break;

    default:
        return false;
    }

    return true;
}

static bool parseTransportLayer(Packet& packet)
{
    switch (packet.network_protocol)
    {
    case NetworkProtocol::IPv4:
        packet.transport_protocol = static_cast<TransportProtocol>(
            reinterpret_cast<IPv4Hdr*>(packet.network_hdr)->protocol);
        packet.transport_hdr = packet.network_hdr + sizeof(IPv4Hdr);
        break;

    case NetworkProtocol::IPv6:
        packet.transport_protocol = static_cast<TransportProtocol>(
            reinterpret_cast<IPv6Hdr*>(packet.network_hdr)->next_hdr);
        packet.transport_hdr = packet.network_hdr + sizeof(IPv6Hdr);
        break;

    default:
        return false;
    }

    return true;
}

static bool parsePayload(Packet& packet)
{
    switch (packet.transport_protocol)
    {
    case TransportProtocol::TCP:
        packet.payload = packet.transport_hdr +
                         reinterpret_cast<TCPHdr*>(packet.transport_hdr)->getDataOffset() * 4;
        break;

    case TransportProtocol::UDP:
        packet.payload = packet.transport_hdr + sizeof(UDPHdr);
        break;

    default:
        packet.payload = nullptr;
        return true;
    }

    if (packet.payload)
    {
        packet.payload_len = packet.end - packet.payload;
    }

    return true;
}

bool parseRawPacket(uint8_t* rawPacket, size_t rawPacketLen, bool isOutbound, Packet& packet)
{
    if (!rawPacket)
    {
        prErr("rawPacket is nullptr.\n");
        return false;
    }

    packet.data = rawPacket;
    packet.data_len = rawPacketLen;
    packet.end = packet.data + packet.data_len;
    packet.is_outbound = isOutbound;

    if (!parseNetworkLayer(packet))
    {
        prErr("Could not parse network layer of packet.\n");
        return false;
    }

    if (!parseTransportLayer(packet))
    {
        prErr("Could not parse transport layer of packet.\n");
        return false;
    }

    parsePayload(packet);

    return true;
}
} // namespace Net
