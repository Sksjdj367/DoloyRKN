// SPDX-License-Identifier: GPL-3.0-or-later

#include "net/traffic_modifier/traffic_modifier.hpp"
#include "net/protocol/packet.hpp"
#include "net/protocol/l3.hpp"
#include "net/protocol/l4.hpp"

#include "circumvention/fake_packet.hpp"

using namespace Net;

namespace Circumvention
{
void trySendFakePkt(Packet* packet, TrafficModifier* trafficModifier)
{
    if (packet->transport_protocol != TransportProtocol::TCP)
        return;

    auto tcp_hdr = reinterpret_cast<TCPHdr*>(packet->transport_hdr);
    auto def_checksum = tcp_hdr->checksum;
    auto def_seq = tcp_hdr->seq;
    auto def_ack = tcp_hdr->ack;

    if (trafficModifier->getParams()->do_fp_tcp_fake_checksum)
    {
        trafficModifier->sendCustomBeforeOriginal(packet);
        tcp_hdr->checksum = def_checksum * 2;
    }
    if (trafficModifier->getParams()->do_fp_tcp_fake_seq)
        tcp_hdr->seq = def_seq * 2;
    if (trafficModifier->getParams()->do_fp_tcp_fake_ack)
        tcp_hdr->ack = def_ack * 2;

    // Empirically established: for successful DPI bypass, packets must leave with
    // a minimum time gap, which is created by the logic for checking conditions between calls.
    // Call grouping makes circumvention ineffective.
    trafficModifier->sendCustomBeforeOriginal(packet);

    tcp_hdr->checksum = def_checksum;
    tcp_hdr->seq = def_seq;
    tcp_hdr->ack = def_ack;
}
} // namespace Circumvention