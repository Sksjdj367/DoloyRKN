// SPDX-License-Identifier: GPL-3.0-or-later

#include "core/connection.hpp"
#include "packet/pkt.hpp"
#include "packet/l3.hpp"
#include "packet/l4.hpp"

#include "circumvention/fake_packet.hpp"

namespace Circumvention
{
void trySendFakePkt(Net::Packet* packet, Core::TrafficModifier* interceptor)
{
    if (packet->transport_protocol != Net::TRANSPORT_PROTOCOLS::TCP)
        return;

    auto TCPHdr = reinterpret_cast<Net::TCPHdr*>(packet->transport_hdr);

    auto def_checksum = TCPHdr->checksum;
    auto def_seq = TCPHdr->seq;
    auto def_ack = TCPHdr->ack;

    if (interceptor->getParams()->do_fp_tcp_fake_checksum)
    {
        interceptor->sendCustomBeforeOriginal(packet);
        TCPHdr->checksum = def_checksum * 2;
    }
    if (interceptor->getParams()->do_fp_tcp_fake_seq)
        TCPHdr->seq = def_seq * 2;
    if (interceptor->getParams()->do_fp_tcp_fake_ack)
        TCPHdr->ack = def_ack * 2;

    // Empirically established: for successful DPI bypass, packets must leave with
    // a minimum time gap, which is created by the logic for checking conditions between calls.
    // Call grouping makes circumvention ineffective.
    interceptor->sendCustomBeforeOriginal(packet);

    TCPHdr->checksum = def_checksum;
    TCPHdr->seq = def_seq;
    TCPHdr->ack = def_ack;
}
} // namespace Circumvention