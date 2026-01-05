// SPDX-License-Identifier: GPL-3.0-or-later

#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "util/log.hpp"
#include "net/util/byte_swap.hpp"
#include "cli/params.hpp"
#include "net/traffic_modifier/netfilter_util.hpp"
#include "net/protocol/packet.hpp"
#include "net/util/parse_raw_packet.hpp"
#include "net/traffic_modifier/traffic_modifier.hpp"

#include "net/traffic_modifier/traffic_modifier_linux.hpp"

using namespace Logs;
using namespace cli;

namespace Net
{
constexpr int sockFamily = AF_INET;
constexpr int netfilterQueueId = 0;

TrafficModifierLinux::TrafficModifierLinux(Params* params, TrafficModifierCallback cb)
    : TrafficModifier(params, cb)
{
}

TrafficModifierLinux::~TrafficModifierLinux()
{
    close(customPacketSock_);
    nfq_destroy_queue(queue_);
    nfq_close(netfilter_);
}

constexpr int one = 1;
constexpr int priority = 6;

void handleInputPacket(NetfilterContext* context)
{
    auto packetInfo = context->packetInfo;

    if (isCustomPacket(packetInfo) || isOriginalQueuedPacket(packetInfo))
    {
        acceptPacket(context);
        return;
    }

    auto trafficModifier = context->trafficModifier;

    if (trafficModifier->getCallback()(context->packet, trafficModifier))
    {
        trafficModifier->isSendedCustom() ? queuePacket(context) : acceptPacket(context);
    }
    else
    {
        dropPacket(context);
    }
}

int cb(struct nfq_q_handle* gh, struct nfgenmsg* nfmsg, struct nfq_data* nfad, void* data)
{
    NetfilterPacketInfo packetInfo;
    Packet packet;
    auto trafficModifier = reinterpret_cast<TrafficModifierLinux*>(data);

    if (!trafficModifier)
    {
        prErr("Traffic modifier is nullptr, did we give it?\n");
        return -1;
    }

    if (!nfmsg)
    {
        prErrno(errno, "nfmsg is nullptr\n");
        return -1;
    }

    if (!fillPacketInfo(&packetInfo, nfad))
    {
        prErrno(errno, "Cannot get packet info from netfilter_queue data\n");
        return -1;
    }

    if (!parseRawPacket(packetInfo.data, packetInfo.data_len, nfq_get_outdev(nfad) > 0, packet))
    {
        prErr("Failed to properly fill packet from packet info\n");
        return -1;
    }

    NetfilterContext context = {gh, trafficModifier, &packet, &packetInfo};

    handleInputPacket(&context);

    return 0;
}

bool TrafficModifierLinux::openNetfilterQueueSystem()
{
    netfilter_ = nfq_open();
    if (!netfilter_)
    {
        prInfo("Failed to open netfilter");
        return 0;
    }

    nfnl_rcvbufsiz(nfq_nfnlh(netfilter_), 800000);

    if (nfq_unbind_pf(netfilter_, sockFamily))
    {
        prErr("Failed to unbind queue");
        nfq_close(netfilter_);
        return 0;
    }

    if (nfq_bind_pf(netfilter_, sockFamily))
    {
        prErrno(errno, "Failed to bind queue");
        nfq_close(netfilter_);
        return 0;
    }

    queue_ = nfq_create_queue(netfilter_, netfilterQueueId, &cb, reinterpret_cast<void*>(this));
    if (!queue_)
    {
        nfq_close(netfilter_);
        prErrno(errno, "Failed to create queue");
        return 0;
    }

    if (nfq_set_mode(queue_, NFQNL_COPY_PACKET, sizeof(packetBuf_)))
    {
        prErrno(errno, "Failed to set queue mode");
        nfq_destroy_queue(queue_);
        nfq_close(netfilter_);
        return 0;
    }

    if (nfq_set_queue_maxlen(queue_, 24600) == -1)
    {
        prErrno(errno, "Failed to set queue max length\n");
    }

    queueSock = nfq_fd(netfilter_);

    return 1;
}

bool TrafficModifierLinux::openCustomPacketSock()
{
    customPacketSock_ = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (customPacketSock_ == -1)
    {
        prErrno(errno, "Cannot open socket for sending custom packets");
        return 0;
    }

    if (fcntl(customPacketSock_, F_SETFL, O_NONBLOCK) == -1)
    {
        prErrno(errno, "Cannot set socket option O_NONBLOCK");
        return 0;
    }

    if (setsockopt(customPacketSock_, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) == -1)
    {
        prErrno(errno, "Cannot set socket option IP_HDRINCL");
        close(customPacketSock_);
        return 0;
    }

    if (setsockopt(customPacketSock_, SOL_SOCKET, SO_PRIORITY, &priority, sizeof(priority)) == -1)
    {
        prErrno(errno, "Cannot set socket option SO_PRIORITY");
        close(customPacketSock_);
        return 0;
    }

    if (setsockopt(customPacketSock_, SOL_SOCKET, SO_MARK, &CustomPacketMark, sizeof(priority)) ==
        -1)
    {
        prErrno(errno, "Cannot set socket option SO_MARK");
        close(customPacketSock_);
        return 0;
    }

    return 1;
}

bool TrafficModifierLinux::init()
{
    if (!openNetfilterQueueSystem())
        return 0;

    if (!openCustomPacketSock())
        return 0;

    return 1;
}

bool TrafficModifierLinux::handlePacket()
{
    auto rv = recv(queueSock, packetBuf_, sizeof(packetBuf_), 0);
    if (rv == -1)
    {
        prErrno(errno, "Could not recv packet from queueSock");
        return false;
    }

    if (isSendedCustom_)
        isSendedCustom_ = false;

    if (nfq_handle_packet(netfilter_, packetBuf_, static_cast<int>(rv)) != 0)
    {
        prErrno(errno, "Error during packet handling");
        return false;
    }

    return true;
}

bool TrafficModifierLinux::sendCustomBeforeOriginal(Packet* packet)
{
    isSendedCustom_ = true;

    auto ip = reinterpret_cast<IPv4Hdr*>(packet->network_hdr)->dst_ip;

    struct sockaddr_in addr = {AF_INET, HostToNetShort(443), {ip}, 0};

    if (sendto(customPacketSock_,
            packet->data,
            packet->data_len,
            0,
            reinterpret_cast<sockaddr*>(&addr),
            sizeof(addr)) == -1)
    {
        prErrno(errno, "Cannot send packet\n");
        return 0;
    }

    return 1;
}

bool TrafficModifierLinux::isSendedCustom() { return isSendedCustom_; }
} // namespace Net
