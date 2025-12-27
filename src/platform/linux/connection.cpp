// SPDX-License-Identifier: GPL-3.0-or-later

#include <errno.h>
#include <netinet/in.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <string.h>
#include <unistd.h>

#include "util/log.hpp"
#include "cli/params.hpp"
#include "core/connection.hpp"
#include "platform/linux/netfilter_util.hpp"
#include "net/pkt.hpp"
#include "net/parse_raw_packet.hpp"

#include "platform/linux/connection.hpp"

namespace Platform
{
using namespace logs;
using namespace Net;

int customPacketSock;

constexpr int sockFamily = AF_INET;
constexpr int netfilterQueueId = 0;

TrafficModifier::TrafficModifier(cli::Params* params, Core::TrafficModifierCallback cb)
    : Core::TrafficModifier(params, cb)
{
}

TrafficModifier::~TrafficModifier()
{
    nfq_destroy_queue(netfilterQueueQueue_);
    nfq_close(netfilterQueue_);
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
    auto trafficModifier = reinterpret_cast<TrafficModifier*>(data);

    if (!trafficModifier)
    {
        err("Traffic modifier is nullptr, did we give it?\n");
        return -1;
    }

    if (!nfmsg)
    {
        pr_errno(errno, "nfmsg is nullptr\n");
        return -1;
    }

    if (!fillPacketInfo(&packetInfo, nfad))
    {
        pr_errno(errno, "Cannot get packet info from netfilter_queue data\n");
        return -1;
    }

    if (!Net::parseRawPacket(packetInfo.data, packetInfo.data_len, &packet))
    {
        err("Failed to properly fill packet from packet info\n");
        return -1;
    }

    NetfilterContext context = {gh, trafficModifier, &packet, &packetInfo};

    handleInputPacket(&context);

    return 0;
}

bool TrafficModifier::openNetfilterQueueSystem()
{
    netfilterQueue_ = nfq_open();
    if (!netfilterQueue_)
    {
        info("Failed to open netfilter");
        return 0;
    }

    if (nfq_unbind_pf(netfilterQueue_, sockFamily))
    {
        err("Failed to unbind queue");
        nfq_close(netfilterQueue_);
        return 0;
    }

    if (nfq_bind_pf(netfilterQueue_, sockFamily))
    {
        pr_errno(errno, "Failed to bind queue");
        nfq_close(netfilterQueue_);
        return 0;
    }

    netfilterQueueQueue_ =
        nfq_create_queue(netfilterQueue_, netfilterQueueId, &cb, reinterpret_cast<void*>(this));
    if (!netfilterQueueQueue_)
    {
        nfq_close(netfilterQueue_);
        pr_errno(errno, "Failed to create queue");
        return 0;
    }

    if (nfq_set_mode(netfilterQueueQueue_, NFQNL_COPY_PACKET, sizeof(packetBuf_)))
    {
        pr_errno(errno, "Failed to set queue mode");
        nfq_destroy_queue(netfilterQueueQueue_);
        nfq_close(netfilterQueue_);
        return 0;
    }

    if (nfq_set_queue_maxlen(netfilterQueueQueue_, 65535) == -1)
    {
        pr_errno(errno, "Failed to set queue max length\n");
    }

    netfilterQueueSock = nfq_fd(netfilterQueue_);

    return 1;
}

bool TrafficModifier::openCustomPacketSock()
{
    customPacketSock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (customPacketSock == -1)
    {
        pr_errno(errno, "Cannot open socket for sending custom packets");
        return 0;
    }

    if (setsockopt(customPacketSock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) == -1)
    {
        pr_errno(errno, "Cannot set socket option IP_HDRINCL");
        close(customPacketSock);
        return 0;
    }

    if (setsockopt(customPacketSock, SOL_SOCKET, SO_PRIORITY, &priority, sizeof(priority)) == -1)
    {
        pr_errno(errno, "Cannot set socket option SO_PRIORITY");
        close(customPacketSock);
        return 0;
    }

    if (setsockopt(customPacketSock, SOL_SOCKET, SO_MARK, &CustomPacketMark, sizeof(priority)) ==
        -1)
    {
        pr_errno(errno, "Cannot set socket option SO_MARK");
        close(customPacketSock);
        return 0;
    }

    return 1;
}

bool TrafficModifier::init()
{
    if (!openNetfilterQueueSystem())
        return 0;

    if (!openCustomPacketSock())
        return 0;

    return 1;
}

bool TrafficModifier::handlePackets()
{
    while (true)
    {
        memset(packetBuf_, 0, sizeof(packetBuf_));

        auto rv = recv(netfilterQueueSock, packetBuf_, sizeof(packetBuf_), 0);
        if (rv == -1)
        {
            pr_errno(errno, "Could not recv packet from netfilterQueueSock");
            return 0;
        }

        if (isSendedCustom_)
        {
            isSendedCustom_ = false;
        }

        if (nfq_handle_packet(netfilterQueue_, packetBuf_, static_cast<int>(rv)) != 0)
        {
            pr_errno(errno, "Error during packet handling");
            return 0;
        }
    }

    return 1;
}

bool TrafficModifier::sendCustomBeforeOriginal(Packet* packet)
{
    isSendedCustom_ = true;

    auto ip = reinterpret_cast<uint32_t*>(
        reinterpret_cast<ipv4_hdr*>(packet->network_hdr)->dst_ip.addr)[0];

    struct sockaddr_in addr = {AF_INET, htons(443), {ip}, 0};

    if (sendto(customPacketSock,
            reinterpret_cast<uint8_t*>(packet->data),
            packet->data_len,
            0,
            reinterpret_cast<sockaddr*>(&addr),
            sizeof(addr)) == -1)
    {
        pr_errno(errno, "Cannot send packet\n");
    }

    return 0;
}

bool TrafficModifier::isSendedCustom() { return isSendedCustom_; }
} // namespace Platform
