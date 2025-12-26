// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>

#include "util/log.hpp"
#include "platform/linux/connection.hpp"

namespace Platform
{
struct NetfilterPacketInfo
{
    uint32_t id;
    uint8_t* data;
    uint32_t data_len;
    uint32_t mark;
};

struct NetfilterContext
{
    nfq_q_handle* netfilter_queue_handle;
    TrafficModifier* trafficModifier;
    Net::Packet* packet;
    NetfilterPacketInfo* packetInfo;
};

[[nodiscard]]
bool fillPacketInfo(NetfilterPacketInfo* packetInfo, nfq_data* nfad);
bool fillPacket(Net::Packet* packet, NetfilterPacketInfo* packetInfo);

constexpr int CustomPacketMark = 187;
constexpr int OriginalQueuedPacketMark = 136;

inline void acceptPacket(NetfilterContext* context)
{
    nfq_set_verdict(context->netfilter_queue_handle,
        context->packetInfo->id,
        NF_ACCEPT,
        context->packetInfo->data_len,
        context->packetInfo->data);
}

inline void queuePacket(NetfilterContext* context)
{
    nfq_set_verdict2(context->netfilter_queue_handle,
        context->packetInfo->id,
        NF_REPEAT,
        OriginalQueuedPacketMark,
        context->packetInfo->data_len,
        context->packetInfo->data);
}

inline void dropPacket(NetfilterContext* context)
{
    nfq_set_verdict(context->netfilter_queue_handle,
        context->packetInfo->id,
        NF_DROP,
        context->packetInfo->data_len,
        context->packetInfo->data);
}

inline bool isCustomPacket(NetfilterPacketInfo* packetInfo)
{
    return packetInfo->mark == CustomPacketMark;
}

inline bool isOriginalQueuedPacket(NetfilterPacketInfo* packetInfo)
{
    return packetInfo->mark == OriginalQueuedPacketMark;
}
} // namespace Platform
