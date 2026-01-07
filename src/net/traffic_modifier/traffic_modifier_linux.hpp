// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>

#include "cli/params.hpp"
#include "net/traffic_modifier/traffic_modifier.hpp"

using namespace cli;
using namespace Net;

namespace Net
{
class TrafficModifierLinux final : public TrafficModifier
{
private:
    nfq_handle* netfilter_;
    nfq_q_handle* queue_;
    nfq_callback* pcb_;
    int queueSock;
    char packetBuf_[10000];
    int customPacketSock_;
    bool isSendedCustom_;

    [[nodiscard]]
    bool openNetfilterQueueSystem();
    [[nodiscard]]
    bool openCustomPacketSock();

public:
    TrafficModifierLinux(Params* params, TrafficModifierCallback cb);
    ~TrafficModifierLinux();

    bool handlePacket() override;
    bool sendCustomBeforeOriginal(Packet* packet) override;

    bool isSendedCustom();
};
} // namespace Net
