// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>

#include "cli/params.hpp"
#include "core/connection.hpp"

namespace Platform
{
class TrafficModifier final : public Core::TrafficModifier
{
  private:
    nfq_handle* netfilter_;
    nfq_q_handle* queue_;
    nfq_callback* pcb_;
    int queueSock;
    char packetBuf_[10000];
    bool isSendedCustom_;

    [[nodiscard]]
    bool openNetfilterQueueSystem();
    [[nodiscard]]
    bool openCustomPacketSock();

  public:
    TrafficModifier(cli::Params* params, Core::TrafficModifierCallback cb);
    ~TrafficModifier();

    [[nodiscard]]
    bool init() override;

    bool handlePackets() override;
    bool sendCustomBeforeOriginal(Net::Packet* packet) override;

    bool isSendedCustom();
};
} // namespace Platform
