// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "cli/params.hpp"
#include "net/pkt.hpp"

namespace Core
{
class TrafficModifier
{
    using TrafficModifierCallback = bool (*)(Net::Packet*, TrafficModifier*);

  public:
    TrafficModifier(cli::Params* params, TrafficModifierCallback callback);
    virtual ~TrafficModifier() = default;

    [[nodiscard]]
    virtual bool init() = 0;

    virtual bool handlePackets() = 0;
    virtual bool sendCustomBeforeOriginal(Net::Packet* packet) = 0;

    const cli::Params* getParams() const;
    TrafficModifierCallback getCallback() const;

  private:
    const cli::Params* params_;
    const TrafficModifierCallback callback_;
};
typedef bool (*TrafficModifierCallback)(Net::Packet* packet, TrafficModifier* trafficModifier);
} // namespace Core