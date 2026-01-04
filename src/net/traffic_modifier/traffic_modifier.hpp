// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <memory>

#include "cli/params.hpp"
#include "net/protocol/packet.hpp"

using namespace cli;
using namespace Net;

namespace Net
{
class TrafficModifier
{
public:
    using TrafficModifierCallback = bool (*)(Packet*, TrafficModifier*);

    TrafficModifier(Params* params, TrafficModifierCallback callback);
    virtual ~TrafficModifier() = default;

    static std::unique_ptr<TrafficModifier> create(
        Params* params, TrafficModifierCallback callback);

    [[nodiscard]]
    virtual bool init() = 0;

    virtual bool handlePacket() = 0;
    virtual bool sendCustomBeforeOriginal(Packet* packet) = 0;

    const Params* getParams() const;
    TrafficModifierCallback getCallback() const;

private:
    const Params* params_;
    const TrafficModifierCallback callback_;
};
} // namespace Net