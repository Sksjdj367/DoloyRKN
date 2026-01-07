// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "cli/params.hpp"
#include "net/protocol/packet.hpp"
#include "net/traffic_modifier/traffic_modifier.hpp"

#include <windivert.h>

using namespace cli;

namespace Net
{
class TrafficModifierWindows final : public TrafficModifier
{
public:
    TrafficModifierWindows(Params* params, TrafficModifierCallback cb);
    ~TrafficModifierWindows();

    [[nodiscard]]
    bool fillPacket(uint8_t* rawPacket, uint32_t rawPacketLen, Packet* packet);
    bool handlePacket(Packet* packet);

    bool handlePacket() override;
    bool sendCustomBeforeOriginal(Packet* packet) override;

private:
    HANDLE winDivert_;
    WINDIVERT_ADDRESS winDivertAddress_;
    uint8_t winDivertPacketBuf_[70000];
};
} // namespace Platform
