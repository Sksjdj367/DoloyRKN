// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <windows.h>
#include "windivert.h"

#include "cli/params.hpp"
#include "core/connection.hpp"
#include "packet/pkt.hpp"

namespace Platform
{
class TrafficModifier final : public Core::TrafficModifier
{
  public:
    TrafficModifier(cli::Params* params, Core::TrafficModifierCallback cb);
    ~TrafficModifier();

    [[nodiscard]]
    bool init() override;

    [[nodiscard]]
    bool fillPacket(uint8_t* rawPacket, uint32_t rawPacketLen, Net::Packet* packet);
    bool handlePacket(Net::Packet* packet);

    bool handlePackets() override;
    bool sendCustomBeforeOriginal(Net::Packet* packet) override;

  private:
    HANDLE winDivert_;
    WINDIVERT_ADDRESS winDivertAddress_;
    uint8_t winDivertPacketBuf_[70000];
};
} // namespace Platform
