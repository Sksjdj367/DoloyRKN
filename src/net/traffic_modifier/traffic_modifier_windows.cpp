// SPDX-License-Identifier: GPL-3.0-or-later

#include <string>

#include "util/log.hpp"
#include "net/protocol/packet.hpp"
#include "net/util/parse_raw_packet.hpp"
#include "net/traffic_modifier/traffic_modifier.hpp"

#include <windivert.h>

#include "net/traffic_modifier/traffic_modifier_windows.hpp"

using namespace Logs;
using namespace cli;
using namespace Net;

namespace Net
{
TrafficModifierWindows::TrafficModifierWindows(Params* params, TrafficModifierCallback cb)
    : TrafficModifier(params, cb)
{
}

TrafficModifierWindows::~TrafficModifierWindows() { WinDivertClose(winDivert_); }

constexpr const char* filter = "!loopback and !icmp and !icmpv6 and !ipv6";

std::string_view getWinDivertOpenErrorStr(DWORD err)
{
    switch (err)
    {
    case 2:
        return "The driver files WinDivert32.sys or WinDivert64.sys were not found.";
    case 5:
        return "You must run application with Administrator privelegies.";
    case 87:
        return "Invalid packet filter string, layer, priority, or flags.";
    case 577:
        return "The driver does not have a valid digital signature.";
    case 654:
        return "An incompatible version of the WinDivert driver is loaded.";
    case 1060:
        return "Driver not installed (WINDIVERT_FLAG_NO_INSTALL was used).";
    case 1275:
        return "Driver blocked by security software or virtualization issue.";
    case 1753:
        return "Base Filtering Engine (BFE) service is disabled.";
    default:
        return "Unknown error.";
    }
}

[[nodiscard]]
bool TrafficModifierWindows::init()
{
    winDivert_ = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, WINDIVERT_PRIORITY_HIGHEST, 0);
    if (winDivert_ == INVALID_HANDLE_VALUE)
    {
        auto error = GetLastError();
        auto errStr = getWinDivertOpenErrorStr(error);

        prErr("Could not open WinDivert (error: %d), %s\n", error, errStr);

        return false;
    }

    return true;
}

bool TrafficModifierWindows::handlePacket(Packet* packet)
{
    if (getCallback()(packet, this))
    {
        WinDivertSend(winDivert_, packet->data, packet->data_len, 0, &winDivertAddress_);
    }
    return 1;
}

bool TrafficModifierWindows::handlePacket()
{
    Packet packet;
    uint32_t rv;

    if (!WinDivertRecv(
            winDivert_, winDivertPacketBuf_, sizeof(winDivertPacketBuf_), &rv, &winDivertAddress_))
    {
        prErr("Could not recv packet from WinDivert handle\n");
        return 0;
    }

    if (!parseRawPacket(winDivertPacketBuf_, rv, winDivertAddress_.Outbound, packet))
    {
        prErr("Failed to parse packet.\n");
        return 0;
    }

    if (!handlePacket(&packet))
    {
        prErr("Could not handle packet");
    }

    return 1;
}

bool TrafficModifierWindows::sendCustomBeforeOriginal(Packet* packet)
{
    if (!WinDivertSend(winDivert_, packet->data, packet->data_len, 0, &winDivertAddress_))
    {
        prInfo("Failed to send custom!\n");
        return false;
    }

    return true;
}
} // namespace Net
