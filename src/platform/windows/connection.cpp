// SPDX-License-Identifier: GPL-3.0-or-later

#include <string>
#include <windivert.h>

#include "util/log.hpp"
#include "core/connection.hpp"
#include "net/pkt.hpp"
#include "net/parse_raw_packet.hpp"

#include "connection.hpp"

using namespace logs;
using namespace Net;

namespace Platform
{
TrafficModifier::TrafficModifier(cli::Params* params, Core::TrafficModifierCallback cb)
    : Core::TrafficModifier(params, cb)
{
}

TrafficModifier::~TrafficModifier() { WinDivertClose(winDivert_); }

constexpr const char* filter = "outbound and !loopback and !icmp and !icmpv6";

std::string_view getWindivertOpenErrorStr(DWORD err)
{
    switch (err)
    {
    case 2:
        return "The driver files WinDivert32.sys or WinDivert64.sys were not found.";
    case 5:
        return "The calling application does not have Administrator privileges.";
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
bool TrafficModifier::init()
{
    winDivert_ = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, WINDIVERT_PRIORITY_HIGHEST, 0);
    if (winDivert_ == INVALID_HANDLE_VALUE)
    {
        auto error = GetLastError();
        auto errStr = getWindivertOpenErrorStr(error);

        err("Could not open WinDivert (error=%d), %s\n", error, errStr);

        return false;
    }

    return true;
}

bool TrafficModifier::handlePacket(Packet* packet)
{
    if (getCallback()(packet, this))
    {
        WinDivertSend(winDivert_, packet->data, packet->data_len, 0, &winDivertAddress_);
    }
    return 1;
}

bool TrafficModifier::handlePackets()
{
    while (true)
    {
        Packet packet;
        uint32_t rv;

        if (!WinDivertRecv(winDivert_,
                winDivertPacketBuf_,
                sizeof(winDivertPacketBuf_),
                &rv,
                &winDivertAddress_))
        {
            err("Could not recv packet from WinDivert handle\n");
            return 0;
        }

        if (!parseRawPacket(winDivertPacketBuf_, rv, &packet))
        {
            err("Failed to parse packet.\n");
            return 0;
        }

        if (!handlePacket(&packet))
        {
            err("Could not handle packet");
        }
    }

    return 1;
}

bool TrafficModifier::sendCustomBeforeOriginal(Packet* packet)
{
    if (!WinDivertSend(winDivert_, packet->data, packet->data_len, 0, &winDivertAddress_))
    {
        info("Failed to send custom!\n");
    }

    return 1;
}
} // namespace Platform
