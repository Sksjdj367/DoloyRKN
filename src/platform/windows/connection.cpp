// SPDX-License-Identifier: GPL-3.0-or-later

#include "windivert.h"

#include "core/connection.hpp"
#include "packet/pkt.hpp"
#include "util/log.hpp"

#include "connection.hpp"

namespace Platform
{
TrafficModifier::TrafficModifier(cli::Params* params, Core::TrafficModifierCallback cb)
    : Core::TrafficModifier(params, cb)
{
}

TrafficModifier::~TrafficModifier() { WinDivertClose(winDivert_); }

constexpr const char* windivertFilterStr = "outbound and !loopback and !icmp and !icmpv6";

[[nodiscard]]
bool TrafficModifier::init()
{
    winDivert_ =
        WinDivertOpen(windivertFilterStr, WINDIVERT_LAYER_NETWORK, WINDIVERT_PRIORITY_HIGHEST, 0);
    if (winDivert_ == INVALID_HANDLE_VALUE)
    {
        auto error = GetLastError();
        logs::err("Could not open WinDivert, error %d\n", error);

        switch (error)
        {
        case 2:
            logs::err("The driver files WinDivert32.sys or WinDivert64.sys were not found.\n");
            break;
        case 5:
            logs::err("The calling application does not have Administrator privileges.\n");
            break;
        case 87:
            logs::err("Invalid packet filter string, layer, priority, or flags.\n");
            break;
        case 577:
            logs::err(
                "The WinDivert32.sys or WinDivert64.sys driver does not have a valid digital "
                "signature\n");
            break;
        case 654:
            logs::err("An incompatible version of the WinDivert driver is currently loaded.\n");
            break;
        case 1060:
            logs::err(
                "The handle was opened with the WINDIVERT_FLAG_NO_INSTALL flag and the "
                "WinDivert driver is not already installed.\n");
            break;
        case 1275:
            logs::err(
                "This error occurs for various reasons, including:\n"
                "the WinDivert driveris blocked by security software;\n"
                "or you are using a virtualization environment that does not support drivers.\n");
            break;
        case 1753:
            logs::err("Base Filtering Engine service has been disabled.\n");
            break;
        default:
            logs::err("Unknown error\n");
            break;
        }

        return 0;
    }

    return 1;
}

[[nodiscard]]
bool TrafficModifier::fillPacket(uint8_t* rawPacket, uint32_t rawPacketLen, Net::Packet* packet)
{
    WINDIVERT_IPHDR* IPv4Hdr;
    WINDIVERT_IPV6HDR* IPv6Hdr;

    WINDIVERT_TCPHDR* TCPHdr;
    WINDIVERT_UDPHDR* UDPHdr;

    void* payload;
    uint32_t payload_len;

    if (!WinDivertHelperParsePacket(rawPacket,
            rawPacketLen,
            &IPv4Hdr,
            &IPv6Hdr,
            reinterpret_cast<uint8_t*>(&packet->transport_protocol),
            nullptr,
            nullptr,
            &TCPHdr,
            &UDPHdr,
            &payload,
            &payload_len,
            nullptr,
            nullptr))
    {
        logs::err("Cannot parse packet\n");
        return 0;
    }

    if (IPv4Hdr)
    {
        packet->data = reinterpret_cast<uint8_t*>(IPv4Hdr);
        packet->network_protocol = Net::NETWORK_PROTOCOLS::IPV4;
    }
    else
    {
        packet->data = reinterpret_cast<uint8_t*>(IPv6Hdr);
        packet->network_protocol = Net::NETWORK_PROTOCOLS::IPV6;
    }

    packet->network_hdr = packet->data;

    if (TCPHdr)
    {
        packet->transport_hdr = reinterpret_cast<uint8_t*>(TCPHdr);
        packet->transport_protocol = Net::TRANSPORT_PROTOCOLS::TCP;
    }
    else
    {
        packet->transport_hdr = reinterpret_cast<uint8_t*>(UDPHdr);
        packet->transport_protocol = Net::TRANSPORT_PROTOCOLS::UDP;
    }

    packet->data_len = rawPacketLen;

    return 1;
}

bool TrafficModifier::handlePacket(Net::Packet* packet)
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
        Net::Packet packet;
        uint32_t rv;

        if (!WinDivertRecv(winDivert_,
                winDivertPacketBuf_,
                sizeof(winDivertPacketBuf_),
                &rv,
                &winDivertAddress_))
        {
            logs::err("Could not recv packet from WinDivert handle\n");
            return 0;
        }

        if (!fillPacket(winDivertPacketBuf_, rv, &packet))
        {
            logs::err("Failed to fill packet\n");
            return 0;
        }

        if (!handlePacket(&packet))
        {
            logs::err("Could not handle packet");
        }
    }

    return 1;
}

bool TrafficModifier::sendCustomBeforeOriginal(Net::Packet* packet)
{
    if (!WinDivertSend(winDivert_, packet->data, packet->data_len, 0, &winDivertAddress_))
    {
        logs::info("Failed to send custom!\n");
    }

    return 1;
}
} // namespace Platform
