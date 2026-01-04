#pragma once

#include "net/protocol/packet.hpp"

namespace Net
{
bool parseRawPacket(uint8_t* rawPacket, size_t rawPacketLen, bool isOutbound, Packet& packet);
} // namespace Net
