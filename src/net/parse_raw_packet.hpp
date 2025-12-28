#pragma once

#include "net/packet.hpp"

namespace Net
{
bool parseRawPacket(uint8_t* rawPacket, size_t rawPacketLen, Packet* packet);
} // namespace Net
