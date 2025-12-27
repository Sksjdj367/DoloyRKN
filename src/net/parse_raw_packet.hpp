#pragma once

#include "net/pkt.hpp"

namespace Net
{
bool parseRawPacket(uint8_t* rawPacket, size_t rawPacketLen, Packet* packet);
} // namespace Net
