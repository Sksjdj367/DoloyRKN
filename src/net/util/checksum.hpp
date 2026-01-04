// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "net/protocol/packet.hpp"

namespace Net
{
void calcChecksum(Packet* packet);
} // namespace Net
