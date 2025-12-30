// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "net/packet.hpp"

namespace Net
{
void calcChecksum(Packet* packet);
} // namespace Net
