// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "net/traffic_modifier/traffic_modifier.hpp"
#include "net/protocol/packet.hpp"

using namespace Net;

namespace Circumvention
{
bool isQUIC(Packet* packet);
} // namespace Circumvention
