// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "core/connection.hpp"
#include "net/packet.hpp"

using namespace Net;

namespace Circumvention
{
bool handlePkt(Packet* packet, Core::TrafficModifier* trafficModifier);
}
