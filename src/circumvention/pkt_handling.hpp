// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "core/connection.hpp"
#include "net/pkt.hpp"

namespace Circumvention
{
bool handlePkt(Net::Packet* packet, Core::TrafficModifier* trafficModifier);
}
