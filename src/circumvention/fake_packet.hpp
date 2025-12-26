// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "core/connection.hpp"
#include "packet/pkt.hpp"

namespace Circumvention
{
void trySendFakePkt(Net::Packet* packet, Core::TrafficModifier* trafficModifier);
}