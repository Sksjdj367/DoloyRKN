// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "core/connection.hpp"
#include "net/packet.hpp"

using namespace Net;

namespace Circumvention
{
void trySendFakePkt(Packet* packet, Core::TrafficModifier* trafficModifier);
}