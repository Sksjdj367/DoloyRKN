// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "cli/params.hpp"
#include "net/packet.hpp"

using namespace cli;
using namespace Net;

namespace Circumvention
{
bool isDNSRequest(const Packet* packet);
bool isDNSResponse(const Packet* packet);
void substituteDNSRequest(const Params* params, Packet* packet);
void substituteDNSResponse(Packet* packet);
} // namespace Circumvention
