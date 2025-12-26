// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "core/connection.hpp"
#include "packet/pkt.hpp"

namespace Circumvention
{
bool isQUIC(Net::Packet* packet);
} // namespace Circumvention
