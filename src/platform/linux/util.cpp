// SPDX-License-Identifier: GPL-3.0-or-later

#include <unistd.h>

#include "platform/linux/util.hpp"

namespace Platform
{
bool isSudo() { return true; }
} // namespace Platform
