// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#if defined __linux__
#include "platform/linux/connection.hpp"
#elif defined __WIN32 || defined __WIN64
#include "platform/windows/connection.hpp"
#endif