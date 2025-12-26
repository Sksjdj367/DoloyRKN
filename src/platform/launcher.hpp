// SPDX-License-Identifier: GPL-3.0-or-later

#if defined(__linux__)
#include "platform/linux/launcher.hpp"
#elif defined(__WIN32) || defined(__WIN64)
#include "platform/windows/launcher.hpp"
#endif