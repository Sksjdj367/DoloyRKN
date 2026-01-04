// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdarg.h>
#include <stdio.h>

namespace Logs
{
void prLog(const char* prefix, const char* msg, ...);
void prErrno(int, const char* msg, ...);

#define prInfo(...) prLog("", ##__VA_ARGS__)
#define prWarn(...) prLog("\033[0;92mWarning\033[0m: ", ##__VA_ARGS__)
#define prErr(...)  prLog("\033[0;91mError\033[0m: ", ##__VA_ARGS__)
} // namespace logs