// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdarg.h>
#include <stdio.h>

namespace logs
{
void log(const char* prefix, const char* msg, ...);
void pr_errno(int, const char* msg, ...);

#define info(...) log("", ##__VA_ARGS__)
#define warn(...) log("\033[0;92mWarning\033[0m: ", ##__VA_ARGS__)
#define err(...)  log("\033[0;91mError\033[0m: ", ##__VA_ARGS__)
} // namespace logs