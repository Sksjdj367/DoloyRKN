// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdarg.h>
#include <stdio.h>

namespace logs
{
void log(const char* prefix, const char* msg, ...);
void pr_errno(int, const char* msg, ...);

#define info(...) log("", ##__VA_ARGS__)
#define warn(...) log("WARN: ", ##__VA_ARGS__)
#define err(...) log(" ERR: ", ##__VA_ARGS__)
} // namespace logs