// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include "util/log.hpp"

namespace logs
{
void log(const char* prefix, const char* msg, ...)
{
    va_list args;

    va_start(args, msg);

    fputs(prefix, stderr);
    vfprintf(stderr, msg, args);

    va_end(args);
}

void pr_errno(int errno, const char* msg, ...)
{
    va_list args;

    va_start(args, msg);

    fputs(" ERR:", stderr);
    vfprintf(stderr, msg, args);
    fprintf(stderr, ": errno: %d, errno_str: %s\n", errno, strerror(errno));

    va_end(args);
}
} // namespace logs