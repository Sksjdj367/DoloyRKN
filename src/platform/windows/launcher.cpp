// SPDX-License-Identifier: GPL-3.0-or-later

#include <windows.h>

#include "util/log.hpp"

#include "platform/windows/launcher.hpp"

using namespace logs;

namespace Platform
{
Launcher::Launcher(int argc, char** argv) : Core::Launcher(argc, argv) {}

Launcher::~Launcher() {}

DWORD enableANSIColors()
{
    auto hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hStdout == INVALID_HANDLE_VALUE)
    {
        return GetLastError();
    }

    DWORD dwMode = 0;
    if (!GetConsoleMode(hStdout, &dwMode))
    {
        return GetLastError();
    }

    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    if (!SetConsoleMode(hStdout, dwMode))
    {
        return GetLastError();
    }

    return 0;
}

int Launcher::run()
{
    auto r = enableANSIColors();
    if (r)
    {
        err("Failed to enable ANSI colors support (err=%d)\n", r);
    }

    return Core::Launcher::run();
}
} // namespace Platform
