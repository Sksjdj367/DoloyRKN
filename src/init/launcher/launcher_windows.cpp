// SPDX-License-Identifier: GPL-3.0-or-later

#include <windows.h>

#include "util/log.hpp"

#include "init/launcher/launcher_windows.hpp"

using namespace Logs;

namespace Init
{
LauncherWindows::LauncherWindows(int argc, char** argv) : Launcher(argc, argv) {}

LauncherWindows::~LauncherWindows() {}

DWORD enableANSIColors()
{
    auto hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hStdout == INVALID_HANDLE_VALUE)
        return GetLastError();

    DWORD dwMode{};
    if (!GetConsoleMode(hStdout, &dwMode))
        return GetLastError();

    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    if (!SetConsoleMode(hStdout, dwMode))
        return GetLastError();

    return 0;
}

int LauncherWindows::run()
{
    auto res = enableANSIColors();
    if (res)
        prErr("Failed to enable ANSI colors support (err=%d)\n", res);

    return Launcher::run();
}
} // namespace Init
