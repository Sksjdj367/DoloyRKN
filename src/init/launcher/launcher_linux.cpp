// SPDX-License-Identifier: GPL-3.0-or-later

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include "util/log.hpp"

#include "init/launcher/launcher_linux.hpp"

using namespace Logs;

namespace Init
{
inline bool isSudo() { return geteuid() == 0; }

LauncherLinux::LauncherLinux(int argc, char** argv) : Launcher(argc, argv) {}

LauncherLinux::~LauncherLinux() {}

[[nodiscard]]
bool setupIptablesRules()
{
    system("sudo iptables -t mangle -F");
    if (system("sudo iptables -t mangle -A OUTPUT -j NFQUEUE --queue-num 0 --queue-bypass &&"
               "sudo iptables -t mangle -A INPUT -j NFQUEUE --queue-num 0 --queue-bypass") != 0)
    {
        prErr(
            "Cannot create iptables rules, potential error resons:\n"
            "If you updated your kernel but not rebooted, then reboot.\n"
            "If you disabled your iptables, then enable it.\n"
            "If you removed iptables, then install it.\n"
            "If your Linux version is less than 3.6, than update your kernel.\n");
        return 0;
    }

    return true;
}

int LauncherLinux::run()
{
    if (!isSudo())
    {
        prErr("you cannot perform launch without sudo or root\n");
        return 1;
    }

    if (!setupIptablesRules())
        return 1;

    return Launcher::run();
}
} // namespace Init
