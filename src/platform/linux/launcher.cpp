// SPDX-License-Identifier: GPL-3.0-or-later

#include <errno.h>
#include <stdlib.h>

#include "platform/linux/util.hpp"
#include "util/log.hpp"

#include "platform/linux/launcher.hpp"

namespace Platform
{
Launcher::Launcher(int argc, char** argv) : Core::Launcher(argc, argv) {}

Launcher::~Launcher() {}

[[nodiscard]]
bool setupIptablesRules()
{
    if (system("sudo iptables -t mangle -A OUTPUT -j NFQUEUE --queue-num 0 --queue-bypass &&"
               "sudo iptables -t mangle -A INPUT -j NFQUEUE --queue-num 0 --queue-bypass") != 0)
    {
        logs::err(
            "Cannot create iptables rules, potential error resons:\n"
            "If you updated your kernel but not rebooted, then reboot\n"
            "If you disabled your iptables, then enable it\n"
            "If you removed iptables, then install it\n"
            "If your Linux version is less than 2.4, then update your kernel, dinosaur!\n");
        return 0;
    }

    return true;
}

int Launcher::run()
{
    if (!isSudo())
    {
        logs::err("you cannot perform launch without sudo or root\n");
        return EACCES;
    }

    if (!setupIptablesRules())
        return 1;

    return Core::Launcher::run();
}
} // namespace Platform
