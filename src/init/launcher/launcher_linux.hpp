// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "init/launcher/launcher.hpp"

namespace Init
{
class LauncherLinux final : public Init::Launcher
{
public:
    LauncherLinux(int argc, char** argv);
    ~LauncherLinux();

    int run() override;
};
} // namespace Init
