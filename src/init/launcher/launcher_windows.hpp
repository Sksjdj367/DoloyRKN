// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "init/launcher/launcher.hpp"

namespace Init
{
class LauncherWindows final : public Init::Launcher
{
public:
    LauncherWindows(int argc, char** argv);
    ~LauncherWindows();

    int run() override;
};
} // namespace Init
