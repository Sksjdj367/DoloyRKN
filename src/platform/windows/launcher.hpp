// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "core/launcher.hpp"

namespace Platform
{
class Launcher final : public Core::Launcher
{
  public:
    Launcher(int argc, char** argv);
    ~Launcher();

    int run() override;
};
} // namespace Platform
