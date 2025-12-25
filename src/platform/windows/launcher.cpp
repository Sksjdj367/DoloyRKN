// SPDX-License-Identifier: GPL-3.0-or-later

#include "util/log.hpp"

#include "platform/windows/launcher.hpp"

namespace Platform
{
Launcher::Launcher(int argc, char** argv) : Core::Launcher(argc, argv) {}

Launcher::~Launcher() {}

int Launcher::run() { return Core::Launcher::run(); }
} // namespace Platform
