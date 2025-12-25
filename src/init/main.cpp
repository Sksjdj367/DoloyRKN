// SPDX-License-Identifier: GPL-3.0-or-later

#include "core/launcher.hpp"

int main(int argc, char** argv)
{
    auto launcher = Core::Launcher::create(argc, argv);

    return launcher ? launcher->run() : 1;
}