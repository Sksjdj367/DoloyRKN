// SPDX-License-Identifier: GPL-3.0-or-later

#include "init/launcher/launcher.hpp"

int main(int argc, char** argv)
{
    auto launcher = Init::Launcher::create(argc, argv);

    return launcher ? launcher->run() : 1;
}