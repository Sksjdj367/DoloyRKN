// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <memory>

#include "cli/params.hpp"

namespace cli
{
[[nodiscard]]
const std::unique_ptr<Params> parseArgs(int argc, char** argv);
}