// SPDX-License-Identifier: GPL-3.0-or-later

#include "cli/params.hpp"

#include "core/connection.hpp"

namespace Core
{
TrafficModifier::TrafficModifier(cli::Params* params, TrafficModifierCallback cb)
    : params_(params), callback_(cb)
{
}

const cli::Params* TrafficModifier::getParams() const { return params_; }

TrafficModifierCallback TrafficModifier::getCallback() const { return callback_; }
} // namespace Core
