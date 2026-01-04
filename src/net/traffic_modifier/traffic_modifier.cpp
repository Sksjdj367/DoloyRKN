// SPDX-License-Identifier: GPL-3.0-or-later

#include "cli/params.hpp"

#if defined(__linux__)
#include "net/traffic_modifier/traffic_modifier_linux.hpp"
using TrafficModifierImpl = Net::TrafficModifierLinux;
#elif defined(__WIN32) || defined(__WIN64)
#include "net/traffic_modifier/traffic_modifier_windows.hpp"
using TrafficModifierImpl = Net::TrafficModifierWindows;
#else
#error "Cannot get TrafficModifier header for targeted platform."
#endif

#include "net/traffic_modifier/traffic_modifier.hpp"

using namespace cli;
using TrafficModifierCallback = TrafficModifier::TrafficModifierCallback;

namespace Net
{
TrafficModifier::TrafficModifier(Params* params, TrafficModifierCallback cb)
    : params_(params), callback_(cb)
{
}

std::unique_ptr<TrafficModifier> TrafficModifier::create(
    Params* params, TrafficModifierCallback callback)
{
    return std::make_unique<TrafficModifierImpl>(params, callback);
}

const Params* TrafficModifier::getParams() const { return params_; }

TrafficModifierCallback TrafficModifier::getCallback() const { return callback_; }
} // namespace Net
