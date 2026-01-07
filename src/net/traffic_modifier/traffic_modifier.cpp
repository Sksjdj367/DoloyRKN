// SPDX-License-Identifier: GPL-3.0-or-later

#include <system_error>

#include "util/log.hpp"
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

using namespace Logs;
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
    try
    {
        auto trafficModifier = std::make_unique<TrafficModifierImpl>(params, callback);
        return trafficModifier;
    }
    catch (const std::system_error& e)
    {
        prErr("Cannot create TrafficModifier: %s\n", e.what());
        return nullptr;
    }
}

const Params* TrafficModifier::getParams() const { return params_; }

TrafficModifierCallback TrafficModifier::getCallback() const { return callback_; }
} // namespace Net
