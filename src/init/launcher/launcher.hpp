// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <memory>

#include "cli/params.hpp"
#include "net/traffic_modifier/traffic_modifier.hpp"

using namespace cli;
using namespace Net;

namespace Init
{
class Launcher
{
public:
    Launcher(int argc, char** argv);
    virtual ~Launcher();

    static std::unique_ptr<Launcher> create(int argc, char** argv);

    virtual int run() = 0;

private:
    int argc_;
    char** argv_;

    void logProgramInfo() const;
    [[nodiscard]]
    const std::unique_ptr<Params> parseArgs();
    [[nodiscard]]
    std::unique_ptr<TrafficModifier> createTrafficModifier(Params* params) const;
    [[nodiscard]]
    bool runFilterLoop(std::unique_ptr<TrafficModifier>& pkt_interceptor) const;
};
} // namespace Core
