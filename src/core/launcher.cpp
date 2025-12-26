// SPDX-License-Identifier: GPL-3.0-or-later

#include <errno.h>
#include <memory>
#include <stdio.h>
#include <unistd.h>

#include "util/log.hpp"
#include "platform/connection.hpp"
#include "platform/launcher.hpp"
#include "platform/release.hpp"
#include "cli/parsing.hpp"
#include "packet/pkt.hpp"
#include "circumvention/pkt_handling.hpp"

#include "core/launcher.hpp"

using namespace logs;

namespace Core
{
Launcher::Launcher(int argc, char** argv) : argc_(argc), argv_(argv) {}

Launcher::~Launcher() {}

std::unique_ptr<Launcher> Launcher::create(int argc, char** argv)
{
    return std::make_unique<Platform::Launcher>(argc, argv);
}

void Launcher::logProgramInfo() const
{
    info(
        "%s v%s for %s %s: DPI Circumvention Utility\n"
        "\n",
        Platform::name,
        Platform::version,
        Platform::os,
        Platform::arch);

    info("argv: {");
    for (int i = 0; i < argc_; i++)
    {
        info("%s ", argv_[i]);
    }
    info("\b}\n\n");
}

[[nodiscard]]
const std::unique_ptr<cli::Params> Launcher::parseArgs()
{
    auto params = cli::parseArgs(argc_, argv_);
    if (!params)
    {
        err("Error during args parsing\n");
        return nullptr;
    }

    return params;
}

[[nodiscard]]
std::unique_ptr<TrafficModifier> Launcher::createTrafficModifier(cli::Params* params) const
{
    auto trafficModifier =
        std::make_unique<Platform::TrafficModifier>(params, &Circumvention::handlePkt);

    if (!trafficModifier)
    {
        err("Failed to open traffic modifier.\n");
        return nullptr;
    }

    if (!trafficModifier->init())
    {
        err("Failed to init packet interceptor.\n");
        return nullptr;
    }

    info("Filter opened, circumvention is running!\n\n");

    return trafficModifier;
}

[[nodiscard]]
bool Launcher::runFilterLoop(std::unique_ptr<TrafficModifier>& trafficModifier) const
{
    while (true)
    {
        if (!trafficModifier->handlePackets())
        {
            err("Could not handle packet\n");
            return 0;
        }
    }

    return 1;
}

void printHelp()
{
    info(
        "Usage: %s [OPTIONS]\n"
        "OPTIONS:\n"
        "  -c --fp-fake-tcp-checksum set fake checksum in fake packet tcp header\n"
        "  -s --fp-fake-tcp-seq      set fake seq in fake packet tcp header\n"
        "  -a --fp-fake-tcp-ack      set fake ack in fake packet tcp header\n"
        "  -F --fp-from-hex <hex>    use custom fake packet from hex\n"
        "\n"
        "  -q --block-quic           drop all quic traffic, greatly increases traffic speed "
        "when using fake packets\n"
        "\n"
        "  -h --help                 print this help and exit\n"
        "",
        Platform::name);
}

void logParams(struct cli::Params* params)
{
    info(
        "Fake packet                   : %d\n"
        "Fake packet fake TCP checksum : %d\n"
        "Fake packet fake TCP seq      : %d\n"
        "Fake packet fake TCP ack      : %d\n"
        "Fake packet from hex          : %d\n"
        "Block QUIC                    : %d\n"
        "Show Help                     : %d\n"
        "\n",
        params->do_fake_packet,
        params->do_fp_tcp_fake_checksum,
        params->do_fp_tcp_fake_seq,
        params->do_fp_tcp_fake_ack,
        params->fake_from_hex != nullptr,
        params->do_block_quic,
        params->do_help);
}

[[nodiscard]]
bool handleExitOpts(cli::Params& params)
{
    if (params.do_help)
    {
        printHelp();
        return true;
    }

    return false;
}

int Launcher::run()
{
    logProgramInfo();

    auto params = parseArgs();
    if (!params)
        return 1;

    logParams(params.get());

    if (params->do_help)
    {
        printHelp();
        return EXIT_SUCCESS;
    }

    auto trafficModifier = createTrafficModifier(params.get());
    if (!trafficModifier)
        return EXIT_FAILURE;

    if (!runFilterLoop(trafficModifier))
    {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
} // namespace Core
