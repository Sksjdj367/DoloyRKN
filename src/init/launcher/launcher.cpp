// SPDX-License-Identifier: GPL-3.0-or-later

#include <string>
#include <errno.h>
#include <memory>
#include <unistd.h>

#include "platform/release.hpp"
#include "util/log.hpp"
#include "cli/parsing.hpp"
#include "circumvention/pkt_handling.hpp"
#include "net/protocol/packet.hpp"
#include "net/util/byte_swap.hpp"
#include "net/util/ip_format.hpp"

#if defined(__linux__)
#include "init/launcher/launcher_linux.hpp"
using LauncherImpl = Init::LauncherLinux;
#elif defined(__WIN32) || defined(__WIN64)
#include "init/launcher/launcher_windows.hpp"
using LauncherImpl = Init::LauncherWindows;
#else
#error "Cannot find launcher impl for targeted platform."
#endif

#include "init/launcher/launcher.hpp"

using namespace Logs;
using namespace cli;
using namespace Net;

namespace Init
{
Launcher::Launcher(int argc, char** argv) : argc_(argc), argv_(argv) {}

Launcher::~Launcher() {}

std::unique_ptr<Launcher> Launcher::create(int argc, char** argv)
{
    return std::make_unique<LauncherImpl>(argc, argv);
}

void Launcher::logProgramInfo() const
{
    prInfo(
        "%s v%s for %s %s: DPI Circumvention Utility\n"
        "\n",
        Platform::name,
        Platform::version,
        Platform::os,
        Platform::arch);

    prInfo("cmd: ");
    for (int i = 0; i < argc_; i++)
    {
        prInfo("%s ", argv_[i]);
    }
    prInfo("\n\n");
}

[[nodiscard]]
const std::unique_ptr<Params> Launcher::parseArgs()
{
    auto params = cli::parseArgs(argc_, argv_);
    if (!params)
    {
        prErr("Error during args parsing\n");
        return nullptr;
    }

    return params;
}

[[nodiscard]]
std::unique_ptr<TrafficModifier> Launcher::createTrafficModifier(Params* params) const
{
    auto trafficModifier = TrafficModifier::create(params, &Circumvention::handlePkt);

    if (!trafficModifier)
    {
        prErr("Failed to open traffic modifier.\n");
        return nullptr;
    }

    if (!trafficModifier->init())
    {
        prErr("Failed to init packet interceptor.\n");
        return nullptr;
    }

    prInfo("Filter opened, circumvention is running!\n\n");

    return trafficModifier;
}

[[nodiscard]]
bool Launcher::runFilterLoop(std::unique_ptr<TrafficModifier>& trafficModifier) const
{
    while (true)
    {
        if (!trafficModifier->handlePacket())
        {
            prErr("Could not handle packet\n");
            return 0;
        }
    }

    return 1;
}

void printHelp()
{
    prInfo(
        "Usage: %s [OPTIONS]\n"
        "OPTIONS:\n"
        "         --dr-ipv4 <ip> -i : redirect to DNS with specified ip\n"
        "         --dr-ipv6 <ip> -I : set dns ipv6 (actually ipv6 is incomplete and does not\n"
        "                             work)\n"
        "\n"
        " --fp-fake-tcp-checksum -c : set fake checksum in fake packet tcp header\n"
        "      --fp-fake-tcp-seq -s : fake seq in TCP\n"
        "      --fp-fake-tcp-ack -a : fake ack in TCP\n"
        "    --fp-from-hex <hex> -F : send fake hex (incomplete)\n"
        "           --block-quic -q : drop quic traffic\n"
        "\n"
        "                 --help -h : print this help and exit\n"
        "",
        Platform::name);
}

void logParams(Params* params)
{
    prInfo(
        "DNS Redirect                  : %d\n"
        "DNS Redirect ipv4             : %s\n"
        "DNS Redirect ipv6             : %s\n"
        "Fake packet                   : %d\n"
        "Fake packet fake TCP checksum : %d\n"
        "Fake packet fake TCP seq      : %d\n"
        "Fake packet fake TCP ack      : %d\n"
        "Fake packet from hex          : %d\n"
        "Block QUIC                    : %d\n"
        "Show Help                     : %d\n"
        "\n",
        params->do_dns_redirect,
        u32ToIPv4(params->dr_ipv4).c_str(),
        IPv6ToStr(params->dr_ipv6).c_str(),
        params->do_fake_packet,
        params->do_fp_tcp_fake_checksum,
        params->do_fp_tcp_fake_seq,
        params->do_fp_tcp_fake_ack,
        params->fake_from_hex != nullptr,
        params->do_block_quic,
        params->do_help);
}

int Launcher::run()
{
    logProgramInfo();

    auto params = parseArgs();
    if (!params)
        return 1;

    logParams(params.get());

    if (params->do_help || argc_ == 1)
    {
        printHelp();
        return 0;
    }

    auto trafficModifier = createTrafficModifier(params.get());
    if (!trafficModifier)
        return 1;

    if (!runFilterLoop(trafficModifier))
    {
        return 1;
    }

    return 0;
}
} // namespace Init
