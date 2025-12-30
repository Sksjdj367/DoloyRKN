// SPDX-License-Identifier: GPL-3.0-or-later

#include <memory>
#include <getopt.h>

#include "util/log.hpp"

#include "cli/params.hpp"
#include "cli/parsing.hpp"

namespace cli
{
struct ParsingContext
{
    int argc;
    char** argv;
    const char* short_opts;
    const struct option* long_opts;
};

const char* shortOpts = const_cast<char*>("i:I:csaqF:h");

enum class Options
{
    DR_IPv4 = 'i',
    DR_IPv6 = 'I',

    FP_FAKE_TCP_CHECKSUM = 'c',
    FP_FAKE_TCP_SEQ = 's',
    FP_FAKE_TCP_ACK = 'a',
    FP_FAKE_FROM_HEX = 'F',

    BLOCK_QUIC = 'q',

    HELP = 'H'
};

const struct option longOpts[]{
    {"dr-ipv4", required_argument, nullptr, static_cast<int>(Options::DR_IPv4)},
    {"dr-ipv6", required_argument, nullptr, static_cast<int>(Options::DR_IPv6)},

    {"fp-fake-tcp-checksum", no_argument, nullptr, static_cast<int>(Options::FP_FAKE_TCP_CHECKSUM)},
    {"fp-fake-tcp-seq", no_argument, nullptr, static_cast<int>(Options::FP_FAKE_TCP_SEQ)},
    {"fp-fake-tcp-ack", no_argument, nullptr, static_cast<int>(Options::FP_FAKE_TCP_ACK)},
    {"fp-from-hex", no_argument, nullptr, static_cast<int>(Options::FP_FAKE_FROM_HEX)},

    {"block-quic", no_argument, nullptr, static_cast<int>(Options::BLOCK_QUIC)},

    {"help", no_argument, nullptr, static_cast<int>(Options::HELP)},

    {nullptr, no_argument, nullptr, 0}};

[[nodiscard]]
int getOpt(struct ParsingContext* ctx)
{
    return getopt_long(ctx->argc, ctx->argv, ctx->short_opts, ctx->long_opts, nullptr);
}

[[nodiscard]]
bool parseOpt(int opt, std::unique_ptr<Params>& params)
{
    switch (static_cast<Options>(opt))
    {
    case Options::HELP:
        params->do_help = true;
        break;

    case Options::DR_IPv4:
        params->do_dns_redirect = true;
        params->dr_ipv4 = 134764621;
        break;

    case Options::DR_IPv6:
        params->do_dns_redirect = true;
        params->dr_ipv6 = 0;
        break;

    case Options::FP_FAKE_TCP_CHECKSUM:
        params->do_fake_packet = true;
        params->do_fp_tcp_fake_checksum = true;
        break;

    case Options::FP_FAKE_TCP_SEQ:
        params->do_fake_packet = true;
        params->do_fp_tcp_fake_seq = true;
        break;

    case Options::FP_FAKE_TCP_ACK:
        params->do_fake_packet = true;
        params->do_fp_tcp_fake_ack = true;
        break;

    case Options::FP_FAKE_FROM_HEX:
        params->do_fake_packet = true;
        params->fake_from_hex = optarg;
        break;

    case Options::BLOCK_QUIC:
        params->do_block_quic = true;
        break;

    default:
        return 0;
    }

    return 1;
}

[[nodiscard]]
const std::unique_ptr<Params> parseArgs(int argc, char** argv)
{
    auto params = std::make_unique<Params>();
    if (!params)
        return nullptr;

    int opt;

    ParsingContext parsingContext = {argc, argv, shortOpts, longOpts};

    while ((opt = getOpt(&parsingContext)) != -1)
    {
        if (!parseOpt(opt, params))
        {
            logs::err("error during option parsing\n");
            return nullptr;
        }
    }

    return params;
}
} // namespace cli