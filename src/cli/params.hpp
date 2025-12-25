// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdint.h>

namespace cli
{
struct Params
{
    bool do_fake_packet;
    bool do_fp_tcp_fake_checksum;
    bool do_fp_tcp_fake_seq;
    bool do_fp_tcp_fake_ack;
    char* fake_from_hex;

    bool do_block_quic;

    bool do_help;

    Params()
        : do_fake_packet{}, do_fp_tcp_fake_checksum{}, do_fp_tcp_fake_seq{}, do_fp_tcp_fake_ack{},
          fake_from_hex{}, do_block_quic{}, do_help{}
    {
    }
    ~Params() {}
};
} // namespace cli