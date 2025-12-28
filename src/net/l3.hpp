// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdint.h>

namespace Net
{
enum class NetworkProtocol : uint8_t
{
    IPv4 = 4,
    IPv6 = 6
};

struct IPv4
{
    uint8_t addr[4];
};

struct IPv6
{
    uint16_t addr[8];
};

#pragma pack(push, 1)
struct IPv4Hdr
{
    uint8_t ver_ihl;
    uint8_t service_type;
    uint16_t len;
    uint16_t frag_id;
    uint16_t frag_shift;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    IPv4 src_ip;
    IPv4 dst_ip;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct IPv6Hdr
{
    uint8_t ip_ver : 4;
    uint8_t diff_srv;
    uint16_t stream_mark;
    uint16_t payload_len;
    uint8_t next_hdr;
    uint8_t ttl;
    IPv6 src_ip;
    IPv6 dst_ip;
};
#pragma pack(pop)
} // namespace Net
