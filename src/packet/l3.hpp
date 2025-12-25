// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdint.h>
#include <stddef.h>

namespace Net
{
enum class NETWORK_PROTOCOLS
{
    IPV4 = 4,
    IPV6 = 6
};

struct ipv4
{
    uint8_t addr[4];
};

struct ipv6
{
    uint16_t addr[8];
};

#pragma pack(push, 1)
struct ipv4_hdr
{
    uint8_t ver_ihl;
    uint8_t service_type;
    uint16_t len;
    uint16_t frag_id;
    uint16_t frag_shift;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    struct ipv4 src_ip;
    struct ipv4 dst_ip;
};
#pragma pack(pop)

#pragma pack(push, 0)
struct ipv6_hdr
{
    uint8_t ip_ver : 4;
    uint8_t diff_srv;
    uint16_t stream_mark;
    uint16_t payload_len;
    uint8_t next_hdr;
    uint8_t ttl;
    struct ipv6 src_ip;
    struct ipv6 dst_ip;
};
#pragma pack(pop)

class network_hdr
{
  public:
    network_hdr(uint8_t* buf, size_t buf_len);
    ~network_hdr();

    ipv4_hdr* get_ipv4_hdr() const;
    ipv6_hdr* get_ipv6_hdr() const;

  private:
    void* buf;
    size_t buf_len;
    enum NETWORK_PROTOCOLS type;
};
} // namespace Net
