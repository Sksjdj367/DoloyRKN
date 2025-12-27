// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "net/l3.hpp"

namespace Net
{
enum class TRANSPORT_PROTOCOLS
{
    TCP = 6,
    UDP = 17,
};

#pragma pack(push, 1)
struct TCPHdr
{
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint16_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_ptr;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct UDPHdr
{
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t checksum;
};
#pragma pack(pop)

class TransportHdr
{
  public:
    TransportHdr(uint8_t* buf, size_t buf_len, network_hdr* net_hdr);
    ~TransportHdr();

    TCPHdr* getTCPHdr() const;
    UDPHdr* getUDPHdr() const;

  private:
    void* buf;
    size_t buf_len;
    enum TRANSPORT_PROTOCOLS type;
};
} // namespace Net
